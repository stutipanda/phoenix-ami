
import pytest

from src.crypto_engine import (
    AuthenticationError,
    EncryptedTelemetry,
    GatewayAuthority,
    MeshCryptoNode,
)


@pytest.fixture
def network():
    gateway = GatewayAuthority(prime_bits=32)

    gateway.register_node("meter-A")
    gateway.register_node("meter-B")
    gateway.register_node("meter-C")

    meter_a = gateway.create_node("meter-A")
    meter_b = gateway.create_node("meter-B")
    meter_c = gateway.create_node("meter-C")

    return gateway, meter_a, meter_b, meter_c


def test_direct_pairwise_key_agreement(network):
    _, meter_a, meter_b, _ = network

    secret_a = meter_a.derive_pairwise_secret(meter_b.Y)
    secret_b = meter_b.derive_pairwise_secret(meter_a.Y)

    assert secret_a == secret_b


def test_key_bridging_after_intermediate_failure(network):
    gateway, meter_a, meter_b, meter_c = network

    # Prepare the token before the intermediate meter fails.
    token = gateway.issue_bridging_token("meter-B", "meter-C")

    # A and B already share a value.
    shared_a_b = meter_a.derive_pairwise_secret(meter_b.Y)

    # Simulate B going offline.
    del meter_b

    # A recovers the A-C shared value locally.
    stitched = meter_a.stitch_shared_secret(shared_a_b, token)

    # Compare against the direct A-C value as a test oracle.
    direct = meter_a.derive_pairwise_secret(meter_c.Y)

    assert stitched == direct


def test_aes_gcm_telemetry_round_trip(network):
    _, meter_a, meter_b, _ = network

    secret_a = meter_a.derive_pairwise_secret(meter_b.Y)
    secret_b = meter_b.derive_pairwise_secret(meter_a.Y)

    telemetry = (
        b'{"meter_id":"meter-A","voltage":231.4,'
        b'"current":5.82,"active_power":1240.7}'
    )
    aad = b"meter-A|meter-B|telemetry-v1"

    packet = MeshCryptoNode.encrypt_telemetry(
        secret_a, telemetry, associated_data=aad
    )

    decrypted = MeshCryptoNode.decrypt_telemetry(
        secret_b, packet, associated_data=aad
    )

    assert decrypted == telemetry
    assert len(packet.nonce) == 12


def test_aes_gcm_rejects_tampered_ciphertext(network):
    _, meter_a, meter_b, _ = network

    secret = meter_a.derive_pairwise_secret(meter_b.Y)

    packet = MeshCryptoNode.encrypt_telemetry(
        secret,
        b'{"active_power":1240.7}',
        associated_data=b"meter-A|meter-B",
    )

    corrupted_ciphertext = (
        packet.ciphertext[:-1]
        + bytes([packet.ciphertext[-1] ^ 1])
    )

    corrupted_packet = EncryptedTelemetry(
        nonce=packet.nonce,
        ciphertext=corrupted_ciphertext,
    )

    with pytest.raises(AuthenticationError):
        MeshCryptoNode.decrypt_telemetry(
            secret,
            corrupted_packet,
            associated_data=b"meter-A|meter-B",
        )
