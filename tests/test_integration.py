import pytest
from src.mesh_sim import build_demo_mesh
from src.crypto_engine import GatewayAuthority, EncryptedTelemetry, AuthenticationError
from src.packet import TelemetryPacket

def test_secure_telemetry_delivery():
    # 1. Setup the Network and the Crypto Gateway
    mesh = build_demo_mesh()
    gateway = GatewayAuthority()

    # 2. Register the meters with the gateway FIRST, then create them
    gateway.register_node("meter-A")
    gateway.register_node("meter-D")
    
    node_a = gateway.create_node("meter-A")
    node_d = gateway.create_node("meter-D")

    # 3. Create a shared secret password between A and D
    secret_A = node_a.derive_pairwise_secret(node_d.Y)
    secret_D = node_d.derive_pairwise_secret(node_a.Y)
    assert secret_A == secret_D  # Prove they mathematically match

    # 4. Meter A prepares and encrypts the data
    raw_data = b'{"voltage": 240.1, "status": "ok"}'
    aad_stamp = b"meter-A_to_meter-D"
    
    encrypted_box = node_a.encrypt_telemetry(
        shared_secret=secret_A, 
        plaintext=raw_data, 
        associated_data=aad_stamp
    )

    # 5. Pack the encrypted box into the Network Packet and route it
    route = mesh.shortest_route("meter-A", "meter-D")
    
    packet = TelemetryPacket(
        source="meter-A",
        destination="meter-D",
        payload=b"",  # Left empty because the real data is encrypted!
        associated_data=aad_stamp,
        nonce=encrypted_box.nonce,
        ciphertext=encrypted_box.ciphertext,
        route=route
    )

    # 6. Meter D receives the packet, unpacks it, and decrypts it
    assert packet.route[-1] == "meter-D" # Confirm it arrived
    
    received_box = EncryptedTelemetry(nonce=packet.nonce, ciphertext=packet.ciphertext)
    
    decrypted_data = node_d.decrypt_telemetry(
        shared_secret=secret_D,
        packet=received_box,
        associated_data=packet.associated_data
    )

    # 7. Verify the data survived the journey perfectly
    assert decrypted_data == raw_data

def test_delivery_after_relay_failure():
    # 1. Setup Network and Crypto
    mesh = build_demo_mesh()
    gateway = GatewayAuthority()
    
    gateway.register_node("meter-A")
    gateway.register_node("meter-D")
    node_a = gateway.create_node("meter-A")
    node_d = gateway.create_node("meter-D")
    
    secret_A = node_a.derive_pairwise_secret(node_d.Y)
    secret_D = node_d.derive_pairwise_secret(node_a.Y)
    
    # 2. INJECT FAILURE: Power outage at meter-B!
    recovery = mesh.simulate_relay_failure("meter-A", "meter-D", failed_node="meter-B")
    
    # Ensure the network found an alternate route
    assert recovery.recovered is True
    assert "meter-B" not in recovery.route
    
    # 3. Encrypt and route using the new recovery path
    encrypted_box = node_a.encrypt_telemetry(secret_A, b"critical grid data")
    
    packet = TelemetryPacket(
        source="meter-A",
        destination="meter-D",
        payload=b"",
        nonce=encrypted_box.nonce,
        ciphertext=encrypted_box.ciphertext,
        route=recovery.route  # The packet takes the new detour!
    )
    
    # 4. Decrypt at destination
    received_box = EncryptedTelemetry(nonce=packet.nonce, ciphertext=packet.ciphertext)
    decrypted_data = node_d.decrypt_telemetry(secret_D, received_box)
    
    # The data survives the detour!
    assert decrypted_data == b"critical grid data"


def test_tampered_packet_rejected():
    # 1. Setup Crypto
    gateway = GatewayAuthority()
    gateway.register_node("meter-A")
    gateway.register_node("meter-D")
    node_a = gateway.create_node("meter-A")
    node_d = gateway.create_node("meter-D")
    
    secret_A = node_a.derive_pairwise_secret(node_d.Y)
    secret_D = node_d.derive_pairwise_secret(node_a.Y)
    
    # 2. Encrypt valid data
    encrypted_box = node_a.encrypt_telemetry(secret_A, b"valid data")
    
    # 3. THE HACK: Tamper with the ciphertext in transit (flipping a byte)
    tampered_ciphertext = bytearray(encrypted_box.ciphertext)
    tampered_ciphertext[-1] ^= 0xFF  # Flip bits of the last byte
    
    tampered_box = EncryptedTelemetry(nonce=encrypted_box.nonce, ciphertext=bytes(tampered_ciphertext))
    
    # 4. Prove that decryption fails and raises an AuthenticationError
    with pytest.raises(AuthenticationError):
        node_d.decrypt_telemetry(secret_D, tampered_box)

def test_key_stitching_mechanism():
    """Prove that local key stitching successfully transforms the shared secret."""
    gateway = GatewayAuthority()
    
    # Register 3 nodes
    gateway.register_node("meter-A")
    gateway.register_node("meter-B")
    gateway.register_node("meter-C")
    
    node_a = gateway.create_node("meter-A")
    node_b = gateway.create_node("meter-B")
    node_c = gateway.create_node("meter-C")
    
    # 1. Meter A has an existing shared secret with Meter B
    secret_AB = node_a.derive_pairwise_secret(node_b.Y)
    
    # 2. Relay B fails. Gateway issues a bridging token to route to C instead.
    # The token mathematically bridges "B" to "C".
    token_B_to_C = gateway.issue_bridging_token(intermediate_id="meter-B", target_id="meter-C")
    
    # 3. Meter A locally stitches the token onto its old secret
    stitched_secret_AC = node_a.stitch_shared_secret(
        intermediate_shared_secret=secret_AB, 
        bridging_token=token_B_to_C
    )
    
    # 4. Meter C derives its normal secret with A
    normal_secret_CA = node_c.derive_pairwise_secret(node_a.Y)
    
    # PROOF: The stitched secret perfectly matches the normal secret!
    assert stitched_secret_AC == normal_secret_CA
    
    # 5. Prove it can decrypt a packet
    encrypted_box = node_a.encrypt_telemetry(stitched_secret_AC, b"stitched data")
    decrypted_data = node_c.decrypt_telemetry(normal_secret_CA, encrypted_box)
    
    assert decrypted_data == b"stitched data"