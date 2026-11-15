import pytest
from cryptography.exceptions import InvalidTag
from src.mesh_sim import build_demo_mesh
from src.crypto_engine import GatewayAuthority, EncryptedTelemetry, AuthenticationError
from src.packet import Packet, TelemetryPacket, deserialize, serialize
from src.simulation import (
    SimulationLogger,
    build_simulation_graph,
    run_paired_scenario,
    run_simulation,
)
import numpy as np

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
    with pytest.raises(InvalidTag):
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


def test_packet_round_trips_with_authenticated_telemetry():
    gateway = GatewayAuthority(prime_bits=32)
    gateway.register_node("sender")
    gateway.register_node("recipient")
    sender = gateway.create_node("sender")
    recipient = gateway.create_node("recipient")
    sender_secret = sender.derive_pairwise_secret(recipient.Y)
    recipient_secret = recipient.derive_pairwise_secret(sender.Y)
    encrypted = sender.encrypt_telemetry(sender_secret, b"sample", nonce=b"n" * 12)
    packet = Packet("DATA", "sender", "recipient", encrypted.nonce, encrypted.ciphertext)
    decoded = deserialize(serialize(packet))
    assert recipient.decrypt_telemetry(
        recipient_secret, EncryptedTelemetry(decoded.nonce, decoded.ciphertext)
    ) == b"sample"
    assert decoded == packet


def test_bridge_keys_match_for_both_participants():
    from src.simulation import derive_bridging_key

    gateway = GatewayAuthority(prime_bits=32)
    for node_id in ("a", "relay", "gateway"):
        gateway.register_node(node_id)
    a = gateway.create_node("a")
    relay = gateway.create_node("relay")
    gateway_node = gateway.create_node("gateway")
    a_key = derive_bridging_key(
        a, "relay", gateway.issue_bridging_token("relay", "gateway"), relay.Y
    )
    gateway_key = derive_bridging_key(
        gateway_node, "relay", gateway.issue_bridging_token("relay", "a"), relay.Y
    )
    assert a_key == gateway_key


def test_packet_rejects_tampered_gcm_ciphertext_as_invalid_tag():
    authority = GatewayAuthority(prime_bits=32)
    authority.register_node("meter-A")
    authority.register_node("meter-B")
    meter_a = authority.create_node("meter-A")
    meter_b = authority.create_node("meter-B")
    secret_a = meter_a.derive_pairwise_secret(meter_b.Y)
    secret_b = meter_b.derive_pairwise_secret(meter_a.Y)
    encrypted = meter_a.encrypt_telemetry(secret_a, b"payload", nonce=b"t" * 12)
    packet = Packet("DATA", "meter-A", "meter-B", encrypted.nonce,
                    encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]))
    decoded = deserialize(serialize(packet))
    with pytest.raises(InvalidTag):
        meter_b.decrypt_telemetry(
            secret_b, EncryptedTelemetry(decoded.nonce, decoded.ciphertext)
        )


def test_nonce_generator_is_unique_for_thousands_of_packets():
    logger = SimulationLogger(np.random.default_rng(42))
    nonces = [logger.next_nonce() for _ in range(5000)]
    assert len(set(nonces)) == 5000


@pytest.mark.parametrize("failed", [["meter-2"], ["meter-2", "meter-7"],
                                     ["meter-2", "meter-7", "meter-12"]])
def test_connected_topologies_deliver_all_leaf_packets(failed):
    graph = build_simulation_graph(20, 42)
    graph.remove_nodes_from(failed)
    assert __import__("networkx").is_connected(graph)
    result = run_simulation(20, 15, 42, "euler", failed_nodes=failed)
    assert result["packets_lost"] == 0
    assert result["packets_delivered"] == 20 - len(failed)


def test_euler_recovers_with_control_gateway_unavailable():
    euler = run_simulation(
        20, 5, 23, "euler", failed_nodes=["meter-0"],
        gateway_control_available=False,
    )
    centralized = run_simulation(
        20, 5, 23, "centralized", failed_nodes=["meter-0"],
        gateway_control_available=False,
    )
    assert euler["nodes_unrecovered"] == 0
    assert centralized["nodes_unrecovered"] > 0


def test_seed_repeats_scenario_counts_but_timing_is_measured():
    first = run_paired_scenario(10, 10, 8)
    second = run_paired_scenario(10, 10, 8)
    for mode in first:
        for field in ("control_bytes", "control_packets", "packets_sent",
                      "packets_delivered", "packets_lost", "nodes_unrecovered"):
            assert first[mode][field] == second[mode][field]
    different = run_paired_scenario(10, 10, 9)
    assert any(first[mode]["control_bytes"] != different[mode]["control_bytes"]
               for mode in first)


def test_partition_and_adjacent_failures_are_reported_as_limitations():
    import math

    # Removing both gateway attachment relays partitions surviving meters;
    # the simulation reports the physical partition instead of claiming recovery.
    partition = run_simulation(
        4, 50, 5, "euler", failed_nodes=["meter-0", "meter-2"]
    )
    assert partition["packets_lost"] >= 1
    assert partition["nodes_unrecovered"] >= 1
    assert math.isnan(partition["recovery_ms"])

    # Adjacent failures may still leave a route; the explicit failure event
    # and delivered/lost packet counts describe the actual graph outcome.
    adjacent = run_simulation(
        10, 20, 5, "euler", failed_nodes=["meter-0", "meter-1"]
    )
    assert adjacent["events"][0]["event"] == "failure"
    assert adjacent["packets_delivered"] + adjacent["packets_lost"] == 8