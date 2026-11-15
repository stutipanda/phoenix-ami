"""Seeded, paired simulation of Euler-style healing and centralized re-keying.

Simulation timing combines measured local crypto time with a modeled
10 ms-per-hop network delay. Heartbeats use a modeled three-miss timeout.
Seeded nonces are for repeatable experiments only; the crypto engine's
default API continues to use operating-system randomness.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

import networkx as nx
import numpy as np

from src.baseline import perform_centralized_rekeys
from src.crypto_engine import GatewayAuthority, MeshCryptoNode
from src.mesh_sim import MeshNetwork
from src.packet import Packet, deserialize, serialize, size_bytes


Mode = Literal["euler", "centralized"]
GATEWAY_ID = "gateway"
PER_HOP_LATENCY_MS = 10.0
HEARTBEAT_INTERVAL_MS = 1000.0
MISSED_HEARTBEATS_FOR_DETECTION = 3
DATA_PAYLOAD_BYTES = 48


@dataclass
class SimulationLogger:
    rng: np.random.Generator
    control_bytes_by_type: dict[str, int] = field(default_factory=lambda: {
        "HEARTBEAT": 0,
        "BRIDGE_TOKEN": 0,
        "REKEY": 0,
    })
    control_packets_by_type: dict[str, int] = field(default_factory=lambda: {
        "HEARTBEAT": 0,
        "BRIDGE_TOKEN": 0,
        "REKEY": 0,
    })
    events: list[dict[str, Any]] = field(default_factory=list)
    packets_sent: int = 0
    packets_delivered: int = 0
    packets_lost: int = 0
    _nonces: set[bytes] = field(default_factory=set)

    def next_nonce(self) -> bytes:
        while True:
            nonce = self.rng.bytes(12)
            if nonce not in self._nonces:
                self._nonces.add(nonce)
                return nonce

    def count_control(self, packet: Packet, hops: int) -> None:
        if packet.type not in self.control_bytes_by_type:
            raise ValueError(f"Not a control packet: {packet.type}")
        frame_bytes = size_bytes(packet)
        self.control_bytes_by_type[packet.type] += frame_bytes * hops
        self.control_packets_by_type[packet.type] += hops

    def record_event(self, event: str, *, time_ms: float = 0.0, **details: Any) -> None:
        self.events.append({"time_ms": round(time_ms, 6), "event": event, **details})

    def metrics(self, recovery_ms: float, nodes_unrecovered: int) -> dict[str, Any]:
        return {
            "control_bytes": sum(self.control_bytes_by_type.values()),
            "control_packets": sum(self.control_packets_by_type.values()),
            "control_bytes_by_type": dict(self.control_bytes_by_type),
            "control_packets_by_type": dict(self.control_packets_by_type),
            "recovery_ms": round(recovery_ms, 6),
            "packets_sent": self.packets_sent,
            "packets_delivered": self.packets_delivered,
            "packets_lost": self.packets_lost,
            "nodes_unrecovered": nodes_unrecovered,
            "events": list(self.events),
        }


def build_simulation_graph(
    num_nodes: int,
    seed: int,
) -> nx.Graph:
    """Build a connected ring with seeded redundant links and a dual-attached gateway."""
    if num_nodes < 4:
        raise ValueError("num_nodes must be at least 4")
    rng = np.random.default_rng(seed)
    graph = nx.Graph()
    meters = [f"meter-{index}" for index in range(num_nodes)]
    graph.add_node(GATEWAY_ID, role="gateway")
    graph.add_nodes_from((node_id, {"role": "meter"}) for node_id in meters)

    for index, node_id in enumerate(meters):
        graph.add_edge(node_id, meters[(index + 1) % num_nodes])
    for index in range(num_nodes):
        for offset in range(2, min(5, num_nodes // 2 + 1)):
            if rng.random() < 0.13:
                graph.add_edge(meters[index], meters[(index + offset) % num_nodes])
    graph.add_edge(GATEWAY_ID, meters[0])
    graph.add_edge(GATEWAY_ID, meters[num_nodes // 2])
    nx.set_edge_attributes(graph, PER_HOP_LATENCY_MS, "latency_ms")
    return graph


def derive_bridging_key(
    local_node: MeshCryptoNode,
    neighbor_id: str,
    token: int,
    neighbor_public: int,
) -> int:
    """Locally stitch a pre-failure neighbor secret using its bridge token."""
    if not neighbor_id:
        raise ValueError("neighbor_id is required")
    old_secret = local_node.derive_pairwise_secret(neighbor_public)
    return local_node.stitch_shared_secret(old_secret, token)


def _route(graph: nx.Graph, source: str, destination: str) -> list[str] | None:
    mesh = MeshNetwork()
    mesh.graph = graph
    try:
        return mesh.shortest_route(source, destination)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def _route_latency(route: list[str]) -> float:
    return max(0, len(route) - 1) * PER_HOP_LATENCY_MS


def run_simulation(
    num_nodes: int = 20,
    dropout_pct: float = 5,
    seed: int = 1,
    mode: Mode = "euler",
    *,
    failed_nodes: list[str] | None = None,
    gateway_control_available: bool = True,
) -> dict[str, Any]:
    """Run one scenario and return common metrics plus timestamped events."""
    if mode not in ("euler", "centralized"):
        raise ValueError("mode must be 'euler' or 'centralized'")
    if not 0 <= dropout_pct <= 100:
        raise ValueError("dropout_pct must be between 0 and 100")

    rng = np.random.default_rng(seed)
    logger = SimulationLogger(rng)
    graph = build_simulation_graph(num_nodes, seed)
    original_graph = graph.copy()
    meters = [node for node, data in graph.nodes(data=True) if data["role"] == "meter"]
    failure_count = max(1, int(np.ceil(num_nodes * dropout_pct / 100)))
    if failed_nodes is None:
        candidates = np.array(meters, dtype=object)
        failures = list(rng.choice(candidates, size=min(failure_count, num_nodes), replace=False))
    else:
        failures = list(dict.fromkeys(failed_nodes))
        if any(node not in meters for node in failures):
            raise ValueError("failed_nodes must identify existing meter nodes")

    authority = GatewayAuthority(prime_bits=32)
    for node_id in [GATEWAY_ID, *meters]:
        authority.register_node(node_id)
    crypto_nodes = {node_id: authority.create_node(node_id) for node_id in [GATEWAY_ID, *meters]}

    affected_nodes: set[str] = set()
    failed_neighbor: dict[str, str] = {}
    for failed in failures:
        for neighbor in original_graph.neighbors(failed):
            if neighbor != GATEWAY_ID and neighbor not in failures:
                affected_nodes.add(neighbor)
                failed_neighbor.setdefault(neighbor, failed)
    bridge_tokens = {
        node_id: authority.issue_bridging_token(failed, GATEWAY_ID)
        for node_id, failed in failed_neighbor.items()
    }
    logger.record_event("failure", failed_nodes=failures)
    for failed in failures:
        if failed in graph:
            graph.remove_node(failed)
    active_meters = [node_id for node_id in meters if node_id not in failures]

    detected_at_ms = HEARTBEAT_INTERVAL_MS * MISSED_HEARTBEATS_FOR_DETECTION
    for node_id, failed in sorted(failed_neighbor.items()):
        heartbeat = Packet("HEARTBEAT", node_id, failed, logger.next_nonce(), b"")
        logger.count_control(heartbeat, 1)
        logger.record_event(
            "detection", time_ms=detected_at_ms, node_id=node_id,
            failed_node=failed, missed_heartbeats=MISSED_HEARTBEATS_FOR_DETECTION,
        )

    rekeyed: dict[str, int] = {}
    euler_keys: dict[str, int] = {}
    unrecovered: set[str] = set()
    crypto_compute_ms = 0.0

    if mode == "centralized":
        rekeyed, unrecovered, crypto_compute_ms = perform_centralized_rekeys(
            graph,
            affected_nodes,
            GATEWAY_ID,
            crypto_nodes,
            rng,
            logger,
            gateway_control_available=gateway_control_available,
            detected_at_ms=detected_at_ms,
        )
    else:
        for node_id in sorted(affected_nodes):
            route = _route(graph, node_id, GATEWAY_ID)
            if route is None:
                unrecovered.add(node_id)
                logger.record_event("reroute_unreachable", node_id=node_id)
                continue
            logger.record_event("reroute", time_ms=detected_at_ms, node_id=node_id, route=route)
            failed = failed_neighbor[node_id]
            nonce = logger.next_nonce()
            token = bridge_tokens[node_id]
            token_bytes = token.to_bytes(max(1, (token.bit_length() + 7) // 8), "big")
            token_sender = next(
                (route_node for route_node in route[1:] if route_node != GATEWAY_ID),
                GATEWAY_ID,
            )
            bridge_packet = Packet(
                "BRIDGE_TOKEN", token_sender, node_id, nonce, token_bytes
            )
            logger.count_control(bridge_packet, 1)
            started = time.perf_counter()
            derived = derive_bridging_key(
                crypto_nodes[node_id], failed, token, crypto_nodes[failed].Y
            )
            reciprocal_token = authority.issue_bridging_token(failed, node_id)
            gateway_derived = derive_bridging_key(
                crypto_nodes[GATEWAY_ID], failed, reciprocal_token,
                crypto_nodes[failed].Y,
            )
            if derived != gateway_derived:
                raise RuntimeError("Locally derived bridge keys did not match")
            crypto_compute_ms += (time.perf_counter() - started) * 1000
            euler_keys[node_id] = derived
            logger.record_event(
                "key_derived",
                time_ms=detected_at_ms + _route_latency(route) + crypto_compute_ms,
                node_id=node_id,
                neighbor_id=failed,
            )

    deliveries: list[tuple[float, str, bool]] = []
    for node_id in active_meters:
        route = _route(graph, node_id, GATEWAY_ID)
        logger.packets_sent += 1
        if route is None:
            logger.packets_lost += 1
            deliveries.append((float("inf"), node_id, False))
            continue

        if node_id in unrecovered:
            logger.packets_lost += 1
            deliveries.append((float("inf"), node_id, False))
            continue

        if mode == "centralized" and node_id in rekeyed:
            shared_secret = rekeyed[node_id]
        elif mode == "euler" and node_id in euler_keys:
            shared_secret = euler_keys[node_id]
        else:
            shared_secret = crypto_nodes[node_id].derive_pairwise_secret(
                crypto_nodes[GATEWAY_ID].Y
            )

        nonce = logger.next_nonce()
        encrypted = MeshCryptoNode.encrypt_telemetry(
            shared_secret,
            bytes([int(rng.integers(0, 256))]) * DATA_PAYLOAD_BYTES,
            nonce=nonce,
        )
        packet = Packet("DATA", node_id, GATEWAY_ID, encrypted.nonce, encrypted.ciphertext)
        received = deserialize(serialize(packet))
        try:
            MeshCryptoNode.decrypt_telemetry(
                shared_secret,
                type(encrypted)(received.nonce, received.ciphertext),
            )
            logger.packets_delivered += 1
            ready_ms = detected_at_ms
            if mode == "euler" and node_id in euler_keys:
                ready_ms += _route_latency(route) + crypto_compute_ms
            elif mode == "centralized" and node_id in rekeyed:
                ready_ms += _route_latency(route) + crypto_compute_ms
            deliveries.append((ready_ms + _route_latency(route), node_id, True))
        except Exception:
            logger.packets_lost += 1
            deliveries.append((float("inf"), node_id, False))

    successful = [item for item in deliveries if item[2]]
    recovery_candidates = [item for item in successful if item[1] in affected_nodes]
    if successful:
        if recovery_candidates:
            first_any_ms, first_any_node, _ = min(recovery_candidates)
            logger.record_event(
                "first_packet_delivered", time_ms=first_any_ms, node_id=first_any_node
            )
        for delivery_ms, node_id, delivered in successful:
            logger.record_event(
                "packet_delivered", time_ms=delivery_ms, node_id=node_id
            )
        recovery_ms = min(recovery_candidates)[0] if recovery_candidates else float("nan")
    else:
        recovery_ms = float("nan")

    physically_unreachable = {
        node_id for node_id in active_meters if _route(graph, node_id, GATEWAY_ID) is None
    }
    unrecovered |= physically_unreachable
    return logger.metrics(recovery_ms, len(unrecovered))


def run_paired_scenario(
    num_nodes: int,
    dropout_pct: float,
    seed: int,
    *,
    failed_nodes: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run both modes with the exact same generated scenario inputs."""
    shared_failures = failed_nodes
    if shared_failures is None:
        selection_rng = np.random.default_rng(seed)
        graph = build_simulation_graph(num_nodes, seed)
        meters = [node for node, data in graph.nodes(data=True) if data["role"] == "meter"]
        count = max(1, int(np.ceil(num_nodes * dropout_pct / 100)))
        shared_failures = list(selection_rng.choice(
            np.array(meters, dtype=object), size=min(count, num_nodes), replace=False
        ))
    return {
        mode: run_simulation(
            num_nodes, dropout_pct, seed, mode, failed_nodes=shared_failures
        )
        for mode in ("euler", "centralized")
    }