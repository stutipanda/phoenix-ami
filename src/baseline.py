"""Centralized re-keying baseline assumptions.

REKEY packets are unicast (not flooded), every hop's transmission is counted,
and nodes without a surviving route from the Gateway cannot be rekeyed.
Affected nodes are surviving direct neighbors of one or more failed relays.
The simulation's result includes those unrecovered nodes and an event log.
"""

from __future__ import annotations

import time
from typing import Any

import networkx as nx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto_engine import MeshCryptoNode
from src.mesh_sim import MeshNetwork
from src.packet import Packet, size_bytes


def perform_centralized_rekeys(
    graph: Any,
    affected_nodes: set[str],
    gateway_id: str,
    crypto_nodes: dict[str, MeshCryptoNode],
    rng: Any,
    logger: Any,
    *,
    gateway_control_available: bool = True,
    detected_at_ms: float = 0.0,
) -> tuple[dict[str, int], set[str], float]:
    """Send one encrypted unicast REKEY to each reachable affected node."""
    session_keys: dict[str, int] = {}
    unrecovered: set[str] = set()
    compute_ms = 0.0

    if not gateway_control_available:
        logger.record_event(
            "gateway_control_unavailable",
            detail="Centralized re-keying cannot reach the authority",
        )
        return session_keys, set(affected_nodes), compute_ms

    gateway = crypto_nodes[gateway_id]
    mesh = MeshNetwork()
    mesh.graph = graph
    for node_id in sorted(affected_nodes):
        try:
            route = mesh.shortest_route(gateway_id, node_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            unrecovered.add(node_id)
            logger.record_event("rekey_unreachable", node_id=node_id)
            continue

        started = time.perf_counter()
        shared_secret = gateway.derive_pairwise_secret(crypto_nodes[node_id].Y)
        session_key = int.from_bytes(rng.bytes(16), "big") or 1
        nonce = logger.next_nonce()
        key = MeshCryptoNode._derive_aes_key(shared_secret, nonce)
        ciphertext = AESGCM(key).encrypt(
            nonce, session_key.to_bytes(16, "big"), None
        )
        received_key = AESGCM(key).decrypt(nonce, ciphertext, None)
        compute_ms += (time.perf_counter() - started) * 1000

        packet = Packet("REKEY", gateway_id, node_id, nonce, ciphertext)
        hops = max(0, len(route) - 1)
        logger.count_control(packet, hops)
        logger.record_event(
            "reroute", time_ms=detected_at_ms, node_id=node_id, route=route
        )
        logger.record_event(
            "rekey_sent", node_id=node_id, route=route, hops=hops
        )
        session_keys[node_id] = int.from_bytes(received_key, "big")

    return session_keys, unrecovered, compute_ms


def run_baseline(
    num_nodes: int = 20,
    dropout_pct: float = 5,
    seed: int = 1,
    *,
    failed_nodes: list[str] | None = None,
    gateway_control_available: bool = True,
) -> dict[str, Any]:
    """Run centralized mode and return the shared simulation metrics dict."""
    from src.simulation import run_simulation

    return run_simulation(
        num_nodes,
        dropout_pct,
        seed,
        "centralized",
        failed_nodes=failed_nodes,
        gateway_control_available=gateway_control_available,
    )