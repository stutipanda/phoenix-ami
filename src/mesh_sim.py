"""Network topology and relay-failure simulation for Phoenix-AMI."""

from __future__ import annotations

import time
from dataclasses import dataclass

import networkx as nx


@dataclass
class RecoveryResult:
    source: str
    destination: str
    failed_node: str
    recovered: bool
    route: list[str]
    elapsed_ms: float
    messages_sent: int


class MeshNetwork:
    """A simple wireless mesh simulation using NetworkX."""

    def __init__(self) -> None:
        self.graph = nx.Graph()

    def add_meter(self, node_id: str, **attributes: object) -> None:
        self.graph.add_node(node_id, role="meter", **attributes)

    def add_gateway(self, node_id: str = "gateway") -> None:
        self.graph.add_node(node_id, role="gateway")

    def add_link(
        self,
        node_a: str,
        node_b: str,
        *,
        latency_ms: float = 10.0,
    ) -> None:
        if latency_ms <= 0:
            raise ValueError("latency_ms must be positive")
        self.graph.add_edge(node_a, node_b, latency_ms=latency_ms)

    def shortest_route(self, source: str, destination: str) -> list[str]:
        """Return the minimum-hop route between two active nodes."""
        return nx.shortest_path(
            self.graph, source, destination, weight=None
        )

    def simulate_relay_failure(
        self,
        source: str,
        destination: str,
        failed_node: str,
    ) -> RecoveryResult:
        """Remove a relay temporarily and find an alternate route."""
        if failed_node not in self.graph:
            raise ValueError(f"Unknown failed node: {failed_node}")
        if failed_node in (source, destination):
            raise ValueError("Source and destination cannot be the failed relay")

        started = time.perf_counter()
        self.graph.nodes[failed_node]["active"] = False
        self.graph.remove_node(failed_node)

        try:
            route = self.shortest_route(source, destination)
            recovered = True
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            route = []
            recovered = False

        elapsed_ms = (time.perf_counter() - started) * 1000

        # This is a simulation-level route-discovery count, not measured
        # radio traffic or cryptographic protocol messages.
        messages_sent = max(0, len(route) - 1) if recovered else 0

        return RecoveryResult(
            source=source,
            destination=destination,
            failed_node=failed_node,
            recovered=recovered,
            route=route,
            elapsed_ms=elapsed_ms,
            messages_sent=messages_sent,
        )

    def restore_relay(self, node_id: str, neighbors: dict[str, float]) -> None:
        """Restore a removed relay and its links."""
        self.graph.add_node(node_id, role="meter", active=True)
        for neighbor, latency_ms in neighbors.items():
            if neighbor in self.graph:
                self.add_link(node_id, neighbor, latency_ms=latency_ms)


def build_demo_mesh() -> MeshNetwork:
    """Build a small mesh with two routes from meter-A to meter-D."""
    mesh = MeshNetwork()
    for node in ("meter-A", "meter-B", "meter-C", "meter-D"):
        mesh.add_meter(node)

    mesh.add_link("meter-A", "meter-B")
    mesh.add_link("meter-B", "meter-D")
    mesh.add_link("meter-A", "meter-C")
    mesh.add_link("meter-C", "meter-D")
    mesh.add_link("meter-B", "meter-C")

    return mesh


if __name__ == "__main__":
    network = build_demo_mesh()
    result = network.simulate_relay_failure(
        "meter-A", "meter-D", "meter-B"
    )
    print(f"Recovered: {result.recovered}")
    print(f"Route: {result.route}")
    print(f"Elapsed: {result.elapsed_ms:.3f} ms")
    print(f"Simulated messages: {result.messages_sent}")

def build_large_mesh(rows: int = 4, cols: int = 5) -> MeshNetwork:
    """Build a 20-node grid-based mesh network for the professor's demonstration."""
    mesh = MeshNetwork()
    
    for r in range(rows):
        for c in range(cols):
            mesh.add_meter(f"meter-{r}-{c}")
            
    for r in range(rows):
        for c in range(cols):
            current = f"meter-{r}-{c}"
            if c + 1 < cols:
                mesh.add_link(current, f"meter-{r}-{c+1}")
            if r + 1 < rows:
                mesh.add_link(current, f"meter-{r+1}-{c}")
                
    return mesh

import random

def build_geometric_mesh(num_nodes: int, radius: float = 0.35) -> MeshNetwork:
    """Build a random geometric graph to model rural AMI deployments."""
    mesh = MeshNetwork()
    
    # Generate spatial graph and ensure it is fully connected
    G = nx.random_geometric_graph(num_nodes, radius)
    while not nx.is_connected(G):
        G = nx.random_geometric_graph(num_nodes, radius)
        
    for node in G.nodes():
        mesh.add_meter(f"meter-{node}")
        
    for u, v in G.edges():
        mesh.add_link(f"meter-{u}", f"meter-{v}", latency_ms=random.uniform(5.0, 15.0))
        
    return mesh