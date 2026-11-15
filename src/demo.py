"""Run a readable fixed-seed 20-meter healing demonstration."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx

from src.simulation import GATEWAY_ID, build_simulation_graph, run_simulation


SEED = 31415
FAILED_NODES = ["meter-4", "meter-13"]


def _save_topology(output: Path) -> None:
    graph = build_simulation_graph(20, SEED)
    healed = graph.copy()
    healed.remove_nodes_from(FAILED_NODES)
    route = nx.shortest_path(healed, "meter-3", GATEWAY_ID)
    positions = nx.spring_layout(graph, seed=SEED)
    figure, axes = plt.subplots(1, 2, figsize=(13, 6))
    failed = set(FAILED_NODES)
    for ax, view, title in (
        (axes[0], graph, "Before relay failures"),
        (axes[1], healed, "After failures and reroute"),
    ):
        node_colors = ["#d1495b" if node in failed else "#2a9d8f" if node == GATEWAY_ID else "#e9c46a"
                       for node in view.nodes]
        nx.draw_networkx_edges(view, positions, ax=ax, edge_color="#b9c1c8", width=1.2)
        nx.draw_networkx_nodes(view, positions, ax=ax, node_color=node_colors, node_size=350)
        nx.draw_networkx_labels(view, positions, ax=ax, font_size=7)
        if title.startswith("After"):
            nx.draw_networkx_edges(
                view, positions, ax=ax, edgelist=list(zip(route, route[1:])),
                edge_color="#e76f51", width=3.0,
            )
        ax.set_title(title)
        ax.set_axis_off()
    figure.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=200, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    euler = run_simulation(
        20, 10, SEED, "euler", failed_nodes=FAILED_NODES
    )
    centralized = run_simulation(
        20, 10, SEED, "centralized", failed_nodes=FAILED_NODES
    )
    print(f"Scenario seed {SEED}; failed relays: {', '.join(FAILED_NODES)}")
    for event in euler["events"]:
        stamp = f"{event['time_ms']:9.2f} ms"
        if event["event"] == "failure":
            print(f"{stamp} Node {' and '.join(event['failed_nodes'])} lost")
        elif event["event"] == "detection":
            print(f"{stamp} {event['node_id']} detects missing heartbeat from {event['failed_node']}")
        elif event["event"] == "reroute":
            print(f"{stamp} reroute {event['node_id']} via {' -> '.join(event['route'])}")
        elif event["event"] == "key_derived":
            print(f"{stamp} {event['node_id']} derives a bridging key locally")
        elif event["event"] == "first_packet_delivered":
            print(f"{stamp} encrypted packet delivered by {event['node_id']}")
    print(
        "Comparison: Euler control bytes/recovery "
        f"{euler['control_bytes']} B/{euler['recovery_ms']:.2f} ms; "
        "centralized "
        f"{centralized['control_bytes']} B/{centralized['recovery_ms']:.2f} ms."
    )
    _save_topology(Path("results/demo_topology.png"))


if __name__ == "__main__":
    main()