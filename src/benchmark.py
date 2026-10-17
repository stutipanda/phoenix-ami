"""Run a basic Phoenix-AMI mesh recovery benchmark."""

import json
from pathlib import Path

from src.mesh_sim import build_demo_mesh


def main() -> None:
    mesh = build_demo_mesh()
    result = mesh.simulate_relay_failure(
        "meter-A", "meter-D", "meter-B"
    )

    report = {
        "scenario": "single_relay_failure",
        "source": result.source,
        "destination": result.destination,
        "failed_node": result.failed_node,
        "recovered": result.recovered,
        "route": result.route,
        "elapsed_ms": result.elapsed_ms,
        "simulated_messages": result.messages_sent,
    }

    output = Path("results/mesh_benchmark.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
