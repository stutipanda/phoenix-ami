"""Paired Euler and centralized-rekey benchmark sweeps."""

from __future__ import annotations

import argparse
import math
import time
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd

from src.crypto_engine import GatewayAuthority
from src.simulation import build_simulation_graph, run_paired_scenario


NODE_COUNTS = [10, 25, 50, 100]
DROPOUT_RATES = [5, 10, 15, 20, 25]
SEED_START = 20261115
METRICS = [
    "control_bytes",
    "control_packets",
    "recovery_ms",
    "packets_sent",
    "packets_delivered",
    "packets_lost",
    "nodes_unrecovered",
]


def _crypto_benchmark(output: Path, iterations: int) -> None:
    rows = []
    for modulus_bits in (1024, 2048):
        while True:
            authority = GatewayAuthority(prime_bits=modulus_bits // 2)
            if authority.n.bit_length() == modulus_bits:
                break
        authority.register_node("crypto-a")
        authority.register_node("crypto-b")
        node_a = authority.create_node("crypto-a")
        node_b = authority.create_node("crypto-b")
        samples = []
        for _ in range(iterations):
            started = time.perf_counter()
            node_a.derive_pairwise_secret(node_b.Y)
            samples.append((time.perf_counter() - started) * 1000)
        deviation = float(np.std(samples, ddof=1)) if len(samples) > 1 else 0.0
        margin = 1.96 * deviation / math.sqrt(len(samples))
        rows.append({
            "modulus_bits": modulus_bits,
            "iterations": iterations,
            "mean_ms": float(np.mean(samples)),
            "std_ms": deviation,
            "ci95_low_ms": max(0.0, float(np.mean(samples)) - margin),
            "ci95_high_ms": float(np.mean(samples)) + margin,
        })
        print(f"Crypto benchmark: {modulus_bits}-bit modulus complete")
    pd.DataFrame(rows).to_csv(output, index=False)


def run_benchmark(quick: bool = False, results_dir: Path = Path("results")) -> None:
    trials = 2 if quick else 30
    crypto_iterations = 5 if quick else 100
    results_dir.mkdir(parents=True, exist_ok=True)
    records = []
    skipped = []
    total = len(NODE_COUNTS) * len(DROPOUT_RATES) * trials
    completed = 0

    for nodes in NODE_COUNTS:
        for dropout_pct in DROPOUT_RATES:
            for trial in range(trials):
                seed = SEED_START + trial
                initial_graph = build_simulation_graph(nodes, seed)
                if not nx.is_connected(initial_graph):
                    skipped.append({
                        "nodes": nodes,
                        "dropout_pct": dropout_pct,
                        "seed": seed,
                        "reason": "disconnected_before_failures",
                    })
                    completed += 1
                    print(f"\rBenchmark {completed}/{total} (skipped disconnected)", end="")
                    continue

                paired = run_paired_scenario(nodes, dropout_pct, seed)
                for mode, metrics in paired.items():
                    records.append({
                        "mode": mode,
                        "nodes": nodes,
                        "dropout_pct": dropout_pct,
                        "seed": seed,
                        **{metric: metrics[metric] for metric in METRICS},
                    })
                completed += 1
                print(f"\rBenchmark {completed}/{total}", end="")
    print()

    columns = ["mode", "nodes", "dropout_pct", "seed", *METRICS]
    raw = pd.DataFrame(records, columns=columns)
    raw.to_csv(results_dir / "benchmark_results.csv", index=False)
    pd.DataFrame(skipped, columns=["nodes", "dropout_pct", "seed", "reason"]).to_csv(
        results_dir / "benchmark_skipped.csv", index=False
    )

    summary_rows = []
    for keys, group in raw.groupby(["mode", "nodes", "dropout_pct"]):
        for metric in METRICS:
            values = group[metric].astype(float).dropna()
            mean = float(values.mean())
            std = float(values.std(ddof=1)) if len(values) > 1 else 0.0
            margin = 1.96 * std / math.sqrt(len(values))
            summary_rows.append({
                "mode": keys[0],
                "nodes": keys[1],
                "dropout_pct": keys[2],
                "metric": metric,
                "mean": mean,
                "std": std,
                "ci95_low": mean - margin,
                "ci95_high": mean + margin,
                "trials": len(values),
            })
    pd.DataFrame(summary_rows).to_csv(results_dir / "summary.csv", index=False)
    _crypto_benchmark(results_dir / "crypto_benchmark.csv", crypto_iterations)
    print(f"Saved {len(raw)} paired-mode rows; skipped {len(skipped)} disconnected trials.")
    print(f"Results: {results_dir.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="Run two paired trials per setting")
    args = parser.parse_args()
    run_benchmark(quick=args.quick)


if __name__ == "__main__":
    main()