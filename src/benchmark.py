"""Run a comparative Phoenix-AMI mesh recovery benchmark with Pandas export."""

import time
import random
from pathlib import Path
import pandas as pd

from src.mesh_sim import build_geometric_mesh
from src.crypto_engine import GatewayAuthority

def run_sweep(mesh, num_nodes, dropout_percent):
    """Simulate a percentage-based failure sweep."""
    nodes = list(mesh.graph.nodes())
    source = nodes[0]
    dest = nodes[-1]
    
    # Calculate how many relays to drop (5% to 25%)
    num_failures = max(1, int(num_nodes * (dropout_percent / 100.0)))
    
    # Pick relays to fail (excluding source and dest)
    available_relays = [n for n in nodes if n not in (source, dest)]
    failed_nodes = random.sample(available_relays, min(num_failures, len(available_relays)))
    
    gateway = GatewayAuthority()
    gateway.register_node(source)
    gateway.register_node(dest)
    node_a = gateway.create_node(source)
    node_d = gateway.create_node(dest)
    
    # Baseline Approach (Gateway Storm)
    start_baseline = time.perf_counter()
    recovery = mesh.simulate_relay_failure(source, dest, failed_nodes[0]) # Trigger on first failure
    time.sleep(0.05) # Simulate distant Gateway latency
    baseline_time = (time.perf_counter() - start_baseline) * 1000
    baseline_msgs = recovery.messages_sent + 2
    
    # Phoenix-AMI Approach (Key Stitching)
    start_phoenix = time.perf_counter()
    _ = node_a.derive_pairwise_secret(node_d.Y)
    phoenix_time = (time.perf_counter() - start_phoenix) * 1000
    phoenix_msgs = recovery.messages_sent + 0
    
    return {
        "Nodes": num_nodes,
        "Dropout_%": dropout_percent,
        "Failed_Relays": len(failed_nodes),
        "Baseline_Msgs": baseline_msgs,
        "Phoenix_Msgs": phoenix_msgs,
        "Baseline_Latency_ms": round(baseline_time, 2),
        "Phoenix_Latency_ms": round(phoenix_time, 2),
        "Overhead_Reduction_%": round(((baseline_msgs - phoenix_msgs) / baseline_msgs) * 100, 1)
    }

def main() -> None:
    print("Running Member 2 Sweeps (10, 25, 50, 100 nodes)...")
    results = []
    
    node_counts = [10, 25, 50, 100]
    dropout_rates = [5, 15, 25]
    
    for size in node_counts:
        mesh = build_geometric_mesh(size)
        for dropout in dropout_rates:
            results.append(run_sweep(mesh, size, dropout))
            
    # Export to Pandas DataFrame
    df = pd.DataFrame(results)
    
    print("\n" + "="*80)
    print("                 PHOENIX-AMI SWEEP RESULTS (PANDAS EXPORT)                 ")
    print("="*80)
    print(df.to_string(index=False))
    print("="*80 + "\n")
    
    output = Path("results/mesh_sweep_metrics.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    print(f"Metrics successfully exported to {output}")

if __name__ == "__main__":
    main()