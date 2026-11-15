"""Generate publication-sized benchmark plots from saved CSV results."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


PALETTE = sns.color_palette("colorblind", 5)


def _save(figure: plt.Figure, output: Path, name: str) -> None:
    figure.savefig(output / f"{name}.png", dpi=200, bbox_inches="tight")
    figure.savefig(output / f"{name}.pdf", bbox_inches="tight")
    plt.close(figure)


def _error_line(
    ax: plt.Axes,
    rows: pd.DataFrame,
    metric: str,
    *,
    group_column: str,
    group_value: str | int,
    label: str,
    color: object,
    marker: str,
) -> None:
    selected = rows[rows[group_column] == group_value].sort_values("nodes")
    if selected.empty:
        return
    mean = selected["mean"].to_numpy(dtype=float)
    lower = mean - selected["ci95_low"].to_numpy(dtype=float)
    upper = selected["ci95_high"].to_numpy(dtype=float) - mean
    ax.errorbar(
        selected["nodes"], mean, yerr=np.vstack([lower, upper]),
        marker=marker, capsize=3, linewidth=1.8, color=color, label=label,
    )


def generate_plots(results_dir: Path = Path("results")) -> None:
    raw = pd.read_csv(results_dir / "benchmark_results.csv")
    summary = pd.read_csv(results_dir / "summary.csv")
    crypto = pd.read_csv(results_dir / "crypto_benchmark.csv")
    sns.set_theme(style="whitegrid", context="talk")
    modes = ["euler", "centralized"]
    dropouts = sorted(raw["dropout_pct"].unique())
    dropout_colors = dict(zip(dropouts, PALETTE))
    mode_markers = {"euler": "o", "centralized": "s"}

    overhead = summary[summary["metric"] == "control_bytes"]
    fig, ax = plt.subplots(figsize=(12, 7))
    for mode in modes:
        for dropout in dropouts:
            _error_line(
                ax, overhead[overhead["mode"] == mode], "control_bytes",
                group_column="dropout_pct", group_value=dropout,
                label=f"{mode.title()}, {dropout}%", color=dropout_colors[dropout],
                marker=mode_markers[mode],
            )
    ax.set(title="Control overhead by network size", xlabel="Meter nodes", ylabel="Control bytes (per trial)")
    ax.legend(ncol=2, fontsize=9, title="Mode, dropout")
    _save(fig, results_dir, "overhead_bytes")

    latency = summary[summary["metric"] == "recovery_ms"]
    fig, ax = plt.subplots(figsize=(12, 7))
    for mode in modes:
        for dropout in dropouts:
            subset = latency[(latency["mode"] == mode) & (latency["dropout_pct"] == dropout)]
            if subset.empty:
                continue
            subset = subset.sort_values("nodes")
            mean = subset["mean"].to_numpy(dtype=float)
            ax.errorbar(
                subset["nodes"], mean,
                yerr=np.vstack([mean - subset["ci95_low"], subset["ci95_high"] - mean]),
                color=dropout_colors[dropout], marker=mode_markers[mode],
                linestyle="-" if mode == "euler" else "--", capsize=3,
                label=f"{mode.title()}, {dropout}%",
            )
    ax.set(title="Recovery latency by network size", xlabel="Meter nodes", ylabel="Recovery time (ms)")
    ax.legend(ncol=2, fontsize=9, title="Mode, dropout")
    _save(fig, results_dir, "recovery_latency")

    fig, ax = plt.subplots(figsize=(9, 6))
    positions = np.arange(len(crypto))
    mean = crypto["mean_ms"].to_numpy(dtype=float)
    ax.bar(positions, mean, color=["#2a9d8f", "#e76f51"], width=0.58)
    ax.errorbar(
        positions, mean,
        yerr=np.vstack([mean - crypto["ci95_low_ms"], crypto["ci95_high_ms"] - mean]),
        fmt="none", ecolor="#202020", capsize=6, linewidth=1.5,
    )
    ax.set_xticks(positions, [f"{bits}-bit" for bits in crypto["modulus_bits"]])
    ax.set(title="Modular key derivation cost", xlabel="Modulus size", ylabel="Mean derivation time (ms)")
    _save(fig, results_dir, "crypto_compute")

    unrecovered = summary[summary["metric"] == "nodes_unrecovered"]
    node_counts = sorted(unrecovered["nodes"].unique())
    fig, axes = plt.subplots(2, 2, figsize=(13, 9), sharex=True)
    for ax, nodes in zip(axes.flat, node_counts):
        for mode in modes:
            subset = unrecovered[(unrecovered["nodes"] == nodes) & (unrecovered["mode"] == mode)]
            subset = subset.sort_values("dropout_pct")
            mean = subset["mean"].to_numpy(dtype=float)
            ax.errorbar(
                subset["dropout_pct"], mean,
                yerr=np.vstack([mean - subset["ci95_low"], subset["ci95_high"] - mean]),
                marker=mode_markers[mode], capsize=3, label=mode.title(),
            )
        ax.set(title=f"{nodes} meter nodes", xlabel="Relay dropout (%)", ylabel="Unrecovered nodes")
    axes.flat[0].legend(title="Mode")
    fig.suptitle("Unrecovered nodes by relay dropout", y=1.02)
    _save(fig, results_dir, "unrecovered_nodes")

    paired = raw.pivot_table(
        index=["nodes", "dropout_pct", "seed"], columns="mode", values="control_bytes"
    ).dropna().reset_index()
    paired["savings_pct"] = np.where(
        paired["centralized"] > 0,
        100 * (paired["centralized"] - paired["euler"]) / paired["centralized"],
        np.nan,
    )
    savings_rows = []
    for (nodes, dropout), group in paired.groupby(["nodes", "dropout_pct"]):
        mean = float(group["savings_pct"].mean())
        std = float(group["savings_pct"].std(ddof=1)) if len(group) > 1 else 0.0
        margin = 1.96 * std / np.sqrt(len(group))
        savings_rows.append({
            "nodes": nodes, "dropout_pct": dropout, "mean": mean,
            "ci95_low": mean - margin, "ci95_high": mean + margin,
        })
    savings = pd.DataFrame(savings_rows)
    fig, ax = plt.subplots(figsize=(12, 7))
    for dropout in dropouts:
        subset = savings[savings["dropout_pct"] == dropout].sort_values("nodes")
        if subset.empty:
            continue
        mean = subset["mean"].to_numpy(dtype=float)
        ax.errorbar(
            subset["nodes"], mean,
            yerr=np.vstack([mean - subset["ci95_low"], subset["ci95_high"] - mean]),
            marker="o", capsize=3, color=dropout_colors[dropout], label=f"{dropout}% dropout",
        )
    ax.axhline(0, color="#333333", linewidth=1)
    ax.set(title="Euler control-byte reduction", xlabel="Meter nodes", ylabel="Control-byte savings (%)")
    ax.legend(title="Relay dropout")
    _save(fig, results_dir, "bandwidth_savings_pct")
    print(f"Saved five plot pairs to {results_dir.resolve()}")


def main() -> None:
    generate_plots()


if __name__ == "__main__":
    main()