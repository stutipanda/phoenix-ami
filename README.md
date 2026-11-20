# PHOENIX-AMI

PHOENIX-AMI is an academic simulation of key recovery in a rural smart-meter
mesh. It compares a local Euler-totient-based key-stitching experiment with a
centralized re-keying baseline over the same seeded topology and relay-failure
scenario. The simulator tracks routed control traffic, encrypted telemetry,
recovery events, and modeled network delay.

This project is for experimentation, not production security. Its
Euler-totient token construction in `src/crypto_engine.py` is nonstandard and
has not been peer reviewed. Simulation timing combines measured local crypto
time with modeled network delay; it is not a radio or field measurement.

## Install

From the repository root, create a virtual environment and install the pinned
dependencies:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The commands below use the venv interpreter directly, so activating the
environment is optional.

## Demo

Run the fixed-seed, 20-meter scenario with relay failures, timestamped
recovery events, and a comparison against centralized re-keying:

```powershell
.\.venv\Scripts\python.exe demo.py
```

The demo writes `results/demo_topology.png`. It reports packet and control
metrics without printing key material.

## Tests

Run the complete pytest suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Tests cover the existing mesh and crypto primitives, CBOR packet framing,
authenticated encryption, reproducibility of scenario counts, relay recovery,
and documented partition and adjacent-failure limitations.

## Benchmarks

Run a short sweep for a quick check, or the full sweep for 30 paired trials
per combination:

```powershell
.\.venv\Scripts\python.exe benchmark.py --quick
.\.venv\Scripts\python.exe benchmark.py
```

The full sweep covers 10, 25, 50, and 100 meters; 5% through 25% dropout;
Euler and centralized modes; and a shared seed list for paired comparisons.
Disconnected pre-failure graphs are recorded in `results/benchmark_skipped.csv`.
The `--quick` option uses fewer trials and is intended for smoke testing, not
strong statistical conclusions.

Regenerate plots from the saved CSVs without rerunning the benchmark:

```powershell
.\.venv\Scripts\python.exe plots.py
```

The benchmark writes `results/benchmark_results.csv`, `results/summary.csv`,
and `results/crypto_benchmark.csv`. The plot command produces PNG and PDF
versions of overhead, recovery latency, crypto compute, unrecovered-node, and
bandwidth-savings charts in `results/`.

## Packet Accounting

Frames use a compact fixed-order CBOR array: `[type-code, sender, recipient,
nonce, ciphertext]`. `src.packet.size_bytes` is the canonical encoded frame
size. Control-byte totals count each transmission on each hop, including
forwarded packets.

## Project Structure

```text
phoenix-ami/
|-- src/
|   |-- crypto_engine.py   # Modular key experiment and AES-GCM helpers
|   |-- mesh_sim.py        # NetworkX mesh topology and routing
|   |-- packet.py          # Packet model, CBOR codec, frame sizing
|   |-- baseline.py        # Centralized unicast re-keying
|   |-- simulation.py      # Shared Euler and centralized simulation
|   |-- benchmark.py       # Paired sweeps and crypto timings
|   |-- plots.py           # CSV-based plots
|   `-- demo.py            # Fixed-seed console demonstration
|-- tests/                 # Crypto, mesh, and integration tests
|-- results/               # Benchmark CSVs and generated figures
|-- docs/limitations.md    # Assumptions and known limitations
|-- requirements.txt       # Pinned Python dependencies
|-- demo.py                # Root command wrapper
|-- benchmark.py           # Root command wrapper
`-- plots.py               # Root command wrapper
```

See [docs/limitations.md](docs/limitations.md) for recovery assumptions and
known limitations, including physical partitions, adjacent relay failures,
and the experimental status of the key-stitching construction.
