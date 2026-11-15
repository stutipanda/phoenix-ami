# PHOENIX-AMI

An academic simulation of key recovery and centralized re-keying in a smart
meter mesh. The Euler-totient token construction in `src/crypto_engine.py` is
nonstandard and has not been peer reviewed; this project is not production
security software.

## Setup

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
```

## Run

```powershell
python -m src.benchmark --quick
python -m src.plots
python -m src.demo
```

Use `python -m src.benchmark` for the full paired sweep. Benchmark and plot
outputs are written to `results/`.

Packet frames use a fixed-order CBOR array `[type-code, sender, recipient,
nonce, ciphertext]`; `src.packet.size_bytes` is the canonical frame-size
measurement. Control bytes are hop-by-hop transmissions.
