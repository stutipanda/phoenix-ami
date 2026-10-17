"""Packet models for the Phoenix-AMI simulation."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TelemetryPacket:
    source: str
    destination: str
    payload: bytes
    associated_data: bytes = b""
    nonce: bytes = b""
    ciphertext: bytes = b""
    tag: bytes = b""
    route: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
