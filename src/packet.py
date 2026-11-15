"""Packet models and compact CBOR framing for the Phoenix-AMI simulation.

The wire representation is a fixed-order CBOR array. Packet types are encoded
as small integer codes to avoid repeating their names in constrained frames.
"""

from dataclasses import dataclass, field
from typing import Any

import cbor2


PACKET_TYPES = {
    "DATA": 0,
    "HEARTBEAT": 1,
    "ACK": 2,
    "REKEY": 3,
    "BRIDGE_TOKEN": 4,
}
PACKET_TYPES_BY_CODE = {code: name for name, code in PACKET_TYPES.items()}


@dataclass(frozen=True)
class Packet:
    type: str
    sender_id: str
    recipient_id: str
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if self.type not in PACKET_TYPES:
            raise ValueError(f"Unsupported packet type: {self.type}")
        if not self.sender_id or not self.recipient_id:
            raise ValueError("Packet sender and recipient are required")
        if not isinstance(self.nonce, bytes) or len(self.nonce) != 12:
            raise ValueError("Packet nonce must be exactly 12 bytes")
        if not isinstance(self.ciphertext, bytes):
            raise ValueError("Packet ciphertext must be bytes")


def serialize(packet: Packet) -> bytes:
    """Encode a packet as [type-code, sender, recipient, nonce, ciphertext]."""
    if not isinstance(packet, Packet):
        raise TypeError("serialize expects a Packet")
    return cbor2.dumps([
        PACKET_TYPES[packet.type],
        packet.sender_id,
        packet.recipient_id,
        packet.nonce,
        packet.ciphertext,
    ])


def deserialize(data: bytes) -> Packet:
    """Decode and validate a fixed-order CBOR packet."""
    try:
        fields = cbor2.loads(data)
    except (cbor2.CBORDecodeError, TypeError) as exc:
        raise ValueError("Invalid CBOR packet") from exc
    if not isinstance(fields, list) or len(fields) != 5:
        raise ValueError("Packet must contain exactly five fields")
    code = fields[0]
    if not isinstance(code, int) or code not in PACKET_TYPES_BY_CODE:
        raise ValueError("Unknown packet type code")
    return Packet(
        type=PACKET_TYPES_BY_CODE[code],
        sender_id=fields[1],
        recipient_id=fields[2],
        nonce=fields[3],
        ciphertext=fields[4],
    )


def size_bytes(packet: Packet) -> int:
    """Return the exact encoded frame size; the sole project byte counter."""
    return len(serialize(packet))


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
