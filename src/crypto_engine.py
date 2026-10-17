import math
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoEngineError(Exception):
    """Base exception for Phoenix-AMI."""


class InvalidParameterError(CryptoEngineError):
    """Invalid cryptographic parameter."""


class AuthenticationError(CryptoEngineError):
    """AES-GCM authentication failed."""


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin probable-prime test."""
    if n < 2:
        return False

    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a probable prime for academic simulation."""
    if bits < 16:
        raise InvalidParameterError("Prime size must be at least 16 bits.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate


def random_coprime(modulus: int) -> int:
    """Generate a value relatively prime to modulus."""
    while True:
        value = secrets.randbelow(modulus - 1) + 1
        if math.gcd(value, modulus) == 1:
            return value


def int_to_bytes(value: int) -> bytes:
    if value < 0:
        raise InvalidParameterError("Negative integers are not supported.")

    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


@dataclass(frozen=True)
class NodeCredential:
    node_id: str
    x: int
    Y: int


@dataclass(frozen=True)
class EncryptedTelemetry:
    nonce: bytes
    ciphertext: bytes


class GatewayAuthority:
    """
    Gateway for the Phoenix-AMI experimental key-stitching simulation.

    WARNING: The totient-token construction is not a validated secure
    key-exchange protocol. Use only for academic experimentation.
    """

    def __init__(self, prime_bits: int = 64):
        self.p = generate_prime(prime_bits)

        while True:
            self.q = generate_prime(prime_bits)
            if self.p != self.q:
                break

        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)

        # A unit modulo n; not guaranteed to generate the full group.
        self.g = random_coprime(self.n)
        self.credentials: dict[str, NodeCredential] = {}

    def register_node(self, node_id: str) -> NodeCredential:
        if not node_id or not node_id.strip():
            raise InvalidParameterError("Node ID cannot be empty.")

        if node_id in self.credentials:
            raise InvalidParameterError(f"{node_id} is already registered.")

        x = random_coprime(self.phi_n)
        Y = pow(self.g, x, self.n)

        credential = NodeCredential(node_id, x, Y)
        self.credentials[node_id] = credential
        return credential

    def get_credential(self, node_id: str) -> NodeCredential:
        try:
            return self.credentials[node_id]
        except KeyError as exc:
            raise InvalidParameterError(
                f"Unknown node: {node_id}"
            ) from exc

    def create_node(self, node_id: str) -> "MeshCryptoNode":
        credential = self.get_credential(node_id)

        return MeshCryptoNode(
            node_id=node_id,
            n=self.n,
            g=self.g,
            x=credential.x,
            Y=credential.Y,
        )

    def issue_bridging_token(
        self,
        intermediate_id: str,
        target_id: str,
    ) -> int:
        """
        Experimental token:
        T = x_intermediate^(-1) * x_target mod phi(n).
        """
        intermediate = self.get_credential(intermediate_id)
        target = self.get_credential(target_id)

        inverse = pow(intermediate.x, -1, self.phi_n)
        return (inverse * target.x) % self.phi_n


class MeshCryptoNode:
    """Simulated smart meter with local cryptographic operations."""

    def __init__(self, node_id: str, n: int, g: int, x: int, Y: int):
        if not node_id:
            raise InvalidParameterError("Node ID cannot be empty.")

        if n <= 2 or not (1 < g < n):
            raise InvalidParameterError("Invalid modulus or base.")

        if math.gcd(g, n) != 1:
            raise InvalidParameterError("g must be in Z_n*.")

        if x < 1:
            raise InvalidParameterError("Private exponent must be positive.")

        if not (1 <= Y < n) or math.gcd(Y, n) != 1:
            raise InvalidParameterError("Y must be in Z_n*.")

        if pow(g, x, n) != Y:
            raise InvalidParameterError("Y does not match g^x mod n.")

        self.node_id = node_id
        self.n = n
        self.g = g
        self.x = x
        self.Y = Y

    def derive_pairwise_secret(self, peer_public: int) -> int:
        """Compute the experimental modular shared value."""
        if not (1 <= peer_public < self.n):
            raise InvalidParameterError("Peer public value is out of range.")

        if math.gcd(peer_public, self.n) != 1:
            raise InvalidParameterError("Peer public value is not a unit.")

        return pow(peer_public, self.x, self.n)

    def stitch_shared_secret(
        self,
        intermediate_shared_secret: int,
        bridging_token: int,
    ) -> int:
        """Apply S_AC = S_AB^T mod n."""
        if not (1 <= intermediate_shared_secret < self.n):
            raise InvalidParameterError("Invalid intermediate shared value.")

        if math.gcd(intermediate_shared_secret, self.n) != 1:
            raise InvalidParameterError("Shared value is not a unit.")

        if bridging_token < 0:
            raise InvalidParameterError("Token cannot be negative.")

        return pow(intermediate_shared_secret, bridging_token, self.n)

   
    @staticmethod
    def _derive_aes_key(shared_secret: int, salt: bytes) -> bytes:
        if shared_secret < 0:
            raise InvalidParameterError("Shared secret cannot be negative.")

        if not isinstance(salt, bytes) or len(salt) < 12:
            raise InvalidParameterError("Salt must be at least 12 bytes.")

        return HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            info=b"Phoenix-AMI telemetry AES-128-GCM v1",
        ).derive(int_to_bytes(shared_secret))

    @staticmethod
    def encrypt_telemetry(
        shared_secret: int,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedTelemetry:
        if not isinstance(plaintext, bytes):
            raise InvalidParameterError("Plaintext must be bytes.")

        if associated_data is not None and not isinstance(
            associated_data, bytes
        ):
            raise InvalidParameterError("Associated data must be bytes.")

        nonce = secrets.token_bytes(12)
        key = MeshCryptoNode._derive_aes_key(shared_secret, nonce)

        ciphertext = AESGCM(key).encrypt(
            nonce, plaintext, associated_data
        )

        return EncryptedTelemetry(nonce, ciphertext)

    @staticmethod
    def decrypt_telemetry(
        shared_secret: int,
        packet: EncryptedTelemetry,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        if not isinstance(packet, EncryptedTelemetry):
            raise InvalidParameterError("Invalid telemetry packet.")

        if len(packet.nonce) != 12:
            raise InvalidParameterError("Nonce must be 12 bytes.")

        key = MeshCryptoNode._derive_aes_key(
            shared_secret, packet.nonce
        )

        try:
            return AESGCM(key).decrypt(
                packet.nonce,
                packet.ciphertext,
                associated_data,
            )
        except InvalidTag as exc:
            raise AuthenticationError(
                "Authentication failed: key, ciphertext, or AAD is invalid."
            ) from exc
