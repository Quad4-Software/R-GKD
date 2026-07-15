from __future__ import annotations

from dataclasses import dataclass

from RNS.Cryptography import Ed25519PrivateKey, X25519PrivateKey
from RNS.Identity import Identity

from . import constants
from .util import require_len


@dataclass(frozen=True)
class PeerKeys:
    """RNS-shaped peer: X25519 encryption half plus Ed25519 signing half."""

    x25519_private: X25519PrivateKey
    ed25519_private: Ed25519PrivateKey

    @property
    def member_pub(self) -> bytes:
        return self.x25519_private.public_key().public_bytes()

    @property
    def admin_pub(self) -> bytes:
        return self.ed25519_private.public_key().public_bytes()

    @property
    def rns_public_key(self) -> bytes:
        return self.member_pub + self.admin_pub

    def sign(self, message: bytes) -> bytes:
        return self.ed25519_private.sign(message)


def generate_peer_keys() -> PeerKeys:
    return PeerKeys(
        x25519_private=X25519PrivateKey.generate(),
        ed25519_private=Ed25519PrivateKey.generate(),
    )


def split_rns_public_key(public_key: bytes) -> tuple[bytes, bytes]:
    require_len(public_key, constants.RNS_PUBLIC_KEY_SIZE, "rns public key")
    half = constants.X25519_PUB_SIZE
    return public_key[:half], public_key[half:]


def destination_hash_from_public(public_key: bytes) -> bytes:
    """Truncated hash of the full RNS public key, matching Identity.hash length."""
    require_len(public_key, constants.RNS_PUBLIC_KEY_SIZE, "rns public key")
    return Identity.truncated_hash(public_key)


class MemberBindStatus:
    PENDING = "pending"
    ACTIVE = "active"
    MISMATCH = "mismatch"


def bind_member_pub(
    *,
    member_x25519_pub: bytes,
    reticulum_dst_hash: bytes,
    resolved_rns_public_key: bytes | None,
) -> str:
    """Return pending, active, or mismatch per draft identity binding rules."""
    require_len(member_x25519_pub, constants.X25519_PUB_SIZE, "member_x25519_pub")
    require_len(reticulum_dst_hash, constants.HASH16, "reticulum_dst_hash")
    if resolved_rns_public_key is None:
        return MemberBindStatus.PENDING
    require_len(
        resolved_rns_public_key,
        constants.RNS_PUBLIC_KEY_SIZE,
        "resolved_rns_public_key",
    )
    if destination_hash_from_public(resolved_rns_public_key) != reticulum_dst_hash:
        return MemberBindStatus.MISMATCH
    enc, _sig = split_rns_public_key(resolved_rns_public_key)
    if enc != member_x25519_pub:
        return MemberBindStatus.MISMATCH
    return MemberBindStatus.ACTIVE
