from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from time import time

from . import constants
from .crypto import commit_grs, sign_ed25519, verify_ed25519
from .identity import PeerKeys
from .util import be16, be32, be64, require_len


@dataclass(frozen=True)
class MemberEntry:
    member_id: bytes
    reticulum_dst_hash: bytes
    member_x25519_pub: bytes
    member_key_version: int = 1

    def __post_init__(self) -> None:
        require_len(self.member_id, constants.HASH16, "member_id")
        require_len(self.reticulum_dst_hash, constants.HASH16, "reticulum_dst_hash")
        require_len(
            self.member_x25519_pub, constants.X25519_PUB_SIZE, "member_x25519_pub",
        )

    def pack(self) -> bytes:
        return (
            self.member_id
            + self.reticulum_dst_hash
            + self.member_x25519_pub
            + be32(self.member_key_version)
        )


def pack_state_body(
    *,
    group_id: bytes,
    state_seq: int,
    prev_state_hash: bytes,
    admin_pub: bytes,
    grs_commit: bytes,
    members: list[MemberEntry],
    epoch_policy: int = constants.EPOCH_POLICY_LOCAL_COUNTER,
    bucket_seconds: int = 0,
    flags: int = 0,
    created_unix: int | None = None,
) -> bytes:
    require_len(group_id, constants.HASH16, "group_id")
    require_len(prev_state_hash, constants.HASH32, "prev_state_hash")
    require_len(admin_pub, constants.ED25519_PUB_SIZE, "admin_pub")
    require_len(grs_commit, constants.HASH32, "grs_commit")
    ordered = sorted(members, key=lambda m: m.member_id)
    if len(ordered) > constants.MAX_MEMBERS:
        raise ValueError(
            f"v1 allows at most {constants.MAX_MEMBERS} members, got {len(ordered)}",
        )
    if len({m.member_id for m in ordered}) != len(ordered):
        raise ValueError("member_id values must be unique")
    if flags & ~constants.STATE_KNOWN_FLAGS:
        raise ValueError("unknown state flag bits")

    body = bytearray()
    body += constants.STATE_MAGIC
    body += bytes([constants.STATE_VERSION])
    body += group_id
    body += be32(state_seq)
    body += prev_state_hash
    body += be64(int(time()) if created_unix is None else created_unix)
    body += bytes([epoch_policy])
    body += be32(bucket_seconds)
    body += be16(flags)
    body += admin_pub
    body += grs_commit
    body += be16(len(ordered))
    for member in ordered:
        body += member.pack()
    body += be16(0)
    return bytes(body)


_OFF_ADMIN_PUB = 72
_OFF_GRS_COMMIT = 104
_OFF_STATE_FLAGS = 70


def sign_state(
    *,
    group_id: bytes,
    state_seq: int,
    prev_state_hash: bytes,
    admin: PeerKeys,
    grs: bytes,
    members: list[MemberEntry],
    epoch_policy: int = constants.EPOCH_POLICY_LOCAL_COUNTER,
    bucket_seconds: int = 0,
    flags: int = 0,
    created_unix: int | None = None,
) -> bytes:
    body = pack_state_body(
        group_id=group_id,
        state_seq=state_seq,
        prev_state_hash=prev_state_hash,
        admin_pub=admin.admin_pub,
        grs_commit=commit_grs(grs, group_id, state_seq),
        members=members,
        epoch_policy=epoch_policy,
        bucket_seconds=bucket_seconds,
        flags=flags,
        created_unix=created_unix,
    )
    return body + sign_ed25519(admin.ed25519_private, body)


def verify_state_object(state_object: bytes, expected_admin_pub: bytes) -> bytes:
    if len(state_object) < constants.STATE_FIXED_WITH_SIG:
        raise ValueError("state object too short")
    body = state_object[: -constants.ED25519_SIG_SIZE]
    signature = state_object[-constants.ED25519_SIG_SIZE :]
    if body[:4] != constants.STATE_MAGIC:
        raise ValueError("bad state magic")
    if body[4] != constants.STATE_VERSION:
        raise ValueError("bad state version")
    flags = int.from_bytes(body[_OFF_STATE_FLAGS : _OFF_STATE_FLAGS + 2], "big")
    if flags & ~constants.STATE_KNOWN_FLAGS:
        raise ValueError("unknown state flag bits")
    admin_pub = body[_OFF_ADMIN_PUB : _OFF_ADMIN_PUB + constants.ED25519_PUB_SIZE]
    if admin_pub != expected_admin_pub:
        raise ValueError("admin_pub mismatch")
    verify_ed25519(admin_pub, body, signature)
    return body


def grs_commit_from_state_body(body: bytes) -> bytes:
    return body[_OFF_GRS_COMMIT : _OFF_GRS_COMMIT + constants.HASH32]


def verify_unsealed_grs(
    grs: bytes,
    *,
    group_id: bytes,
    state_seq: int,
    state_body: bytes,
) -> None:
    expected = grs_commit_from_state_body(state_body)
    got = commit_grs(grs, group_id, state_seq)
    if got != expected:
        raise ValueError("GRS does not match admin-signed commitment")


def state_body_hash(body: bytes) -> bytes:
    return sha256(body).digest()


def pack_keydist_body(
    *,
    group_id: bytes,
    state_seq: int,
    state_hash: bytes,
    recipients: list[tuple[bytes, bytes]],
) -> bytes:
    require_len(group_id, constants.HASH16, "group_id")
    require_len(state_hash, constants.HASH32, "state_hash")
    if len(recipients) > constants.MAX_MEMBERS:
        raise ValueError(
            f"v1 allows at most {constants.MAX_MEMBERS} recipients, got {len(recipients)}",
        )
    ids = [member_id for member_id, _ in recipients]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate keydist recipient MemberID")
    out = bytearray()
    out += constants.KEYDIST_MAGIC
    out += group_id
    out += be32(state_seq)
    out += state_hash
    out += be16(len(recipients))
    for member_id, seal_blob in recipients:
        require_len(member_id, constants.HASH16, "MemberID")
        require_len(seal_blob, constants.SEAL_BLOB_SIZE, "SealBlob")
        out += member_id
        out += seal_blob
    return bytes(out)


def keydist_has_recipient(keydist_body: bytes, member_id: bytes) -> bool:
    require_len(member_id, constants.HASH16, "MemberID")
    if len(keydist_body) < constants.KEYDIST_FIXED_BODY:
        raise ValueError("keydist body too short")
    count = int.from_bytes(keydist_body[56:58], "big")
    offset = 58
    row = constants.HASH16 + constants.SEAL_BLOB_SIZE
    for _ in range(count):
        if offset + row > len(keydist_body):
            raise ValueError("truncated keydist recipients")
        if keydist_body[offset : offset + constants.HASH16] == member_id:
            return True
        offset += row
    return False


def pack_keydist(
    *,
    group_id: bytes,
    state_seq: int,
    state_hash: bytes,
    recipients: list[tuple[bytes, bytes]],
    admin: PeerKeys,
) -> bytes:
    body = pack_keydist_body(
        group_id=group_id,
        state_seq=state_seq,
        state_hash=state_hash,
        recipients=recipients,
    )
    return body + sign_ed25519(admin.ed25519_private, body)


def verify_keydist(keydist: bytes, expected_admin_pub: bytes) -> bytes:
    if len(keydist) < constants.KEYDIST_FIXED:
        raise ValueError("keydist too short")
    body = keydist[: -constants.ED25519_SIG_SIZE]
    signature = keydist[-constants.ED25519_SIG_SIZE :]
    if body[:4] != constants.KEYDIST_MAGIC:
        raise ValueError("bad keydist magic")
    verify_ed25519(expected_admin_pub, body, signature)
    return body


def pack_ordinary_header(
    *,
    group_id: bytes,
    member_id: bytes,
    state_seq: int,
    epoch: int,
    counter: int,
    fmt: int = constants.MSG_FORMAT_TOKEN,
    has_signature: bool = False,
) -> bytes:
    require_len(group_id, constants.HASH16, "group_id")
    require_len(member_id, constants.HASH16, "member_id")
    if fmt != constants.MSG_FORMAT_TOKEN:
        raise ValueError(f"unknown format {fmt}")
    flags = constants.MSG_FLAG_HAS_SIG if has_signature else 0
    if flags & ~constants.MSG_KNOWN_FLAGS:
        raise ValueError("unknown message flag bits")
    header = bytearray()
    header += be16(constants.MSG_MAGIC)
    header += bytes([fmt, flags])
    header += group_id[:8]
    header += be32(state_seq)
    header += be32(epoch)
    header += member_id[:8]
    header += be32(counter)
    return bytes(header)


def ordinary_message_min_length(*, has_signature: bool) -> int:
    return constants.MSG_MIN_SIGNED if has_signature else constants.MSG_MIN_UNSIGNED


def validate_ordinary_message_length(message: bytes) -> None:
    """Reject truncated ordinary messages before splitting token and signature."""
    if len(message) < 4:
        raise ValueError("ordinary message too short")
    fmt = message[2]
    flags = message[3]
    if fmt != constants.MSG_FORMAT_TOKEN:
        raise ValueError(f"unknown format {fmt}")
    if flags & ~constants.MSG_KNOWN_FLAGS:
        raise ValueError("unknown message flag bits")
    has_sig = bool(flags & constants.MSG_FLAG_HAS_SIG)
    minimum = ordinary_message_min_length(has_signature=has_sig)
    if len(message) < minimum:
        raise ValueError(
            f"ordinary message too short: need {minimum}, got {len(message)}"
        )
    body_after_header = len(message) - constants.MSG_HEADER
    if has_sig:
        body_after_header -= constants.ED25519_SIG_SIZE
    if body_after_header < constants.MSG_MIN_TOKEN:
        raise ValueError("token shorter than RNS Token minimum")
