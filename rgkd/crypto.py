from __future__ import annotations

from hashlib import sha256

from RNS.Cryptography import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Token,
    X25519PrivateKey,
    X25519PublicKey,
    hkdf,
)

from . import constants
from .util import be32, require_len


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return hkdf(length=length, derive_from=ikm, salt=salt, context=info)


def commit_grs(grs: bytes, group_id: bytes, state_seq: int) -> bytes:
    require_len(grs, 32, "GRS")
    require_len(group_id, constants.HASH16, "GroupID")
    return sha256(constants.LABEL_GRS + group_id + be32(state_seq) + grs).digest()


def derive_epoch_key(grs: bytes, group_id: bytes, state_seq: int, epoch: int) -> bytes:
    require_len(grs, 32, "GRS")
    require_len(group_id, constants.HASH16, "GroupID")
    return hkdf_sha256(
        grs,
        salt=group_id,
        info=constants.LABEL_EPOCH + be32(state_seq) + be32(epoch),
        length=32,
    )


def derive_sender_key(
    ck: bytes,
    group_id: bytes,
    member_id: bytes,
    state_seq: int,
    epoch: int,
) -> bytes:
    require_len(member_id, constants.HASH16, "MemberID")
    return hkdf_sha256(
        ck,
        salt=group_id,
        info=constants.LABEL_SENDER + member_id + be32(state_seq) + be32(epoch),
        length=32,
    )


def derive_message_key(sender_key: bytes, group_id: bytes, counter: int) -> bytes:
    """64-byte RNS Token key: HMAC half || AES half."""
    return hkdf_sha256(
        sender_key,
        salt=group_id,
        info=constants.LABEL_MSG + be32(counter),
        length=constants.TOKEN_KEY_SIZE,
    )


def encrypt_token(key: bytes, plaintext: bytes) -> bytes:
    require_len(key, constants.TOKEN_KEY_SIZE, "Token key")
    return Token(key).encrypt(plaintext)


def decrypt_token(key: bytes, token: bytes) -> bytes:
    require_len(key, constants.TOKEN_KEY_SIZE, "Token key")
    if len(token) < constants.TOKEN_OVERHEAD + constants.AES_BLOCK:
        raise ValueError("token too short")
    return Token(key).decrypt(token)


def seal_grs(
    *,
    grs: bytes,
    group_id: bytes,
    state_seq: int,
    member_id: bytes,
    member_pub: bytes,
    eph_private: X25519PrivateKey | None = None,
) -> bytes:
    """Seal GRS to one member X25519 public key. Returns SealBlob."""
    require_len(grs, 32, "GRS")
    require_len(group_id, constants.HASH16, "GroupID")
    require_len(member_id, constants.HASH16, "MemberID")
    require_len(member_pub, constants.X25519_PUB_SIZE, "MemberPub")

    eph = eph_private or X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes()
    if member_pub == bytes(32):
        raise ValueError("invalid MemberPub")
    peer = X25519PublicKey.from_public_bytes(member_pub)
    shared = eph.exchange(peer)
    if shared == bytes(32):
        raise ValueError("invalid X25519 shared secret")
    seal_key = hkdf_sha256(
        shared,
        salt=group_id,
        info=constants.LABEL_SEAL + member_id,
        length=constants.TOKEN_KEY_SIZE,
    )
    plaintext = grs + group_id + be32(state_seq)
    token = encrypt_token(seal_key, plaintext)
    blob = eph_pub + token
    if len(blob) != constants.SEAL_BLOB_SIZE:
        raise RuntimeError(f"unexpected seal blob size {len(blob)}")
    return blob


def unseal_grs(
    *,
    seal_blob: bytes,
    group_id: bytes,
    state_seq: int,
    member_id: bytes,
    member_private: X25519PrivateKey,
) -> bytes:
    require_len(seal_blob, constants.SEAL_BLOB_SIZE, "SealBlob")
    eph_pub = seal_blob[:32]
    token = seal_blob[32:]
    eph = X25519PublicKey.from_public_bytes(eph_pub)
    shared = member_private.exchange(eph)
    if shared == bytes(32):
        raise ValueError("invalid X25519 shared secret")
    seal_key = hkdf_sha256(
        shared,
        salt=group_id,
        info=constants.LABEL_SEAL + member_id,
        length=constants.TOKEN_KEY_SIZE,
    )
    plaintext = decrypt_token(seal_key, token)
    if len(plaintext) != constants.SEAL_PLAINTEXT_SIZE:
        raise ValueError("bad seal plaintext length")
    grs = plaintext[:32]
    got_gid = plaintext[32:48]
    got_seq = int.from_bytes(plaintext[48:52], "big")
    if got_gid != group_id or got_seq != state_seq:
        raise ValueError("seal plaintext group binding mismatch")
    return grs


def sign_ed25519(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> None:
    require_len(public_key, constants.ED25519_PUB_SIZE, "AdminPub")
    require_len(signature, constants.ED25519_SIG_SIZE, "signature")
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)


def message_key_for(
    *,
    grs: bytes,
    group_id: bytes,
    member_id: bytes,
    state_seq: int,
    epoch: int,
    counter: int,
) -> bytes:
    ck = derive_epoch_key(grs, group_id, state_seq, epoch)
    sk = derive_sender_key(ck, group_id, member_id, state_seq, epoch)
    return derive_message_key(sk, group_id, counter)
