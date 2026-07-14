from __future__ import annotations

from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import constants
from .util import be32, require_len


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


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
    )


def derive_message_key(sender_key: bytes, group_id: bytes, counter: int) -> bytes:
    return hkdf_sha256(
        sender_key,
        salt=group_id,
        info=constants.LABEL_MSG + be32(counter),
    )


def derive_nonce12(
    group_id: bytes,
    member_id: bytes,
    state_seq: int,
    epoch: int,
    counter: int,
) -> bytes:
    digest = sha256(
        constants.LABEL_NONCE
        + group_id
        + member_id
        + be32(state_seq)
        + be32(epoch)
        + be32(counter),
    ).digest()
    return digest[:12]


def encrypt_chacha(
    key: bytes,
    nonce12: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    require_len(key, 32, "AEAD key")
    require_len(nonce12, 12, "nonce")
    return ChaCha20Poly1305(key).encrypt(nonce12, plaintext, aad)


def decrypt_chacha(
    key: bytes,
    nonce12: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    require_len(key, 32, "AEAD key")
    require_len(nonce12, 12, "nonce")
    return ChaCha20Poly1305(key).decrypt(nonce12, ciphertext, aad)


def seal_grs(
    *,
    grs: bytes,
    group_id: bytes,
    state_seq: int,
    member_id: bytes,
    member_pub: bytes,
    eph_private: x25519.X25519PrivateKey | None = None,
) -> bytes:
    """Seal GRS to one member X25519 public key. Returns a 100-byte SealBlob."""
    require_len(grs, 32, "GRS")
    require_len(group_id, constants.HASH16, "GroupID")
    require_len(member_id, constants.HASH16, "MemberID")
    require_len(member_pub, constants.X25519_PUB_SIZE, "MemberPub")

    eph = eph_private or x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    if member_pub == bytes(32):
        raise ValueError("invalid MemberPub")
    peer = x25519.X25519PublicKey.from_public_bytes(member_pub)
    shared = eph.exchange(peer)
    if shared == bytes(32):
        raise ValueError("invalid X25519 shared secret")
    seal_key = hkdf_sha256(
        shared,
        salt=group_id,
        info=constants.LABEL_SEAL + member_id,
    )
    plaintext = grs + group_id + be32(state_seq)
    nonce = sha256(
        constants.LABEL_SEAL + eph_pub + member_id + be32(state_seq),
    ).digest()[:12]
    aad = group_id + be32(state_seq) + member_id
    ct_tag = encrypt_chacha(seal_key, nonce, plaintext, aad)
    blob = eph_pub + ct_tag
    if len(blob) != constants.SEAL_BLOB_SIZE:
        raise RuntimeError(f"unexpected seal blob size {len(blob)}")
    return blob


def unseal_grs(
    *,
    seal_blob: bytes,
    group_id: bytes,
    state_seq: int,
    member_id: bytes,
    member_private: x25519.X25519PrivateKey,
) -> bytes:
    require_len(seal_blob, constants.SEAL_BLOB_SIZE, "SealBlob")
    eph_pub = seal_blob[:32]
    ct_tag = seal_blob[32:]
    eph = x25519.X25519PublicKey.from_public_bytes(eph_pub)
    shared = member_private.exchange(eph)
    if shared == bytes(32):
        raise ValueError("invalid X25519 shared secret")
    seal_key = hkdf_sha256(
        shared,
        salt=group_id,
        info=constants.LABEL_SEAL + member_id,
    )
    nonce = sha256(
        constants.LABEL_SEAL + eph_pub + member_id + be32(state_seq),
    ).digest()[:12]
    aad = group_id + be32(state_seq) + member_id
    plaintext = decrypt_chacha(seal_key, nonce, ct_tag, aad)
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


def message_keys_for(
    *,
    grs: bytes,
    group_id: bytes,
    member_id: bytes,
    state_seq: int,
    epoch: int,
    counter: int,
) -> tuple[bytes, bytes]:
    ck = derive_epoch_key(grs, group_id, state_seq, epoch)
    sk = derive_sender_key(ck, group_id, member_id, state_seq, epoch)
    mk = derive_message_key(sk, group_id, counter)
    nonce = derive_nonce12(group_id, member_id, state_seq, epoch, counter)
    return mk, nonce
