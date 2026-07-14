from __future__ import annotations

from . import constants


def state_object_size(member_count: int) -> int:
    if member_count < 0:
        raise ValueError("member_count must be >= 0")
    if member_count > constants.MAX_MEMBERS:
        raise ValueError(
            f"v1 allows at most {constants.MAX_MEMBERS} members, got {member_count}",
        )
    return constants.STATE_FIXED_WITH_SIG + constants.MEMBER_ENTRY_SIZE * member_count


def seal_blob_size() -> int:
    return constants.SEAL_BLOB_SIZE


def keydist_size(recipient_count: int) -> int:
    if recipient_count < 0:
        raise ValueError("recipient_count must be >= 0")
    if recipient_count > constants.MAX_MEMBERS:
        raise ValueError(
            f"v1 allows at most {constants.MAX_MEMBERS} recipients, got {recipient_count}",
        )
    return constants.KEYDIST_FIXED + recipient_count * (
        constants.HASH16 + constants.SEAL_BLOB_SIZE
    )


def ordinary_header_size(fmt: int = constants.MSG_FORMAT_COUNTER) -> int:
    if fmt == constants.MSG_FORMAT_COUNTER:
        return constants.MSG_HEADER_COUNTER
    if fmt == constants.MSG_FORMAT_XCHACHA:
        return constants.MSG_HEADER_XCHACHA
    raise ValueError(f"unknown message format {fmt}")


def message_overhead(
    plaintext_len: int,
    *,
    fmt: int = constants.MSG_FORMAT_COUNTER,
    with_signature: bool = False,
) -> int:
    header = ordinary_header_size(fmt)
    sig = constants.ED25519_SIG_SIZE if with_signature else 0
    return header + constants.AEAD_TAG_SIZE + plaintext_len + sig


def draft_claims() -> dict[str, int | float]:
    """Numeric size claims from the draft, for automated checking."""
    return {
        "state_fixed_with_sig": constants.STATE_FIXED_WITH_SIG,
        "member_entry": constants.MEMBER_ENTRY_SIZE,
        "state_n16": state_object_size(16),
        "seal_blob": constants.SEAL_BLOB_SIZE,
        "keydist_fixed": constants.KEYDIST_FIXED,
        "keydist_per_recipient": constants.HASH16 + constants.SEAL_BLOB_SIZE,
        "keydist_n15": keydist_size(15),
        "msg_header_counter": constants.MSG_HEADER_COUNTER,
        "msg_header_xchacha": constants.MSG_HEADER_XCHACHA,
        "aead_tag": constants.AEAD_TAG_SIZE,
    }
