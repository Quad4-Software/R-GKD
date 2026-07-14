from __future__ import annotations

import struct
from typing import Final

_BE32: Final = struct.Struct(">I")
_BE16: Final = struct.Struct(">H")
_BE64: Final = struct.Struct(">Q")


def be32(value: int) -> bytes:
    return _BE32.pack(value & 0xFFFFFFFF)


def be16(value: int) -> bytes:
    return _BE16.pack(value & 0xFFFF)


def be64(value: int) -> bytes:
    return _BE64.pack(value & 0xFFFFFFFFFFFFFFFF)


def require_len(data: bytes, expected: int, name: str) -> None:
    if len(data) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(data)}")
