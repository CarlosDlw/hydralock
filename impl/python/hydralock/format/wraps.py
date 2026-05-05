import struct
from dataclasses import dataclass, field
from typing import List

WRAPS_HEADER_LEN = 4
WRAPPER_ENTRY_HEADER_LEN = 8

WRAPPER_TYPE_PASS_ARGON2ID = 0x0001
WRAPPER_TYPE_X25519 = 0x0002
WRAPPER_TYPE_MLKEM768_X25519 = 0x0003
WRAPPER_TYPE_THRESHOLD = 0x0004


@dataclass
class WrapperEntry:
    wrapper_type: int
    wrapper_flags: int
    wrapper_id: bytes
    stanza: bytes


@dataclass
class WrapsSection:
    wraps_version: int
    wrappers: List[WrapperEntry]

    @classmethod
    def parse(cls, data: bytes) -> "WrapsSection":
        if len(data) < WRAPS_HEADER_LEN:
            raise ValueError(f"wraps section too short: {len(data)}")
        wraps_version, wrapper_count = struct.unpack_from(">HH", data, 0)
        if wraps_version != 1:
            raise ValueError(f"unsupported wraps version: {wraps_version}")

        offset = WRAPS_HEADER_LEN
        wrappers = []
        seen_ids = set()

        for idx in range(wrapper_count):
            if offset + WRAPPER_ENTRY_HEADER_LEN > len(data):
                raise ValueError(f"truncated wrapper entry header at index {idx}")
            wrapper_type, wrapper_flags, wrapper_id_len, stanza_len = struct.unpack_from(
                ">HHHH", data, offset
            )
            offset += WRAPPER_ENTRY_HEADER_LEN

            if wrapper_id_len == 0:
                raise ValueError(f"wrapper_id must not be empty at index {idx}")

            if offset + wrapper_id_len > len(data):
                raise ValueError(f"truncated wrapper_id at index {idx}")
            wrapper_id = data[offset : offset + wrapper_id_len]
            offset += wrapper_id_len

            if offset + stanza_len > len(data):
                raise ValueError(f"truncated stanza at index {idx}")
            stanza = data[offset : offset + stanza_len]
            offset += stanza_len

            if wrapper_id in seen_ids:
                raise ValueError("duplicate wrapper_id")
            seen_ids.add(wrapper_id)

            wrappers.append(WrapperEntry(wrapper_type, wrapper_flags, wrapper_id, stanza))

        return cls(wraps_version=wraps_version, wrappers=wrappers)
