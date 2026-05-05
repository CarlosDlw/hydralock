import struct

MAGIC = b"HLK1"
FIXED_HEADER_LEN = 70
RESERVED_LEN = 32


class FixedHeader:
    __slots__ = (
        "format_version_major",
        "format_version_minor",
        "suite_id",
        "flags",
        "header_len",
        "policy_len",
        "wraps_len",
        "metadata_len",
        "payload_offset",
    )

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    @classmethod
    def parse(cls, data: bytes) -> "FixedHeader":
        if len(data) != FIXED_HEADER_LEN:
            raise ValueError(f"fixed header must be {FIXED_HEADER_LEN} bytes, got {len(data)}")
        magic = data[0:4]
        if magic != MAGIC:
            raise ValueError(f"invalid magic: {magic!r}")
        # Offset 4: format_version_major u16, format_version_minor u16
        fmt_major, fmt_minor = struct.unpack_from(">HH", data, 4)
        suite_id, = struct.unpack_from(">H", data, 8)
        flags, = struct.unpack_from(">I", data, 10)
        header_len, = struct.unpack_from(">I", data, 14)
        policy_len, = struct.unpack_from(">I", data, 18)
        wraps_len, = struct.unpack_from(">I", data, 22)
        metadata_len, = struct.unpack_from(">I", data, 26)
        payload_offset, = struct.unpack_from(">Q", data, 30)
        reserved = data[38:70]
        if any(reserved):
            raise ValueError("reserved bytes must be zero")
        expected_payload_offset = header_len + policy_len + wraps_len + metadata_len
        if payload_offset != expected_payload_offset:
            raise ValueError(
                f"invalid payload_offset: expected {expected_payload_offset}, got {payload_offset}"
            )
        return cls(
            format_version_major=fmt_major,
            format_version_minor=fmt_minor,
            suite_id=suite_id,
            flags=flags,
            header_len=header_len,
            policy_len=policy_len,
            wraps_len=wraps_len,
            metadata_len=metadata_len,
            payload_offset=payload_offset,
        )
