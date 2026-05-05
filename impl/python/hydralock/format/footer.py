import struct
from dataclasses import dataclass

FOOTER_HEADER_LEN = 12


@dataclass
class FooterSection:
    footer_version: int
    flags: int
    manifest_root: bytes
    auth_tag: bytes

    @classmethod
    def parse(cls, data: bytes) -> "FooterSection":
        if len(data) < FOOTER_HEADER_LEN:
            raise ValueError(f"footer section too short: {len(data)}")
        footer_version, flags = struct.unpack_from(">HH", data, 0)
        if footer_version != 1:
            raise ValueError(f"unsupported footer version: {footer_version}")
        manifest_root_len, auth_tag_len = struct.unpack_from(">HH", data, 4)
        reserved = data[8:12]
        if reserved != b"\x00\x00\x00\x00":
            raise ValueError("footer reserved bytes must be zero")
        if manifest_root_len == 0:
            raise ValueError("manifest_root must not be empty")
        if auth_tag_len == 0:
            raise ValueError("auth_tag must not be empty")

        offset = FOOTER_HEADER_LEN
        end_mr = offset + manifest_root_len
        if end_mr > len(data):
            raise ValueError("truncated manifest_root")
        manifest_root = data[offset:end_mr]

        end_at = end_mr + auth_tag_len
        if end_at > len(data):
            raise ValueError("truncated auth_tag")
        auth_tag = data[end_mr:end_at]

        if end_at != len(data):
            raise ValueError(
                f"footer length mismatch: declared {FOOTER_HEADER_LEN + manifest_root_len + auth_tag_len}, actual {len(data)}"
            )

        return cls(
            footer_version=footer_version,
            flags=flags,
            manifest_root=manifest_root,
            auth_tag=auth_tag,
        )
