import struct

POLICY_SECTION_LEN = 8


class PolicySection:
    __slots__ = ("policy_version", "threshold", "total_shares", "wrapper_count")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    @classmethod
    def parse(cls, data: bytes) -> "PolicySection":
        if len(data) < POLICY_SECTION_LEN:
            raise ValueError(f"policy section too short: {len(data)} < {POLICY_SECTION_LEN}")
        # Layout: policy_version(2) + threshold(1) + total_shares(1) + wrapper_count(2) + reserved(2)
        policy_version, = struct.unpack_from(">H", data, 0)
        threshold = data[2]
        total_shares = data[3]
        wrapper_count, = struct.unpack_from(">H", data, 4)
        reserved = data[6:8]
        if policy_version != 1:
            raise ValueError(f"unsupported policy version: {policy_version}")
        if reserved != b"\x00\x00":
            raise ValueError("policy reserved bytes must be zero")
        return cls(
            policy_version=policy_version,
            threshold=threshold,
            total_shares=total_shares,
            wrapper_count=wrapper_count,
        )
