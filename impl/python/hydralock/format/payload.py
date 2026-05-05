import struct
from dataclasses import dataclass, field
from typing import List

PAYLOAD_HEADER_LEN = 16
CHUNK_ENTRY_HEADER_LEN = 8
CHUNK_FLAG_FINAL = 0x0001


@dataclass
class ChunkEntry:
    flags: int
    ciphertext: bytes  # encrypted bytes, WITHOUT tag
    tag: bytes         # auth tag (tag_size bytes)

    def is_final(self) -> bool:
        return bool(self.flags & CHUNK_FLAG_FINAL)

    def ciphertext_with_tag(self) -> bytes:
        return self.ciphertext + self.tag


@dataclass
class PayloadSection:
    payload_version: int
    flags: int
    chunk_size: int
    tag_size: int
    chunks: List[ChunkEntry]

    @classmethod
    def parse(cls, data: bytes) -> "PayloadSection":
        if len(data) < PAYLOAD_HEADER_LEN:
            raise ValueError(f"payload section too short: {len(data)}")
        payload_version, flags = struct.unpack_from(">HH", data, 0)
        if payload_version != 1:
            raise ValueError(f"unsupported payload version: {payload_version}")
        chunk_size, tag_size = struct.unpack_from(">II", data, 4)
        reserved = data[12:16]
        if reserved != b"\x00\x00\x00\x00":
            raise ValueError("payload reserved bytes must be zero")
        if chunk_size == 0:
            raise ValueError("chunk_size must be > 0")
        if tag_size == 0:
            raise ValueError("tag_size must be > 0")

        offset = PAYLOAD_HEADER_LEN
        chunks = []
        tag_size_int = int(tag_size)

        while offset < len(data):
            idx = len(chunks)
            if offset + CHUNK_ENTRY_HEADER_LEN > len(data):
                raise ValueError(f"truncated chunk header at index {idx}")
            ciphertext_len = struct.unpack_from(">I", data, offset)[0]
            chunk_flags = struct.unpack_from(">H", data, offset + 4)[0]
            chunk_reserved = data[offset + 6 : offset + 8]
            offset += CHUNK_ENTRY_HEADER_LEN

            if chunk_reserved != b"\x00\x00":
                raise ValueError(f"non-zero reserved in chunk header at index {idx}")
            if ciphertext_len == 0:
                raise ValueError(f"ciphertext_len must not be zero at index {idx}")

            ct_end = offset + ciphertext_len
            if ct_end > len(data):
                raise ValueError(f"truncated ciphertext at chunk {idx}")
            ciphertext = data[offset:ct_end]
            offset = ct_end

            tag_end = offset + tag_size_int
            if tag_end > len(data):
                raise ValueError(f"truncated tag at chunk {idx}")
            tag = data[offset:tag_end]
            offset = tag_end

            chunks.append(ChunkEntry(flags=chunk_flags, ciphertext=ciphertext, tag=tag))

        if not chunks:
            raise ValueError("payload has no chunks")

        final_indices = [i for i, c in enumerate(chunks) if c.is_final()]
        if not final_indices:
            raise ValueError("no chunk is marked as final")
        if final_indices[0] != len(chunks) - 1:
            raise ValueError("final flag must be on the last chunk")

        return cls(
            payload_version=payload_version,
            flags=flags,
            chunk_size=chunk_size,
            tag_size=tag_size,
            chunks=chunks,
        )

