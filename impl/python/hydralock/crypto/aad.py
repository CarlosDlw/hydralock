import struct


def build_chunk_aad(
    suite_id: int,
    file_uuid: bytes,
    epoch_idx: int,
    chunk_idx: int,
    pt_chunk_len: int,
    is_final: bool,
    header_hash: bytes,
) -> bytes:
    # 69 bytes: magic(4) + version(2) + suite_id(2) + file_uuid(16) +
    #           epoch_idx(4) + chunk_idx(4) + pt_chunk_len(4) + is_final(1) + header_hash(32)
    aad = b"HLK1"
    aad += struct.pack(">H", 1)
    aad += struct.pack(">H", suite_id)
    aad += file_uuid
    aad += struct.pack(">I", epoch_idx)
    aad += struct.pack(">I", chunk_idx)
    aad += struct.pack(">I", pt_chunk_len)
    aad += b"\x01" if is_final else b"\x00"
    aad += header_hash
    return aad


def build_metadata_aad(suite_id: int, file_uuid: bytes, header_hash: bytes) -> bytes:
    # 57 bytes: magic(4) + version(2) + suite_id(2) + section_type=0x04(1) + file_uuid(16) + header_hash(32)
    aad = b"HLK1"
    aad += struct.pack(">H", 1)
    aad += struct.pack(">H", suite_id)
    aad += b"\x04"  # SECTION_TYPE_METADATA
    aad += file_uuid
    aad += header_hash
    return aad


def build_wrapper_aad(
    suite_id: int,
    wrapper_idx: int,
    file_uuid: bytes,
    header_hash: bytes,
) -> bytes:
    # 53 bytes: suite_id(2) + section_type=0x03(1) + wrapper_idx(2) + file_uuid(16) + header_hash(32)
    aad = struct.pack(">H", suite_id)
    aad += b"\x03"  # SECTION_TYPE_WRAP
    aad += struct.pack(">H", wrapper_idx)
    aad += file_uuid
    aad += header_hash
    return aad
