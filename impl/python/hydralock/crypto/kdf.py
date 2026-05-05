import struct

import blake3
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _blake3_keyed(key: bytes, data: bytes) -> bytes:
    return blake3.blake3(data, key=key).digest()


def derive_root_key(fmk: bytes, file_uuid: bytes) -> bytes:
    hkdf = HKDF(algorithm=SHA512(), length=32, salt=file_uuid, info=b"hydralock:v1:root")
    return hkdf.derive(fmk)


def derive_subkeys(root_key: bytes) -> dict:
    return {
        "k_control":        _blake3_keyed(root_key, b"hydralock:v1:control"),
        "k_manifest":       _blake3_keyed(root_key, b"hydralock:v1:manifest"),
        "k_payload_master": _blake3_keyed(root_key, b"hydralock:v1:payload-master"),
        "k_padding":        _blake3_keyed(root_key, b"hydralock:v1:padding"),
        "k_rewrap":         _blake3_keyed(root_key, b"hydralock:v1:rewrap"),
    }


def derive_epoch_key(k_payload_master: bytes, epoch_idx: int) -> bytes:
    # Matches payload_reader.rs: uses derive_chunk_key (LABEL_CHUNK_KEY) at the epoch level
    data = b"hydralock:v1:chunk-key" + struct.pack(">I", epoch_idx)
    return _blake3_keyed(k_payload_master, data)


def derive_chunk_key(k_epoch: bytes, chunk_idx_in_epoch: int) -> bytes:
    data = b"hydralock:v1:chunk-key" + struct.pack(">I", chunk_idx_in_epoch)
    return _blake3_keyed(k_epoch, data)


def derive_chunk_nonce(k_epoch: bytes, chunk_idx_in_epoch: int) -> bytes:
    data = b"hydralock:v1:chunk-nonce" + struct.pack(">I", chunk_idx_in_epoch)
    h = blake3.blake3(data, key=k_epoch)
    return h.digest(length=24)


def derive_metadata_nonce(plaintext_cbor: bytes) -> bytes:
    h = blake3.blake3(b"hydralock:v1:metadata-nonce" + plaintext_cbor)
    return h.digest(length=12)
