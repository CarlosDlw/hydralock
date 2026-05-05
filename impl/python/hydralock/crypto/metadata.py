import cbor2
from dataclasses import dataclass
from typing import Optional, List, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from hydralock.crypto.aad import build_metadata_aad


@dataclass
class MetadataPlaintext:
    plaintext_size: int
    logical_name: Optional[str]
    mime_type: Optional[str]
    created_at: Optional[int]
    chunk_size: int
    epoch_size: int
    manifest_root: bytes
    payload_mode: int
    padding_bucket: Any
    reserved: bytes


def decrypt_metadata(
    k_control: bytes,
    ciphertext_input: bytes,
    file_uuid: bytes,
    suite_id: int,
    header_hash: bytes,
) -> MetadataPlaintext:
    if len(ciphertext_input) < 12:
        raise ValueError("metadata ciphertext too short")
    nonce = ciphertext_input[:12]
    ct_with_tag = ciphertext_input[12:]
    aad = build_metadata_aad(suite_id, file_uuid, header_hash)
    cipher = AESGCMSIV(k_control)
    plaintext_cbor = cipher.decrypt(nonce, ct_with_tag, aad)
    decoded = cbor2.loads(plaintext_cbor)
    # Array: [plaintext_size, logical_name, mime_type, created_at, chunk_size,
    #         epoch_size, manifest_root, payload_mode, padding_bucket, reserved]
    return MetadataPlaintext(
        plaintext_size=decoded[0],
        logical_name=decoded[1],
        mime_type=decoded[2],
        created_at=decoded[3],
        chunk_size=decoded[4],
        epoch_size=decoded[5],
        manifest_root=bytes(decoded[6]),
        payload_mode=decoded[7],
        padding_bucket=decoded[8],
        reserved=bytes(decoded[9]) if decoded[9] is not None else b"",
    )
