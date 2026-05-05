import struct
from dataclasses import dataclass
from typing import Optional

import blake3
from Crypto.Cipher import ChaCha20_Poly1305 as _ChaCha20Poly1305

from hydralock.format.header import FixedHeader, FIXED_HEADER_LEN
from hydralock.format.policy import PolicySection
from hydralock.format.wraps import WrapsSection, WRAPPER_TYPE_PASS_ARGON2ID, WRAPPER_TYPE_X25519, WRAPPER_TYPE_MLKEM768_X25519
from hydralock.format.payload import PayloadSection
from hydralock.format.footer import FooterSection

from hydralock.crypto.kdf import derive_root_key, derive_subkeys, derive_epoch_key, derive_chunk_key, derive_chunk_nonce
from hydralock.crypto.aad import build_chunk_aad, build_wrapper_aad
from hydralock.crypto.verify import verify_footer_auth_tag
from hydralock.crypto.metadata import decrypt_metadata

from hydralock.wrapper import passargon2id, x25519, mlkem768_x25519


@dataclass
class PassKeyMaterial:
    passphrase: bytes


@dataclass
class X25519KeyMaterial:
    secret_key: bytes  # 32 bytes


@dataclass
class MlKem768X25519KeyMaterial:
    x25519_sk: bytes       # 32 bytes
    mlkem_dk_seed: bytes   # 64 bytes


@dataclass
class DecryptResult:
    plaintext: bytes
    logical_name: Optional[str]
    plaintext_size: int
    format_version_major: int
    format_version_minor: int
    suite_id: int
    header_hash: bytes
    threshold: int
    total_shares: int
    wrapper_count: int


def _scan_payload_end(container: bytes, payload_offset: int) -> int:
    payload_bytes = container[payload_offset:]
    if len(payload_bytes) < 16:
        raise ValueError("payload section too short to scan")
    tag_size = struct.unpack_from(">I", payload_bytes, 8)[0]
    offset = 16
    while True:
        if offset + 8 > len(payload_bytes):
            raise ValueError("truncated chunk header during scan")
        ciphertext_len = struct.unpack_from(">I", payload_bytes, offset)[0]
        chunk_flags = struct.unpack_from(">H", payload_bytes, offset + 4)[0]
        is_final = bool(chunk_flags & 0x0001)
        offset += 8 + ciphertext_len + tag_size
        if is_final:
            break
        if offset >= len(payload_bytes):
            raise ValueError("no final chunk found during scan")
    return payload_offset + offset


def decrypt(container: bytes, key_material) -> DecryptResult:
    if len(container) < FIXED_HEADER_LEN:
        raise ValueError("container too short")

    fixed_header = FixedHeader.parse(container[:FIXED_HEADER_LEN])
    header_hash = blake3.blake3(container[:FIXED_HEADER_LEN]).digest()
    suite_id = fixed_header.suite_id

    # Section offsets
    policy_start = FIXED_HEADER_LEN
    policy_end = policy_start + fixed_header.policy_len
    wraps_start = policy_end
    wraps_end = wraps_start + fixed_header.wraps_len
    metadata_start = wraps_end
    metadata_end = metadata_start + fixed_header.metadata_len
    payload_start = fixed_header.payload_offset

    if len(container) < metadata_end or len(container) < payload_start:
        raise ValueError("container too short for declared section lengths")

    _policy = PolicySection.parse(container[policy_start:policy_end])
    wraps = WrapsSection.parse(container[wraps_start:wraps_end])
    encrypted_metadata = container[metadata_start:metadata_end]

    payload_end = _scan_payload_end(container, payload_start)
    footer_bytes = container[payload_end:]
    _footer = FooterSection.parse(footer_bytes)

    file_uuid = _extract_file_uuid(wraps)
    fmk = _try_unwrap_fmk(wraps, key_material, suite_id, header_hash, file_uuid)

    root_key = derive_root_key(fmk, file_uuid)
    subkeys = derive_subkeys(root_key)

    pre_footer = container[:payload_end]
    if not verify_footer_auth_tag(subkeys["k_manifest"], pre_footer, _footer.auth_tag):
        raise ValueError("footer auth tag verification failed")

    metadata = decrypt_metadata(
        subkeys["k_control"],
        encrypted_metadata,
        file_uuid,
        suite_id,
        header_hash,
    )

    payload_section = PayloadSection.parse(container[payload_start:payload_end])
    k_payload_master = subkeys["k_payload_master"]

    epoch_idx = 0
    chunk_idx_in_epoch = 0
    total_chunk_idx = 0
    epoch_size = metadata.epoch_size
    k_epoch = derive_epoch_key(k_payload_master, 0)
    plaintext_parts = []

    for i, chunk in enumerate(payload_section.chunks):
        is_final = chunk.is_final()
        pt_chunk_len = len(chunk.ciphertext)

        k_chunk = derive_chunk_key(k_epoch, chunk_idx_in_epoch)
        n_chunk = derive_chunk_nonce(k_epoch, chunk_idx_in_epoch)

        aad = build_chunk_aad(
            suite_id,
            file_uuid,
            epoch_idx,
            chunk_idx_in_epoch,
            pt_chunk_len,
            is_final,
            header_hash,
        )
        cipher = _ChaCha20Poly1305.new(key=k_chunk, nonce=n_chunk)
        cipher.update(aad)
        # ciphertext is ct without tag; tag is separate
        ciphertext_only = chunk.ciphertext
        tag = chunk.tag
        plaintext_part = cipher.decrypt_and_verify(ciphertext_only, tag)
        plaintext_parts.append(plaintext_part)

        # Advance position
        chunk_idx_in_epoch += 1
        total_chunk_idx += 1
        if chunk_idx_in_epoch >= epoch_size:
            epoch_idx += 1
            chunk_idx_in_epoch = 0
            if not is_final:
                k_epoch = derive_epoch_key(k_payload_master, epoch_idx)

    plaintext = b"".join(plaintext_parts)
    plaintext = plaintext[:metadata.plaintext_size]

    return DecryptResult(
        plaintext=plaintext,
        logical_name=metadata.logical_name,
        plaintext_size=metadata.plaintext_size,
        format_version_major=fixed_header.format_version_major,
        format_version_minor=fixed_header.format_version_minor,
        suite_id=suite_id,
        header_hash=header_hash,
        threshold=_policy.threshold,
        total_shares=_policy.total_shares,
        wrapper_count=_policy.wrapper_count,
    )


def _extract_file_uuid(wraps: WrapsSection) -> bytes:
    if not wraps.wrappers:
        raise ValueError("no wrappers found")
    wid = wraps.wrappers[0].wrapper_id
    if len(wid) < 16:
        raise ValueError("wrapper_id too short to extract file_uuid")
    return wid[:16]


def _try_unwrap_fmk(wraps: WrapsSection, key_material, suite_id: int, header_hash: bytes, file_uuid: bytes) -> bytes:
    for i, entry in enumerate(wraps.wrappers):
        aad = build_wrapper_aad(suite_id, i, file_uuid, header_hash)
        try:
            if entry.wrapper_type == WRAPPER_TYPE_PASS_ARGON2ID:
                if isinstance(key_material, PassKeyMaterial):
                    return passargon2id.unwrap(entry.stanza, key_material.passphrase, aad)

            elif entry.wrapper_type == WRAPPER_TYPE_X25519:
                if isinstance(key_material, X25519KeyMaterial):
                    return x25519.unwrap(entry.stanza, key_material.secret_key, aad)

            elif entry.wrapper_type == WRAPPER_TYPE_MLKEM768_X25519:
                if isinstance(key_material, MlKem768X25519KeyMaterial):
                    return mlkem768_x25519.unwrap(
                        entry.stanza,
                        key_material.x25519_sk,
                        key_material.mlkem_dk_seed,
                        aad,
                    )
        except Exception:
            continue

    raise ValueError("no matching wrapper could decrypt the FMK")
