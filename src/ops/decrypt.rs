use crate::crypto::aad::WrapperAadInput;
use crate::crypto::kdf::{derive_root_key, derive_subkeys};
use crate::crypto::metadata::{decrypt_metadata, MetadataEncryptionError};
use crate::crypto::secret::{Fmk, SecretKey32, fmk_from_bytes};
use crate::crypto::manifest::verify_manifest_root;
use crate::crypto::verify::verify_container_no_decrypt;
use crate::format::footer::{FooterSection, FooterSectionError};
use crate::format::header::{FIXED_HEADER_LEN, FixedHeaderError};
use crate::format::metadata_plaintext::MetadataPlaintext;
use crate::format::payload::{PAYLOAD_HEADER_LEN, PayloadSection, PayloadSectionError};
use crate::format::payload_reader::{PayloadReader, PayloadReaderError};
use crate::format::policy::{POLICY_SECTION_LEN, PolicySection, PolicySectionError};
use crate::format::wraps::{WrapperEntry, WrapsSection, WrapsSectionError};
use crate::wrapper::mlkem768_x25519::{MlKem768X25519RecipientSecretKey, MlKem768X25519Stanza};
use crate::wrapper::passargon2id::PassArgon2idStanza;
use crate::wrapper::x25519::X25519Stanza;

pub enum OpenKeyMaterial {
    Passphrase(Vec<u8>),
    X25519SecretKey([u8; 32]),
    MlKem768X25519SecretKey(MlKem768X25519RecipientSecretKey),
}

pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub metadata: MetadataPlaintext,
}

#[derive(Debug)]
pub enum DecryptError {
    ContainerTooShort,
    HeaderParseFailed(FixedHeaderError),
    PolicyParseFailed(PolicySectionError),
    WrapsParseFailed(WrapsSectionError),
    FooterParseFailed(FooterSectionError),
    PayloadParseFailed(PayloadSectionError),
    MetadataDecrypt(MetadataEncryptionError),
    NoMatchingWrapper,
    VerifyFailed,
    PayloadDecrypt(PayloadReaderError),
    PayloadTruncated,
    LayoutOverflow,
    UnsupportedSuiteId(u16),
    UnsupportedFormatVersion { major: u16, minor: u16 },
    PlaintextSizeLimitExceeded { declared: u64, limit: u64 },
}

impl core::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContainerTooShort => write!(f, "container too short"),
            Self::HeaderParseFailed(e) => write!(f, "header parse error: {e}"),
            Self::PolicyParseFailed(e) => write!(f, "policy parse error: {e:?}"),
            Self::WrapsParseFailed(e) => write!(f, "wraps parse error: {e}"),
            Self::FooterParseFailed(e) => write!(f, "footer parse error: {e:?}"),
            Self::PayloadParseFailed(e) => write!(f, "payload parse error: {e:?}"),
            Self::MetadataDecrypt(e) => write!(f, "metadata decrypt error: {e:?}"),
            Self::NoMatchingWrapper => write!(f, "no wrapper matched the provided key material"),
            Self::VerifyFailed => write!(f, "container integrity verification failed"),
            Self::PayloadDecrypt(e) => write!(f, "payload decrypt error: {e:?}"),
            Self::PayloadTruncated => write!(f, "payload section is truncated"),
            Self::LayoutOverflow => write!(f, "container layout overflow"),
            Self::UnsupportedSuiteId(id) => write!(f, "unsupported suite_id: 0x{id:04x} (expected 0x0001)"),
            Self::UnsupportedFormatVersion { major, minor } => {
                write!(f, "unsupported format version {major}.{minor} (expected 1.0)")
            }
            Self::PlaintextSizeLimitExceeded { declared, limit } => {
                write!(f, "declared plaintext_size {declared} exceeds limit {limit}")
            }
        }
    }
}

impl std::error::Error for DecryptError {}

/// Decrypt a HydraLock v1 container.
///
/// Convention: wrapper_id = file_uuid(16) || user_label (written by ops::encrypt).
/// file_uuid is recovered from wrapper_id[0..16] so no separate argument is needed.
pub fn decrypt(container: &[u8], key_material: &OpenKeyMaterial) -> Result<DecryptResult, DecryptError> {
    if container.len() < FIXED_HEADER_LEN {
        return Err(DecryptError::ContainerTooShort);
    }
    let fh = crate::format::header::FixedHeader::parse(&container[..FIXED_HEADER_LEN])
        .map_err(DecryptError::HeaderParseFailed)?;

    let header_hash: [u8; 32] = *blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes();
    let suite_id = fh.suite_id;

    // Reject unknown suite_id and format versions — no silent fallback.
    const SUPPORTED_SUITE_ID: u16 = 0x0001;
    const SUPPORTED_FMT_MAJOR: u16 = 1;
    const SUPPORTED_FMT_MINOR: u16 = 0;
    if suite_id != SUPPORTED_SUITE_ID {
        return Err(DecryptError::UnsupportedSuiteId(suite_id));
    }
    if fh.format_version_major != SUPPORTED_FMT_MAJOR || fh.format_version_minor != SUPPORTED_FMT_MINOR {
        return Err(DecryptError::UnsupportedFormatVersion {
            major: fh.format_version_major,
            minor: fh.format_version_minor,
        });
    }

    let policy_start = FIXED_HEADER_LEN;
    let policy_end = policy_start.checked_add(fh.policy_len as usize).ok_or(DecryptError::LayoutOverflow)?;
    let wraps_start = policy_end;
    let wraps_end = wraps_start.checked_add(fh.wraps_len as usize).ok_or(DecryptError::LayoutOverflow)?;
    let metadata_start = wraps_end;
    let metadata_end = metadata_start.checked_add(fh.metadata_len as usize).ok_or(DecryptError::LayoutOverflow)?;
    let payload_start = fh.payload_offset as usize;

    if container.len() < metadata_end || container.len() < payload_start {
        return Err(DecryptError::ContainerTooShort);
    }

    if policy_end.saturating_sub(policy_start) < POLICY_SECTION_LEN {
        return Err(DecryptError::ContainerTooShort);
    }
    let _policy = PolicySection::parse(&container[policy_start..policy_end])
        .map_err(DecryptError::PolicyParseFailed)?;
    let wraps = WrapsSection::parse(&container[wraps_start..wraps_end])
        .map_err(DecryptError::WrapsParseFailed)?;
    let encrypted_metadata = &container[metadata_start..metadata_end];

    if container.get(payload_start..).map_or(true, |b| b.len() < PAYLOAD_HEADER_LEN) {
        return Err(DecryptError::PayloadTruncated);
    }

    let payload_end = scan_payload_end(container, payload_start)?;
    let footer_bytes = container.get(payload_end..).ok_or(DecryptError::ContainerTooShort)?;
    let footer = FooterSection::parse(footer_bytes).map_err(DecryptError::FooterParseFailed)?;

    let file_uuid = extract_file_uuid(&wraps.wrappers)?;
    let fmk = try_unwrap_fmk(&wraps.wrappers, key_material, suite_id, &header_hash, &file_uuid)?;

    let root_key = derive_root_key(&fmk, &file_uuid);
    let subkeys = derive_subkeys(&root_key);

    let pre_footer = &container[..payload_end];
    let k_manifest = SecretKey32::from_bytes(*subkeys.k_manifest.expose());
    verify_container_no_decrypt(&k_manifest, pre_footer, footer_bytes)
        .map_err(|_| DecryptError::VerifyFailed)?;

    let k_control = SecretKey32::from_bytes(*subkeys.k_control.expose());
    let metadata = decrypt_metadata(&k_control, encrypted_metadata, &file_uuid, suite_id, &header_hash)
        .map_err(DecryptError::MetadataDecrypt)?;

    let payload_section = PayloadSection::parse(&container[payload_start..payload_end])
        .map_err(DecryptError::PayloadParseFailed)?;

    let k_payload_master = SecretKey32::from_bytes(*subkeys.k_payload_master.expose());
    let mut reader = PayloadReader::new(k_payload_master, file_uuid, suite_id, header_hash, metadata.epoch_size);

    // Guard against DoS via inflated plaintext_size before any allocation.
    const MAX_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB
    if metadata.plaintext_size > MAX_PLAINTEXT_BYTES {
        return Err(DecryptError::PlaintextSizeLimitExceeded {
            declared: metadata.plaintext_size,
            limit: MAX_PLAINTEXT_BYTES,
        });
    }

    let mut plaintext = Vec::with_capacity(metadata.plaintext_size as usize);
    let mut chunk_cts: Vec<Vec<u8>> = Vec::with_capacity(payload_section.chunks.len());
    for chunk in &payload_section.chunks {
        let mut ct = chunk.ciphertext.clone();
        ct.extend_from_slice(&chunk.tag);
        let pt = reader.read_chunk(&ct, chunk.is_final()).map_err(DecryptError::PayloadDecrypt)?;
        plaintext.extend_from_slice(&pt);
        chunk_cts.push(ct);
    }
    plaintext.truncate(metadata.plaintext_size as usize);

    // Verify manifest root against actual chunk ciphertexts (defense-in-depth).
    let expected_root: [u8; 32] = footer.manifest_root.as_slice()
        .try_into()
        .map_err(|_| DecryptError::VerifyFailed)?;
    let manifest_ok = verify_manifest_root(&k_manifest, &chunk_cts, &expected_root)
        .map_err(|_| DecryptError::VerifyFailed)?;
    if !manifest_ok {
        return Err(DecryptError::VerifyFailed);
    }

    Ok(DecryptResult { plaintext, metadata })
}

pub fn extract_file_uuid(wrappers: &[WrapperEntry]) -> Result<[u8; 16], DecryptError> {
    let entry = wrappers.first().ok_or(DecryptError::NoMatchingWrapper)?;
    if entry.wrapper_id.len() < 16 {
        return Err(DecryptError::NoMatchingWrapper);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&entry.wrapper_id[..16]);
    Ok(uuid)
}

pub fn try_unwrap_fmk(
    wrappers: &[WrapperEntry],
    key_material: &OpenKeyMaterial,
    suite_id: u16,
    header_hash: &[u8; 32],
    file_uuid: &[u8; 16],
) -> Result<Fmk, DecryptError> {
    for (i, entry) in wrappers.iter().enumerate() {
        let aad = WrapperAadInput {
            suite_id,
            wrapper_index: i as u16,
            file_uuid: *file_uuid,
            header_hash: *header_hash,
        }
        .encode();

        let result: Option<Fmk> = match key_material {
            OpenKeyMaterial::Passphrase(pass) => {
                if entry.wrapper_type != crate::wrapper::passargon2id::WRAPPER_TYPE_PASS_ARGON2ID {
                    None
                } else {
                    PassArgon2idStanza::parse(&entry.stanza)
                        .ok()
                        .and_then(|s| s.open(pass, &aad).ok())
                        .map(|k| fmk_from_bytes(*k.expose()))
                }
            }
            OpenKeyMaterial::X25519SecretKey(sk_bytes) => {
                if entry.wrapper_type != crate::wrapper::x25519::WRAPPER_TYPE_X25519 {
                    None
                } else {
                    X25519Stanza::parse(&entry.stanza)
                        .ok()
                        .and_then(|s| s.open(sk_bytes, &aad).ok())
                        .map(|k| fmk_from_bytes(*k.expose()))
                }
            }
            OpenKeyMaterial::MlKem768X25519SecretKey(sk) => {
                if entry.wrapper_type != crate::wrapper::mlkem768_x25519::WRAPPER_TYPE_MLKEM768_X25519 {
                    None
                } else {
                    MlKem768X25519Stanza::parse(&entry.stanza)
                        .ok()
                        .and_then(|s| s.open(sk, &aad).ok())
                        .map(|k| fmk_from_bytes(*k.expose()))
                }
            }
        };

        if let Some(fmk) = result {
            return Ok(fmk);
        }
    }
    Err(DecryptError::NoMatchingWrapper)
}

pub fn scan_payload_end(container: &[u8], payload_offset: usize) -> Result<usize, DecryptError> {
    let payload_bytes = container.get(payload_offset..).ok_or(DecryptError::ContainerTooShort)?;

    if payload_bytes.len() < PAYLOAD_HEADER_LEN {
        return Err(DecryptError::PayloadTruncated);
    }

    let tag_size = u32::from_be_bytes([
        payload_bytes[8], payload_bytes[9], payload_bytes[10], payload_bytes[11],
    ]) as usize;

    let mut offset = PAYLOAD_HEADER_LEN;
    loop {
        if offset + 8 > payload_bytes.len() {
            return Err(DecryptError::PayloadTruncated);
        }
        let ciphertext_len = u32::from_be_bytes([
            payload_bytes[offset], payload_bytes[offset + 1],
            payload_bytes[offset + 2], payload_bytes[offset + 3],
        ]) as usize;
        let chunk_flags = u16::from_be_bytes([payload_bytes[offset + 4], payload_bytes[offset + 5]]);
        let is_final = chunk_flags & 0x0001 != 0;
        offset = offset
            .checked_add(8)
            .and_then(|o| o.checked_add(ciphertext_len))
            .and_then(|o| o.checked_add(tag_size))
            .ok_or(DecryptError::LayoutOverflow)?;
        if is_final {
            break;
        }
        if offset >= payload_bytes.len() {
            return Err(DecryptError::PayloadTruncated);
        }
    }
    payload_offset.checked_add(offset).ok_or(DecryptError::LayoutOverflow)
}
