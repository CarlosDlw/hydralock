use rand::RngCore;

use crate::crypto::aad::WrapperAadInput;
use crate::crypto::kdf::{derive_root_key, derive_subkeys};
use crate::crypto::manifest::ManifestBuilder;
use crate::crypto::manifest::ManifestError;
use crate::crypto::metadata::MetadataEncryptionError;
use crate::crypto::metadata::encrypt_metadata;
use crate::crypto::password::{Argon2Params, Argon2Profile};
use crate::crypto::secret::{Fmk, SecretKey32, fmk_expose, fmk_from_bytes};
use crate::crypto::verify::build_footer;
use crate::format::footer::FooterSectionError;
use crate::format::header::{FIXED_HEADER_LEN, FixedHeader, FixedHeaderError};
use crate::format::metadata_plaintext::{MetadataError, MetadataPlaintext, PaddingBucket};
use crate::format::payload::{CHUNK_FLAG_FINAL, ChunkEntry, PayloadSection, PayloadSectionError};
use crate::format::payload_writer::{PayloadWriter, PayloadWriterError};
use crate::format::policy::{POLICY_SECTION_LEN, PolicySection, PolicySectionError};
use crate::format::wraps::{
    WRAPPER_ENTRY_HEADER_LEN, WRAPS_HEADER_LEN, WrapperEntry, WrapsSection, WrapsSectionError,
};
use crate::wrapper::mlkem768_x25519::{
    MLKEM768_X25519_STANZA_LEN, MlKem768X25519RecipientPublicKey, MlKem768X25519Stanza,
};
use crate::wrapper::passargon2id::{PASS_ARGON2ID_STANZA_LEN, PassArgon2idStanza};
use crate::wrapper::x25519::{X25519_STANZA_LEN, X25519Stanza};

pub const DEFAULT_CHUNK_SIZE: u32 = 65_536;
pub const DEFAULT_EPOCH_SIZE: u32 = 256;
pub const SUITE_ID: u16 = 0x0001;
pub const FORMAT_VERSION_MAJOR: u16 = 1;
pub const FORMAT_VERSION_MINOR: u16 = 0;
const POLY1305_TAG_SIZE: usize = 16;

/// Specification for a single wrapper (how to protect the FMK).
pub enum WrapperSpec {
    /// Protect FMK with Argon2id-derived KEK.
    PassArgon2id {
        passphrase: Vec<u8>,
        profile: Argon2Profile,
        wrapper_id: Vec<u8>,
    },
    /// Protect FMK with ephemeral X25519 ECDH.
    X25519 {
        recipient_pk: [u8; 32],
        wrapper_id: Vec<u8>,
    },
    /// Protect FMK with ML-KEM-768 + X25519 hybrid.
    MlKem768X25519 {
        recipient_pk: Box<MlKem768X25519RecipientPublicKey>,
        wrapper_id: Vec<u8>,
    },
}

impl WrapperSpec {
    fn stanza_len(&self) -> usize {
        match self {
            WrapperSpec::PassArgon2id { .. } => PASS_ARGON2ID_STANZA_LEN,
            WrapperSpec::X25519 { .. } => X25519_STANZA_LEN,
            WrapperSpec::MlKem768X25519 { .. } => MLKEM768_X25519_STANZA_LEN,
        }
    }

    /// The user-provided label suffix. Wire wrapper_id = file_uuid(16) || label.
    fn label(&self) -> &[u8] {
        match self {
            WrapperSpec::PassArgon2id { wrapper_id, .. } => wrapper_id,
            WrapperSpec::X25519 { wrapper_id, .. } => wrapper_id,
            WrapperSpec::MlKem768X25519 { wrapper_id, .. } => wrapper_id,
        }
    }

    fn wrapper_type(&self) -> u16 {
        match self {
            WrapperSpec::PassArgon2id { .. } => {
                crate::wrapper::passargon2id::WRAPPER_TYPE_PASS_ARGON2ID
            }
            WrapperSpec::X25519 { .. } => crate::wrapper::x25519::WRAPPER_TYPE_X25519,
            WrapperSpec::MlKem768X25519 { .. } => {
                crate::wrapper::mlkem768_x25519::WRAPPER_TYPE_MLKEM768_X25519
            }
        }
    }

    /// Wire wrapper_id = file_uuid(16) || label.
    /// Label may be empty; the file_uuid prefix ensures wrapper_id is always non-empty.
    fn wire_id(&self, file_uuid: &[u8; 16]) -> Vec<u8> {
        let mut id = Vec::with_capacity(16 + self.label().len());
        id.extend_from_slice(file_uuid);
        id.extend_from_slice(self.label());
        id
    }
}

/// Input parameters for the encrypt operation.
pub struct EncryptInput<'a> {
    pub plaintext: &'a [u8],
    pub logical_name: Option<String>,
    pub mime_type: Option<String>,
    pub created_at: Option<i64>,
    pub chunk_size: u32,
    pub epoch_size: u32,
    pub padding: PaddingBucket,
}

impl<'a> Default for EncryptInput<'a> {
    fn default() -> Self {
        Self {
            plaintext: &[],
            logical_name: None,
            mime_type: None,
            created_at: None,
            chunk_size: DEFAULT_CHUNK_SIZE,
            epoch_size: DEFAULT_EPOCH_SIZE,
            padding: PaddingBucket::None,
        }
    }
}

#[derive(Debug)]
pub enum EncryptError {
    EmptyWrappers,
    WrapperIdEmpty,
    WrapperIdTooLong,
    PayloadWrite(PayloadWriterError),
    ManifestBuild(ManifestError),
    MetadataEncode(MetadataError),
    MetadataEncrypt(MetadataEncryptionError),
    MetadataSizeMismatch { expected: usize, actual: usize },
    PolicyEncode(PolicySectionError),
    WrapsEncode(WrapsSectionError),
    PayloadEncode(PayloadSectionError),
    FooterEncode(FooterSectionError),
    HeaderEncode(FixedHeaderError),
    WrapperSealFailed { index: usize, reason: String },
    LengthOverflow,
}

impl core::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyWrappers => write!(f, "at least one wrapper is required"),
            Self::WrapperIdEmpty => write!(f, "wrapper_id must not be empty"),
            Self::WrapperIdTooLong => write!(f, "wrapper_id exceeds u16::MAX bytes"),
            Self::PayloadWrite(e) => write!(f, "payload write error: {e:?}"),
            Self::ManifestBuild(e) => write!(f, "manifest build error: {e:?}"),
            Self::MetadataEncode(e) => write!(f, "metadata encode error: {e:?}"),
            Self::MetadataEncrypt(e) => write!(f, "metadata encrypt error: {e:?}"),
            Self::MetadataSizeMismatch { expected, actual } => {
                write!(
                    f,
                    "metadata size mismatch: expected {expected}, got {actual}"
                )
            }
            Self::PolicyEncode(e) => write!(f, "policy encode error: {e:?}"),
            Self::WrapsEncode(e) => write!(f, "wraps encode error: {e:?}"),
            Self::PayloadEncode(e) => write!(f, "payload encode error: {e:?}"),
            Self::FooterEncode(e) => write!(f, "footer encode error: {e:?}"),
            Self::HeaderEncode(e) => write!(f, "header encode error: {e}"),
            Self::WrapperSealFailed { index, reason } => {
                write!(f, "wrapper {index} seal failed: {reason}")
            }
            Self::LengthOverflow => write!(f, "container size overflow"),
        }
    }
}

impl std::error::Error for EncryptError {}

/// Encrypt `input.plaintext` and seal the FMK with each `WrapperSpec`.
///
/// Returns the full serialized HydraLock v1 container.
pub fn encrypt<R: RngCore>(
    input: &EncryptInput<'_>,
    wrappers: &[WrapperSpec],
    rng: &mut R,
) -> Result<Vec<u8>, EncryptError> {
    if wrappers.is_empty() {
        return Err(EncryptError::EmptyWrappers);
    }
    for w in wrappers {
        let label = w.label();
        if label.len() > (u16::MAX as usize).saturating_sub(16) {
            return Err(EncryptError::WrapperIdTooLong);
        }
    }

    // ── 1. Generate keying material ─────────────────────────────────────────
    let mut fmk_bytes = [0u8; 32];
    rng.fill_bytes(&mut fmk_bytes);
    let fmk: Fmk = fmk_from_bytes(fmk_bytes);

    let mut file_uuid = [0u8; 16];
    rng.fill_bytes(&mut file_uuid);

    let root_key = derive_root_key(&fmk, &file_uuid);
    let subkeys = derive_subkeys(&root_key);

    // ── 2. Compute layout sizes ─────────────────────────────────────────────
    let suite_id = SUITE_ID;
    let chunk_size = input.chunk_size;
    let epoch_size = input.epoch_size;

    let entry_sizes: Vec<(usize, usize)> = wrappers
        .iter()
        .map(|w| (16 + w.label().len(), w.stanza_len()))
        .collect();

    let wraps_len: usize = WRAPS_HEADER_LEN
        + entry_sizes
            .iter()
            .map(|(id_len, stanza_len)| WRAPPER_ENTRY_HEADER_LEN + id_len + stanza_len)
            .sum::<usize>();

    // Compute metadata_len by encoding a placeholder metadata (manifest_root=[0;32]).
    // CBOR size is invariant to the content of a fixed-size bstr field.
    let placeholder_meta = MetadataPlaintext {
        plaintext_size: input.plaintext.len() as u64,
        logical_name: input.logical_name.clone(),
        mime_type: input.mime_type.clone(),
        created_at: input.created_at,
        chunk_size,
        epoch_size,
        manifest_root: [0u8; 32],
        payload_mode: 0,
        padding_bucket: input.padding.clone(),
    };
    let placeholder_cbor = placeholder_meta
        .encode()
        .map_err(EncryptError::MetadataEncode)?;
    let metadata_len: usize = placeholder_cbor.len() + 12 + 16; // nonce(12) + tag(16)

    let header_len = FIXED_HEADER_LEN as u32;
    let policy_len = POLICY_SECTION_LEN as u32;
    let wraps_len_u32 = wraps_len
        .try_into()
        .map_err(|_| EncryptError::LengthOverflow)?;
    let metadata_len_u32: u32 = metadata_len
        .try_into()
        .map_err(|_| EncryptError::LengthOverflow)?;

    let payload_offset: u64 = u64::from(header_len)
        + u64::from(policy_len)
        + u64::from(wraps_len_u32)
        + u64::from(metadata_len_u32);

    // ── 3. Build and hash the fixed header ──────────────────────────────────
    let fixed_header = FixedHeader {
        format_version_major: FORMAT_VERSION_MAJOR,
        format_version_minor: FORMAT_VERSION_MINOR,
        suite_id,
        flags: 0,
        header_len,
        policy_len,
        wraps_len: wraps_len_u32,
        metadata_len: metadata_len_u32,
        payload_offset,
    };
    let header_bytes = fixed_header.encode();
    let header_hash: [u8; 32] = *blake3::hash(&header_bytes).as_bytes();

    // ── 4. Write payload ─────────────────────────────────────────────────────
    let plaintext_total = input.plaintext.len() as u64;

    let k_payload_master = SecretKey32::from_bytes(*subkeys.k_payload_master.expose());
    let mut writer = PayloadWriter::new(
        k_payload_master,
        file_uuid,
        suite_id,
        chunk_size,
        epoch_size,
        plaintext_total,
    )
    .map_err(EncryptError::PayloadWrite)?;

    if !input.plaintext.is_empty() {
        writer
            .write(input.plaintext)
            .map_err(EncryptError::PayloadWrite)?;
    }
    let encrypted_chunks = writer.finalize().map_err(EncryptError::PayloadWrite)?;

    // ── 5. Build manifest root ───────────────────────────────────────────────
    let k_manifest_for_manifest = SecretKey32::from_bytes(*subkeys.k_manifest.expose());
    let mut manifest_builder = ManifestBuilder::new(k_manifest_for_manifest);
    for chunk in &encrypted_chunks {
        manifest_builder.add_chunk(&chunk.ciphertext_with_tag);
    }
    let manifest_root = manifest_builder
        .finalize()
        .map_err(EncryptError::ManifestBuild)?;

    // ── 6. Encrypt metadata with real manifest_root ─────────────────────────
    let real_meta = MetadataPlaintext {
        plaintext_size: plaintext_total,
        logical_name: input.logical_name.clone(),
        mime_type: input.mime_type.clone(),
        created_at: input.created_at,
        chunk_size,
        epoch_size,
        manifest_root,
        payload_mode: 0,
        padding_bucket: input.padding.clone(),
    };
    let k_control = SecretKey32::from_bytes(*subkeys.k_control.expose());
    let encrypted_metadata =
        encrypt_metadata(&k_control, &real_meta, &file_uuid, suite_id, &header_hash)
            .map_err(EncryptError::MetadataEncrypt)?;

    if encrypted_metadata.len() != metadata_len {
        return Err(EncryptError::MetadataSizeMismatch {
            expected: metadata_len,
            actual: encrypted_metadata.len(),
        });
    }

    // ── 7. Seal wrappers ─────────────────────────────────────────────────────
    let mut wrapper_entries: Vec<WrapperEntry> = Vec::with_capacity(wrappers.len());
    for (i, spec) in wrappers.iter().enumerate() {
        let aad = WrapperAadInput {
            suite_id,
            wrapper_index: i as u16,
            file_uuid,
            header_hash,
        }
        .encode();

        let fmk_key = SecretKey32::from_bytes(*fmk_expose(&fmk));

        let stanza_bytes: Vec<u8> = match spec {
            WrapperSpec::PassArgon2id {
                passphrase,
                profile,
                ..
            } => {
                let params = Argon2Params {
                    version: 19,
                    memory_kib: profile.memory_kib(),
                    time_cost: profile.time_cost(),
                    parallelism: profile.parallelism(),
                    salt: [0u8; 32], // filled by seal_with_rng
                };
                let stanza =
                    PassArgon2idStanza::seal_with_rng(&fmk_key, params, passphrase, &aad, rng)
                        .map_err(|e| EncryptError::WrapperSealFailed {
                            index: i,
                            reason: format!("{e:?}"),
                        })?;
                stanza.encode().to_vec()
            }
            WrapperSpec::X25519 { recipient_pk, .. } => {
                let stanza = X25519Stanza::seal_with_rng(&fmk_key, recipient_pk, &aad, rng)
                    .map_err(|e| EncryptError::WrapperSealFailed {
                        index: i,
                        reason: format!("{e:?}"),
                    })?;
                stanza.encode().to_vec()
            }
            WrapperSpec::MlKem768X25519 { recipient_pk, .. } => {
                let stanza = MlKem768X25519Stanza::seal_with_rng(&fmk_key, recipient_pk, &aad, rng)
                    .map_err(|e| EncryptError::WrapperSealFailed {
                        index: i,
                        reason: format!("{e:?}"),
                    })?;
                stanza.encode().to_vec()
            }
        };

        wrapper_entries.push(WrapperEntry {
            wrapper_type: spec.wrapper_type(),
            wrapper_flags: 0,
            wrapper_id: spec.wire_id(&file_uuid),
            stanza: stanza_bytes,
        });
    }

    // ── 8. Encode all sections ───────────────────────────────────────────────
    let policy = PolicySection {
        policy_version: 1,
        threshold: 1,
        total_shares: 1,
        wrapper_count: wrappers.len() as u16,
    };
    let policy_bytes = policy.encode().map_err(EncryptError::PolicyEncode)?;

    let wraps_section = WrapsSection {
        wraps_version: 1,
        wrappers: wrapper_entries,
    };
    let wraps_bytes = wraps_section.encode().map_err(EncryptError::WrapsEncode)?;

    // Convert EncryptedChunkEntry → ChunkEntry
    let chunk_entries: Vec<ChunkEntry> = encrypted_chunks
        .iter()
        .map(|e| {
            let ct = &e.ciphertext_with_tag;
            let ct_len = ct.len().saturating_sub(POLY1305_TAG_SIZE);
            let ciphertext = ct[..ct_len].to_vec();
            let tag = ct[ct_len..].to_vec();
            let flags: u16 = if e.is_final { CHUNK_FLAG_FINAL } else { 0 };
            ChunkEntry {
                flags,
                ciphertext,
                tag,
            }
        })
        .collect();

    let payload_section = PayloadSection {
        payload_version: 1,
        flags: 0,
        chunk_size,
        tag_size: POLY1305_TAG_SIZE as u32,
        chunks: chunk_entries,
    };
    let payload_bytes = payload_section
        .encode()
        .map_err(EncryptError::PayloadEncode)?;

    // ── 9. Build footer ──────────────────────────────────────────────────────
    let mut pre_footer: Vec<u8> = Vec::new();
    pre_footer.extend_from_slice(&header_bytes);
    pre_footer.extend_from_slice(&policy_bytes);
    pre_footer.extend_from_slice(&wraps_bytes);
    pre_footer.extend_from_slice(&encrypted_metadata);
    pre_footer.extend_from_slice(&payload_bytes);

    let k_manifest_for_footer = SecretKey32::from_bytes(*subkeys.k_manifest.expose());
    let footer_bytes = build_footer(&k_manifest_for_footer, manifest_root, &pre_footer);

    // ── 10. Assemble container ───────────────────────────────────────────────
    let mut container = pre_footer;
    container.extend_from_slice(&footer_bytes);
    Ok(container)
}
