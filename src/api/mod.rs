use rand::rngs::OsRng;

use crate::crypto::aad::WrapperAadInput;
use crate::crypto::password::{Argon2Params, Argon2Profile};
use crate::crypto::secret::{SecretKey32, fmk_expose};
use crate::format::header::{FIXED_HEADER_LEN, FixedHeader};
use crate::format::metadata_plaintext::{MetadataPlaintext, PaddingBucket};
use crate::format::policy::PolicySection;
use crate::format::wraps::{WrapperEntry, WrapsSection};
use crate::ops::decrypt::{
    DecryptError, DecryptResult, OpenKeyMaterial, decrypt as decrypt_container, extract_file_uuid,
    try_unwrap_fmk,
};
use crate::ops::encrypt::{EncryptError, EncryptInput, WrapperSpec, encrypt as encrypt_container};
use crate::ops::rewrap::{
    RewrapError, compute_rewrap_header_hash, rewrap_container as rewrap_container_bytes,
};
use crate::wrapper::mlkem768_x25519::{
    MLKEM768_X25519_STANZA_LEN, MlKem768X25519RecipientPublicKey, MlKem768X25519RecipientSecretKey,
    MlKem768X25519Stanza, WRAPPER_TYPE_MLKEM768_X25519,
};
use crate::wrapper::passargon2id::{
    PASS_ARGON2ID_STANZA_LEN, PassArgon2idStanza, WRAPPER_TYPE_PASS_ARGON2ID,
};
use crate::wrapper::x25519::{WRAPPER_TYPE_X25519, X25519_STANZA_LEN, X25519Stanza};

/// Errors returned by the high-level public API.
#[derive(Debug)]
pub enum ApiError {
    EmptyRecipients,
    InvalidContainerLayout,
    Encrypt(EncryptError),
    Decrypt(DecryptError),
    Rewrap(RewrapError),
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyRecipients => write!(f, "at least one recipient is required"),
            Self::InvalidContainerLayout => write!(f, "invalid container layout"),
            Self::Encrypt(e) => write!(f, "encrypt error: {e}"),
            Self::Decrypt(e) => write!(f, "decrypt error: {e}"),
            Self::Rewrap(e) => write!(f, "rewrap error: {e}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<EncryptError> for ApiError {
    fn from(value: EncryptError) -> Self {
        Self::Encrypt(value)
    }
}

impl From<DecryptError> for ApiError {
    fn from(value: DecryptError) -> Self {
        Self::Decrypt(value)
    }
}

impl From<RewrapError> for ApiError {
    fn from(value: RewrapError) -> Self {
        Self::Rewrap(value)
    }
}

/// Recipient definition used by the high-level API.
pub enum RecipientSpec {
    Passphrase {
        passphrase: Vec<u8>,
        profile: Argon2Profile,
        label: Option<Vec<u8>>,
    },
    X25519 {
        recipient_pk: [u8; 32],
        label: Option<Vec<u8>>,
    },
    MlKem768X25519 {
        recipient_pk: Box<MlKem768X25519RecipientPublicKey>,
        label: Option<Vec<u8>>,
    },
}

/// Key material accepted by high-level decrypt/rewrap.
pub enum KeyMaterial {
    Passphrase(Vec<u8>),
    X25519SecretKey([u8; 32]),
    MlKem768X25519SecretKey(MlKem768X25519RecipientSecretKey),
}

/// High-level encryption options.
pub struct EncryptOptions {
    pub logical_name: Option<String>,
    pub mime_type: Option<String>,
    pub created_at: Option<i64>,
    pub chunk_size: u32,
    pub epoch_size: u32,
    pub padding: PaddingBucket,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            logical_name: None,
            mime_type: None,
            created_at: None,
            chunk_size: crate::ops::encrypt::DEFAULT_CHUNK_SIZE,
            epoch_size: crate::ops::encrypt::DEFAULT_EPOCH_SIZE,
            padding: PaddingBucket::None,
        }
    }
}

/// Minimal policy surface for high-level rewrap.
pub struct RewrapPolicy {
    pub threshold: u8,
    pub total_shares: u8,
}

impl Default for RewrapPolicy {
    fn default() -> Self {
        Self {
            threshold: 1,
            total_shares: 1,
        }
    }
}

/// High-level decrypt output.
pub struct DecryptOutput {
    pub plaintext: Vec<u8>,
    pub metadata: MetadataPlaintext,
}

/// Encrypt plaintext bytes into a HydraLock container.
///
/// Invariants:
/// - `recipients` must not be empty.
/// - wrapper labels are optional; if omitted, deterministic defaults are used
///   (`pass{idx}` / `rcpt{idx}`).
pub fn encrypt(
    plaintext: &[u8],
    recipients: &[RecipientSpec],
    options: EncryptOptions,
) -> Result<Vec<u8>, ApiError> {
    if recipients.is_empty() {
        return Err(ApiError::EmptyRecipients);
    }

    let wrappers = build_encrypt_wrappers(recipients);
    let input = EncryptInput {
        plaintext,
        logical_name: options.logical_name,
        mime_type: options.mime_type,
        created_at: options.created_at,
        chunk_size: options.chunk_size,
        epoch_size: options.epoch_size,
        padding: options.padding,
    };

    let mut rng = OsRng;
    encrypt_container(&input, &wrappers, &mut rng).map_err(ApiError::Encrypt)
}

/// Decrypt a HydraLock container using one key source.
pub fn decrypt(container: &[u8], key: KeyMaterial) -> Result<DecryptOutput, ApiError> {
    let open = to_open_key_material(key);
    let DecryptResult {
        plaintext,
        metadata,
    } = decrypt_container(container, &open).map_err(ApiError::Decrypt)?;
    Ok(DecryptOutput {
        plaintext,
        metadata,
    })
}

/// Rewrap a container without re-encrypting payload bytes.
///
/// Invariants:
/// - FMK is recovered from existing wrappers using `current_key`.
/// - payload and metadata ciphertext are preserved verbatim.
/// - only header/policy/wraps/footer are rewritten.
pub fn rewrap_container(
    container: &[u8],
    current_key: KeyMaterial,
    new_recipients: &[RecipientSpec],
    policy: RewrapPolicy,
) -> Result<Vec<u8>, ApiError> {
    if new_recipients.is_empty() {
        return Err(ApiError::EmptyRecipients);
    }
    if container.len() < FIXED_HEADER_LEN {
        return Err(ApiError::InvalidContainerLayout);
    }

    let fixed = FixedHeader::parse(&container[..FIXED_HEADER_LEN])
        .map_err(|_| ApiError::InvalidContainerLayout)?;
    let header_hash: [u8; 32] = *blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes();

    let wraps_start = FIXED_HEADER_LEN
        .checked_add(fixed.policy_len as usize)
        .ok_or(ApiError::InvalidContainerLayout)?;
    let wraps_end = wraps_start
        .checked_add(fixed.wraps_len as usize)
        .ok_or(ApiError::InvalidContainerLayout)?;
    let wraps_bytes = container
        .get(wraps_start..wraps_end)
        .ok_or(ApiError::InvalidContainerLayout)?;
    let wraps = WrapsSection::parse(wraps_bytes).map_err(|_| ApiError::InvalidContainerLayout)?;

    let file_uuid = extract_file_uuid(&wraps.wrappers).map_err(ApiError::Decrypt)?;
    let current_open = to_open_key_material(current_key);
    let fmk = try_unwrap_fmk(
        &wraps.wrappers,
        &current_open,
        fixed.suite_id,
        &header_hash,
        &file_uuid,
    )
    .map_err(ApiError::Decrypt)?;

    let entry_sizes = compute_entry_sizes(new_recipients);
    let new_policy = PolicySection {
        policy_version: 1,
        threshold: policy.threshold,
        total_shares: policy.total_shares,
        wrapper_count: entry_sizes.len() as u16,
    };
    let new_header_hash =
        compute_rewrap_header_hash(&fixed, &new_policy, &entry_sizes).map_err(ApiError::Rewrap)?;

    let fmk_key = SecretKey32::from_bytes(*fmk_expose(&fmk));
    let new_wrappers = seal_rewrap_wrappers(
        new_recipients,
        &fmk_key,
        fixed.suite_id,
        &file_uuid,
        &new_header_hash,
    )?;

    rewrap_container_bytes(container, &fmk, &file_uuid, new_policy, new_wrappers)
        .map_err(ApiError::Rewrap)
}

/// Public low-level surface for advanced integrations.
///
/// Keep this list intentionally small to avoid freezing internal layout details.
pub mod low_level {
    pub use crate::ops::decrypt::{DecryptError, OpenKeyMaterial, decrypt};
    pub use crate::ops::encrypt::{EncryptError, EncryptInput, WrapperSpec, encrypt};
    pub use crate::ops::rewrap::{
        RewrapError, compute_rewrap_header_hash, compute_wraps_section_len, rewrap_container,
    };
}

fn build_encrypt_wrappers(recipients: &[RecipientSpec]) -> Vec<WrapperSpec> {
    recipients
        .iter()
        .enumerate()
        .map(|(idx, spec)| match spec {
            RecipientSpec::Passphrase {
                passphrase,
                profile,
                label,
            } => WrapperSpec::PassArgon2id {
                passphrase: passphrase.clone(),
                profile: *profile,
                wrapper_id: label
                    .clone()
                    .unwrap_or_else(|| format!("pass{idx}").into_bytes()),
            },
            RecipientSpec::X25519 {
                recipient_pk,
                label,
            } => WrapperSpec::X25519 {
                recipient_pk: *recipient_pk,
                wrapper_id: label
                    .clone()
                    .unwrap_or_else(|| format!("rcpt{idx}").into_bytes()),
            },
            RecipientSpec::MlKem768X25519 {
                recipient_pk,
                label,
            } => WrapperSpec::MlKem768X25519 {
                recipient_pk: recipient_pk.clone(),
                wrapper_id: label
                    .clone()
                    .unwrap_or_else(|| format!("rcpt{idx}").into_bytes()),
            },
        })
        .collect()
}

fn compute_entry_sizes(recipients: &[RecipientSpec]) -> Vec<(usize, usize)> {
    recipients
        .iter()
        .enumerate()
        .map(|(idx, spec)| {
            let label_len = match spec {
                RecipientSpec::Passphrase { label, .. }
                | RecipientSpec::X25519 { label, .. }
                | RecipientSpec::MlKem768X25519 { label, .. } => label
                    .as_ref()
                    .map(|b| b.len())
                    .unwrap_or_else(|| default_label(spec, idx).len()),
            };
            let stanza_len = match spec {
                RecipientSpec::Passphrase { .. } => PASS_ARGON2ID_STANZA_LEN,
                RecipientSpec::X25519 { .. } => X25519_STANZA_LEN,
                RecipientSpec::MlKem768X25519 { .. } => MLKEM768_X25519_STANZA_LEN,
            };
            (16 + label_len, stanza_len)
        })
        .collect()
}

fn seal_rewrap_wrappers(
    recipients: &[RecipientSpec],
    fmk_key: &SecretKey32,
    suite_id: u16,
    file_uuid: &[u8; 16],
    header_hash: &[u8; 32],
) -> Result<Vec<WrapperEntry>, ApiError> {
    let mut rng = OsRng;
    let mut wrappers = Vec::with_capacity(recipients.len());

    for (idx, spec) in recipients.iter().enumerate() {
        let label = match spec {
            RecipientSpec::Passphrase { label, .. }
            | RecipientSpec::X25519 { label, .. }
            | RecipientSpec::MlKem768X25519 { label, .. } => {
                label.clone().unwrap_or_else(|| default_label(spec, idx))
            }
        };

        let mut wire_id = Vec::with_capacity(16 + label.len());
        wire_id.extend_from_slice(file_uuid);
        wire_id.extend_from_slice(&label);

        let aad = WrapperAadInput {
            suite_id,
            wrapper_index: idx as u16,
            file_uuid: *file_uuid,
            header_hash: *header_hash,
        }
        .encode();

        let entry = match spec {
            RecipientSpec::Passphrase {
                passphrase,
                profile,
                ..
            } => {
                let params = Argon2Params::from_profile(*profile, [0u8; 32]);
                let stanza =
                    PassArgon2idStanza::seal_with_rng(fmk_key, params, passphrase, &aad, &mut rng)
                        .map_err(|e| {
                            ApiError::Encrypt(EncryptError::WrapperSealFailed {
                                index: idx,
                                reason: format!("passphrase stanza seal error: {e:?}"),
                            })
                        })?;
                WrapperEntry {
                    wrapper_type: WRAPPER_TYPE_PASS_ARGON2ID,
                    wrapper_flags: 0,
                    wrapper_id: wire_id,
                    stanza: stanza.encode().to_vec(),
                }
            }
            RecipientSpec::X25519 { recipient_pk, .. } => {
                let stanza = X25519Stanza::seal_with_rng(fmk_key, recipient_pk, &aad, &mut rng)
                    .map_err(|e| {
                        ApiError::Encrypt(EncryptError::WrapperSealFailed {
                            index: idx,
                            reason: format!("x25519 stanza seal error: {e:?}"),
                        })
                    })?;
                WrapperEntry {
                    wrapper_type: WRAPPER_TYPE_X25519,
                    wrapper_flags: 0,
                    wrapper_id: wire_id,
                    stanza: stanza.encode().to_vec(),
                }
            }
            RecipientSpec::MlKem768X25519 { recipient_pk, .. } => {
                let stanza =
                    MlKem768X25519Stanza::seal_with_rng(fmk_key, recipient_pk, &aad, &mut rng)
                        .map_err(|e| {
                            ApiError::Encrypt(EncryptError::WrapperSealFailed {
                                index: idx,
                                reason: format!("mlkem768-x25519 stanza seal error: {e:?}"),
                            })
                        })?;
                WrapperEntry {
                    wrapper_type: WRAPPER_TYPE_MLKEM768_X25519,
                    wrapper_flags: 0,
                    wrapper_id: wire_id,
                    stanza: stanza.encode().to_vec(),
                }
            }
        };
        wrappers.push(entry);
    }

    Ok(wrappers)
}

fn to_open_key_material(key: KeyMaterial) -> OpenKeyMaterial {
    match key {
        KeyMaterial::Passphrase(p) => OpenKeyMaterial::Passphrase(p),
        KeyMaterial::X25519SecretKey(sk) => OpenKeyMaterial::X25519SecretKey(sk),
        KeyMaterial::MlKem768X25519SecretKey(sk) => OpenKeyMaterial::MlKem768X25519SecretKey(sk),
    }
}

fn default_label(spec: &RecipientSpec, idx: usize) -> Vec<u8> {
    match spec {
        RecipientSpec::Passphrase { .. } => format!("pass{idx}").into_bytes(),
        RecipientSpec::X25519 { .. } | RecipientSpec::MlKem768X25519 { .. } => {
            format!("rcpt{idx}").into_bytes()
        }
    }
}
