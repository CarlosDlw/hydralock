use base64::{Engine, engine::general_purpose::STANDARD as B64};
use std::path::Path;

use crate::wrapper::mlkem768_x25519::{
    MLKEM768_EK_LEN, MLKEM768_SEED_LEN, MlKem768X25519RecipientPublicKey,
    MlKem768X25519RecipientSecretKey,
};

pub const X25519_PUB_HEADER: &str = "-----BEGIN HYDRALOCK X25519 PUBLIC KEY-----";
pub const X25519_PUB_FOOTER: &str = "-----END HYDRALOCK X25519 PUBLIC KEY-----";
pub const X25519_SEC_HEADER: &str = "-----BEGIN HYDRALOCK X25519 SECRET KEY-----";
pub const X25519_SEC_FOOTER: &str = "-----END HYDRALOCK X25519 SECRET KEY-----";
pub const MLKEM_PUB_HEADER: &str = "-----BEGIN HYDRALOCK MLKEM768-X25519 PUBLIC KEY-----";
pub const MLKEM_PUB_FOOTER: &str = "-----END HYDRALOCK MLKEM768-X25519 PUBLIC KEY-----";
pub const MLKEM_SEC_HEADER: &str = "-----BEGIN HYDRALOCK MLKEM768-X25519 SECRET KEY-----";
pub const MLKEM_SEC_FOOTER: &str = "-----END HYDRALOCK MLKEM768-X25519 SECRET KEY-----";

#[derive(Debug)]
pub enum KeyError {
    Io(std::io::Error),
    InvalidFormat(String),
    InvalidLength { expected: usize, actual: usize },
    Base64(base64::DecodeError),
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidFormat(msg) => write!(f, "invalid key format: {msg}"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            Self::Base64(e) => write!(f, "base64 decode error: {e}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<std::io::Error> for KeyError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// Encode bytes in PEM-like format with the given header/footer.
pub fn encode_pem(header: &str, footer: &str, data: &[u8]) -> String {
    let b64 = B64.encode(data);
    // Wrap at 64 chars per line.
    let mut lines = String::new();
    let mut i = 0;
    while i < b64.len() {
        let end = (i + 64).min(b64.len());
        lines.push_str(&b64[i..end]);
        lines.push('\n');
        i = end;
    }
    format!("{header}\n{lines}{footer}\n")
}

/// Decode bytes from PEM-like format.
pub fn decode_pem(header: &str, footer: &str, pem: &str) -> Result<Vec<u8>, KeyError> {
    let pem = pem.trim();
    let after_header = pem
        .strip_prefix(header)
        .ok_or_else(|| KeyError::InvalidFormat(format!("expected header: {header}")))?
        .trim_start_matches('\n');
    let before_footer = after_header
        .strip_suffix(footer)
        .ok_or_else(|| KeyError::InvalidFormat(format!("expected footer: {footer}")))?
        .trim_end_matches('\n');
    let b64: String = before_footer.lines().collect();
    B64.decode(b64.trim()).map_err(KeyError::Base64)
}

// ── X25519 ───────────────────────────────────────────────────────────────────

pub fn encode_x25519_public(pk: &[u8; 32]) -> String {
    encode_pem(X25519_PUB_HEADER, X25519_PUB_FOOTER, pk)
}

pub fn decode_x25519_public(pem: &str) -> Result<[u8; 32], KeyError> {
    let bytes = decode_pem(X25519_PUB_HEADER, X25519_PUB_FOOTER, pem)?;
    if bytes.len() != 32 {
        return Err(KeyError::InvalidLength { expected: 32, actual: bytes.len() });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn encode_x25519_secret(sk: &[u8; 32]) -> String {
    encode_pem(X25519_SEC_HEADER, X25519_SEC_FOOTER, sk)
}

pub fn decode_x25519_secret(pem: &str) -> Result<[u8; 32], KeyError> {
    let bytes = decode_pem(X25519_SEC_HEADER, X25519_SEC_FOOTER, pem)?;
    if bytes.len() != 32 {
        return Err(KeyError::InvalidLength { expected: 32, actual: bytes.len() });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn load_x25519_public(path: &Path) -> Result<[u8; 32], KeyError> {
    let pem = std::fs::read_to_string(path)?;
    decode_x25519_public(&pem)
}

pub fn load_x25519_secret(path: &Path) -> Result<[u8; 32], KeyError> {
    let pem = std::fs::read_to_string(path)?;
    decode_x25519_secret(&pem)
}

// ── ML-KEM-768 + X25519 ──────────────────────────────────────────────────────

/// Public key wire: x25519_pk(32) || mlkem768_ek(1184) = 1216 bytes.
pub fn encode_mlkem_public(pk: &MlKem768X25519RecipientPublicKey) -> String {
    let mut raw = Vec::with_capacity(32 + MLKEM768_EK_LEN);
    raw.extend_from_slice(&pk.x25519_pk);
    raw.extend_from_slice(&pk.mlkem768_ek_bytes);
    encode_pem(MLKEM_PUB_HEADER, MLKEM_PUB_FOOTER, &raw)
}

pub fn decode_mlkem_public(pem: &str) -> Result<MlKem768X25519RecipientPublicKey, KeyError> {
    let bytes = decode_pem(MLKEM_PUB_HEADER, MLKEM_PUB_FOOTER, pem)?;
    let expected = 32 + MLKEM768_EK_LEN;
    if bytes.len() != expected {
        return Err(KeyError::InvalidLength { expected, actual: bytes.len() });
    }
    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(&bytes[..32]);
    let mut mlkem768_ek_bytes = [0u8; MLKEM768_EK_LEN];
    mlkem768_ek_bytes.copy_from_slice(&bytes[32..]);
    Ok(MlKem768X25519RecipientPublicKey { x25519_pk, mlkem768_ek_bytes })
}

/// Secret key wire: x25519_sk(32) || mlkem768_seed(64) = 96 bytes.
pub fn encode_mlkem_secret(sk: &MlKem768X25519RecipientSecretKey) -> String {
    let mut raw = Vec::with_capacity(32 + MLKEM768_SEED_LEN);
    raw.extend_from_slice(sk.x25519_sk.as_ref());
    raw.extend_from_slice(sk.mlkem768_dk_seed.as_ref());
    encode_pem(MLKEM_SEC_HEADER, MLKEM_SEC_FOOTER, &raw)
}

pub fn decode_mlkem_secret(pem: &str) -> Result<MlKem768X25519RecipientSecretKey, KeyError> {
    let bytes = decode_pem(MLKEM_SEC_HEADER, MLKEM_SEC_FOOTER, pem)?;
    let expected = 32 + MLKEM768_SEED_LEN;
    if bytes.len() != expected {
        return Err(KeyError::InvalidLength { expected, actual: bytes.len() });
    }
    let mut x25519_sk = [0u8; 32];
    x25519_sk.copy_from_slice(&bytes[..32]);
    let mut mlkem768_dk_seed = [0u8; MLKEM768_SEED_LEN];
    mlkem768_dk_seed.copy_from_slice(&bytes[32..]);
    Ok(MlKem768X25519RecipientSecretKey::new(x25519_sk, mlkem768_dk_seed))
}

pub fn load_mlkem_public(path: &Path) -> Result<MlKem768X25519RecipientPublicKey, KeyError> {
    let pem = std::fs::read_to_string(path)?;
    decode_mlkem_public(&pem)
}

pub fn load_mlkem_secret(path: &Path) -> Result<MlKem768X25519RecipientSecretKey, KeyError> {
    let pem = std::fs::read_to_string(path)?;
    decode_mlkem_secret(&pem)
}

/// Detect key type from PEM header line and load as secret key material.
///
/// Returns the appropriate OpenKeyMaterial for use with ops::decrypt.
pub fn load_secret_key_material(
    path: &Path,
) -> Result<crate::ops::decrypt::OpenKeyMaterial, KeyError> {
    let pem = std::fs::read_to_string(path)?;
    let first_line = pem.lines().next().unwrap_or("").trim();
    if first_line == X25519_SEC_HEADER {
        let sk = decode_x25519_secret(&pem)?;
        Ok(crate::ops::decrypt::OpenKeyMaterial::X25519SecretKey(sk))
    } else if first_line == MLKEM_SEC_HEADER {
        let sk = decode_mlkem_secret(&pem)?;
        Ok(crate::ops::decrypt::OpenKeyMaterial::MlKem768X25519SecretKey(sk))
    } else {
        Err(KeyError::InvalidFormat(format!(
            "unrecognized key file header: {first_line}"
        )))
    }
}
