use secrecy::ExposeSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// File Master Key — 32 random bytes, root of the entire key derivation tree.
///
/// Wrapped in `secrecy::Secret` to prevent accidental debug printing and to
/// enforce explicit exposure via `expose_secret()`.
pub type Fmk = secrecy::Secret<[u8; 32]>;

/// Generic 32-byte derived secret key.
///
/// Zeroed automatically when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32([u8; 32]);

impl SecretKey32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose the raw key bytes for use in cryptographic operations.
    ///
    /// Callers are responsible for ensuring the returned slice is not copied
    /// into long-lived heap allocations.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 24-byte nonce for XChaCha20-Poly1305.
///
/// Zeroed automatically when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretNonce24([u8; 24]);

impl SecretNonce24 {
    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 24] {
        &self.0
    }
}

/// Full set of root subkeys derived from `root_key`.
///
/// Each subkey is domain-separated and serves a single cryptographic plane.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubkeySet {
    pub k_control: SecretKey32,
    pub k_manifest: SecretKey32,
    pub k_payload_master: SecretKey32,
    pub k_padding: SecretKey32,
    pub k_rewrap: SecretKey32,
}

/// Construct a `Fmk` from raw bytes.
///
/// Intended for test helpers and deserialization boundaries only.
pub fn fmk_from_bytes(bytes: [u8; 32]) -> Fmk {
    secrecy::Secret::new(bytes)
}

/// Expose the raw bytes of a `Fmk`.
pub fn fmk_expose(fmk: &Fmk) -> &[u8; 32] {
    fmk.expose_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key32_expose_is_stable() {
        let bytes = [0xABu8; 32];
        let key = SecretKey32::from_bytes(bytes);
        assert_eq!(key.expose(), &bytes);
    }

    #[test]
    fn secret_nonce24_expose_is_stable() {
        let bytes = [0x5Cu8; 24];
        let nonce = SecretNonce24::from_bytes(bytes);
        assert_eq!(nonce.expose(), &bytes);
    }

    #[test]
    fn fmk_roundtrip_is_stable() {
        let bytes = [0x01u8; 32];
        let fmk = fmk_from_bytes(bytes);
        assert_eq!(fmk_expose(&fmk), &bytes);
    }
}
