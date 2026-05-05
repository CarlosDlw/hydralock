use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::secret::SecretKey32;

/// Argon2id time-cost + memory-cost + parallelism profiles for HydraLock v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Profile {
    /// 64 MiB, t=3, p=1 — suitable for interactive contexts (terminal, UI).
    Interactive,
    /// 256 MiB, t=3, p=1 — recommended default for file encryption.
    Balanced,
    /// 1024 MiB, t=3, p=1 — maximum hardness for long-term archival.
    Paranoid,
}

impl Argon2Profile {
    /// Memory cost in kibibytes.
    pub fn memory_kib(&self) -> u32 {
        match self {
            Self::Interactive => 65_536,      // 64 MiB
            Self::Balanced => 262_144,        // 256 MiB
            Self::Paranoid => 1_048_576,      // 1024 MiB
        }
    }

    /// Time cost (iterations).
    pub fn time_cost(&self) -> u32 {
        3
    }

    /// Parallelism (lanes).
    pub fn parallelism(&self) -> u32 {
        1
    }
}

/// Wire-level parameters for Argon2id, as stored inside a `PASS-ARGON2ID` stanza.
///
/// These are the exact values used to reproduce the KDF derivation from any
/// conforming implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Params {
    /// Argon2 algorithm version — always 19 (0x13) for v1.
    pub version: u32,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
    /// Salt bytes — exactly 32 bytes in HydraLock v1.
    pub salt: [u8; 32],
}

impl Argon2Params {
    pub fn from_profile(profile: Argon2Profile, salt: [u8; 32]) -> Self {
        Self {
            version: 19,
            memory_kib: profile.memory_kib(),
            time_cost: profile.time_cost(),
            parallelism: profile.parallelism(),
            salt,
        }
    }
}

/// A KEK (Key Encryption Key) derived from a passphrase via Argon2id.
///
/// This is the output of `derive_kek_from_passphrase`. It is used directly
/// as the key for AES-256-GCM-SIV to wrap/unwrap the file master key share.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Kek(pub(crate) SecretKey32);

impl Kek {
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

/// Error type for password derivation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    /// The provided Argon2 parameters are invalid (memory/time/parallelism out of range).
    InvalidParams,
    /// Argon2 computation itself failed (e.g., out of memory).
    DerivationFailed,
}

impl core::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParams => write!(f, "invalid Argon2id parameters"),
            Self::DerivationFailed => write!(f, "Argon2id derivation failed"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Derive a 32-byte KEK from `passphrase` and `params` using Argon2id.
///
/// Output: 32 bytes suitable for use as an AES-256-GCM-SIV key.
///
/// The passphrase is accepted as a byte slice to support arbitrary encodings.
/// Callers are responsible for normalizing the passphrase (e.g., NFC/NFKC)
/// before calling this function.
pub fn derive_kek_from_passphrase(
    passphrase: &[u8],
    params: &Argon2Params,
) -> Result<Kek, PasswordError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| PasswordError::InvalidParams)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase, &params.salt, &mut out)
        .map_err(|_| PasswordError::DerivationFailed)?;

    Ok(Kek(SecretKey32::from_bytes(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; 32] {
        [0xBBu8; 32]
    }

    fn test_passphrase() -> &'static [u8] {
        b"correct horse battery staple"
    }

    fn minimal_params() -> Argon2Params {
        // Use minimal parameters to keep tests fast.
        Argon2Params {
            version: 19,
            memory_kib: 64,
            time_cost: 1,
            parallelism: 1,
            salt: test_salt(),
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let p = minimal_params();
        let k1 = derive_kek_from_passphrase(test_passphrase(), &p).expect("should derive");
        let k2 = derive_kek_from_passphrase(test_passphrase(), &p).expect("should derive");
        assert_eq!(k1.expose(), k2.expose());
    }

    #[test]
    fn different_passphrases_produce_different_keks() {
        let p = minimal_params();
        let k1 = derive_kek_from_passphrase(b"passphrase-one", &p).expect("should derive");
        let k2 = derive_kek_from_passphrase(b"passphrase-two", &p).expect("should derive");
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn different_salts_produce_different_keks() {
        let mut p1 = minimal_params();
        let mut p2 = minimal_params();
        p1.salt = [0x01u8; 32];
        p2.salt = [0x02u8; 32];
        let k1 = derive_kek_from_passphrase(test_passphrase(), &p1).expect("should derive");
        let k2 = derive_kek_from_passphrase(test_passphrase(), &p2).expect("should derive");
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn profile_interactive_has_expected_params() {
        let p = Argon2Profile::Interactive;
        assert_eq!(p.memory_kib(), 65_536);
        assert_eq!(p.time_cost(), 3);
        assert_eq!(p.parallelism(), 1);
    }

    #[test]
    fn profile_balanced_has_expected_params() {
        let p = Argon2Profile::Balanced;
        assert_eq!(p.memory_kib(), 262_144);
        assert_eq!(p.time_cost(), 3);
        assert_eq!(p.parallelism(), 1);
    }

    #[test]
    fn profile_paranoid_has_expected_params() {
        let p = Argon2Profile::Paranoid;
        assert_eq!(p.memory_kib(), 1_048_576);
        assert_eq!(p.time_cost(), 3);
        assert_eq!(p.parallelism(), 1);
    }
}
