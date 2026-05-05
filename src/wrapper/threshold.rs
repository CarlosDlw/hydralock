/// Threshold (Shamir Secret Sharing) wrapper for HydraLock v1.
///
/// Splits the File Master Key (or any 32-byte secret) into `n` shares such
/// that any `t` of them reconstruct the original. Each share is wrapped
/// individually using AES-256-GCM-SIV, binding it to:
///   - the share's position (share_index) and threshold parameters (t, n)
///   - the wrapper type id and wrapper context (suite_id, file_uuid, header_hash)
///   - the share's unique id (x-coordinate in GF(256))
///
/// This prevents:
///   - share swapping attacks (different share_index in AAD)
///   - cross-file attacks (file_uuid and header_hash in AAD)
///   - threshold downgrade attacks (t and n in AAD)
///
/// Each share KEK is derived from a caller-supplied `k_share_root` via
/// HKDF-SHA-512 domain-separated by the share id:
///   KEK_i = HKDF-SHA-512(
///       ikm  = k_share_root,
///       salt = [],
///       info = "hydralock:v1:share-kek:" || share_id_byte,
///   ) → 32 bytes
///
/// Wire format per share stanza (76 bytes):
///   Offset  Size  Field
///   0       2     stanza_version (u16 = 1, big-endian)
///   2       1     share_id       (GF(256) x-coordinate, 1..=255)
///   3       1     threshold_t    (minimum shares to reconstruct)
///   4       1     total_n        (total share count at split time)
///   5       12    wrap_nonce
///   17      48    wrapped_share  (32B share value + 16B AES-GCM-SIV tag, no nonce prefix)
///   Total: 65 bytes
///
/// Note: the `k_share_root` is a share-split-level key — the caller is
/// responsible for how it is established. Typically it is either the FMK
/// itself (if threshold is the sole access mechanism) or a derived key.

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::crypto::password::Kek;
use crate::crypto::secret::SecretKey32;
use crate::crypto::shamir::{ShamirError, ShamirShare, combine, split};
use crate::crypto::wrap::{AES_GCM_SIV_NONCE_LEN, WRAPPED_KEY_LEN, WrapError, unwrap_key, wrap_key};

/// Stanza type identifier for the threshold wrapper.
pub const WRAPPER_TYPE_THRESHOLD: u16 = 0x0004;

/// Wire-format stanza version.
const STANZA_VERSION: u16 = 1;

/// HKDF info prefix for per-share KEK derivation.
const HKDF_INFO_PREFIX: &[u8] = b"hydralock:v1:share-kek:";

/// Byte length of the wrapped share body stored in the stanza (no nonce prefix).
const WRAPPED_SHARE_BODY_LEN: usize = WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN; // 48

/// Fixed byte length of an encoded share stanza.
///
/// Layout:
///   Offset  Size  Field
///   0       2     stanza_version
///   2       1     share_id
///   3       1     threshold_t
///   4       1     total_n
///   5       12    wrap_nonce
///   17      48    wrapped_share
///   Total: 65 bytes
pub const SHARE_STANZA_LEN: usize = 2 + 1 + 1 + 1 + AES_GCM_SIV_NONCE_LEN + WRAPPED_SHARE_BODY_LEN;

const SHARE_ID_OFFSET: usize = 2;
const THRESHOLD_T_OFFSET: usize = 3;
const TOTAL_N_OFFSET: usize = 4;
const WRAP_NONCE_OFFSET: usize = 5;
const WRAPPED_SHARE_OFFSET: usize = WRAP_NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN; // 17

/// Errors from threshold wrapping/unwrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// Stanza byte length is wrong.
    InvalidLength { expected: usize, actual: usize },
    /// The `stanza_version` field is not 1.
    UnsupportedStanzaVersion { expected: u16, actual: u16 },
    /// Shamir split/combine error.
    Shamir(ShamirError),
    /// Key wrapping failed.
    WrapFailed,
    /// Key unwrapping failed — wrong key, corrupted data, or mismatched AAD.
    UnwrapFailed,
    /// Inconsistent stanza parameters (t or n mismatch across stanzas).
    InconsistentParameters,
}

impl core::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid stanza length: expected {expected}, got {actual}")
            }
            Self::UnsupportedStanzaVersion { expected, actual } => {
                write!(f, "unsupported stanza version: expected {expected}, got {actual}")
            }
            Self::Shamir(e) => write!(f, "Shamir error: {e}"),
            Self::WrapFailed => write!(f, "threshold share wrapping failed"),
            Self::UnwrapFailed => write!(f, "threshold share unwrapping failed"),
            Self::InconsistentParameters => {
                write!(f, "share stanzas have inconsistent threshold/total parameters")
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

impl From<ShamirError> for ThresholdError {
    fn from(e: ShamirError) -> Self {
        Self::Shamir(e)
    }
}

/// A decoded and authenticated share stanza.
#[derive(Clone)]
pub struct ShareStanza {
    /// The GF(256) x-coordinate of this share.
    pub share_id: u8,
    /// Minimum number of shares required to reconstruct.
    pub threshold_t: u8,
    /// Total number of shares produced at split time.
    pub total_n: u8,
    /// 12-byte AES-GCM-SIV nonce.
    pub wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
    /// 48-byte wrapped share (ciphertext 32B + tag 16B, without nonce prefix).
    pub wrapped_share: [u8; WRAPPED_SHARE_BODY_LEN],
}

impl ShareStanza {
    /// Parse a stanza from its canonical 65-byte binary representation.
    pub fn parse(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != SHARE_STANZA_LEN {
            return Err(ThresholdError::InvalidLength {
                expected: SHARE_STANZA_LEN,
                actual: bytes.len(),
            });
        }

        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != STANZA_VERSION {
            return Err(ThresholdError::UnsupportedStanzaVersion {
                expected: STANZA_VERSION,
                actual: version,
            });
        }

        let share_id = bytes[SHARE_ID_OFFSET];
        let threshold_t = bytes[THRESHOLD_T_OFFSET];
        let total_n = bytes[TOTAL_N_OFFSET];

        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        wrap_nonce.copy_from_slice(&bytes[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN]);

        let mut wrapped_share = [0u8; WRAPPED_SHARE_BODY_LEN];
        wrapped_share.copy_from_slice(&bytes[WRAPPED_SHARE_OFFSET..WRAPPED_SHARE_OFFSET + WRAPPED_SHARE_BODY_LEN]);

        Ok(Self { share_id, threshold_t, total_n, wrap_nonce, wrapped_share })
    }

    /// Encode this stanza into its canonical 65-byte binary representation.
    pub fn encode(&self) -> [u8; SHARE_STANZA_LEN] {
        let mut out = [0u8; SHARE_STANZA_LEN];
        out[0..2].copy_from_slice(&STANZA_VERSION.to_be_bytes());
        out[SHARE_ID_OFFSET] = self.share_id;
        out[THRESHOLD_T_OFFSET] = self.threshold_t;
        out[TOTAL_N_OFFSET] = self.total_n;
        out[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN]
            .copy_from_slice(&self.wrap_nonce);
        out[WRAPPED_SHARE_OFFSET..WRAPPED_SHARE_OFFSET + WRAPPED_SHARE_BODY_LEN]
            .copy_from_slice(&self.wrapped_share);
        out
    }
}

impl core::fmt::Debug for ShareStanza {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareStanza")
            .field("share_id", &self.share_id)
            .field("threshold_t", &self.threshold_t)
            .field("total_n", &self.total_n)
            .field("wrapped_share", &"[REDACTED]")
            .finish()
    }
}

/// Seal (split + wrap) `secret` into `n` share stanzas.
///
/// Parameters:
///   - `secret`: 32-byte value to protect (typically FMK or a share of FMK).
///   - `t`: minimum shares to reconstruct.
///   - `n`: total shares to produce.
///   - `k_share_root`: 32-byte root key from which per-share KEKs are derived.
///   - `aad`: additional authenticated data binding each stanza to the file.
///   - `rng`: cryptographically secure RNG for Shamir polynomial and nonces.
///
/// Returns `n` stanzas, one per share (share ids 1..=n).
pub fn seal<R: RngCore>(
    secret: &SecretKey32,
    t: u8,
    n: u8,
    k_share_root: &SecretKey32,
    aad: &[u8],
    rng: &mut R,
) -> Result<Vec<ShareStanza>, ThresholdError> {
    let shares = split(secret.expose(), t, n, rng)?;
    let mut stanzas = Vec::with_capacity(n as usize);

    for share in &shares {
        let kek = derive_share_kek(k_share_root, share.id);
        let share_secret = SecretKey32::from_bytes(share.value);

        let share_aad = build_share_aad(aad, share.id, t, n);

        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        rng.fill_bytes(&mut wrap_nonce);

        let wrapped_full = wrap_key(&kek, &share_secret, &wrap_nonce, &share_aad)
            .map_err(|_| ThresholdError::WrapFailed)?;

        let mut wrapped_share = [0u8; WRAPPED_SHARE_BODY_LEN];
        wrapped_share.copy_from_slice(&wrapped_full[AES_GCM_SIV_NONCE_LEN..]);

        stanzas.push(ShareStanza {
            share_id: share.id,
            threshold_t: t,
            total_n: n,
            wrap_nonce,
            wrapped_share,
        });
    }

    Ok(stanzas)
}

/// Open (unwrap + combine) `t` or more share stanzas to reconstruct the secret.
///
/// All provided stanzas must have consistent (threshold_t, total_n) values.
/// Exactly `threshold_t` of the provided stanzas are used for reconstruction
/// (the first `threshold_t` after validation).
///
/// Parameters:
///   - `stanzas`: at least `threshold_t` authenticated share stanzas.
///   - `k_share_root`: 32-byte root key (same as at seal time).
///   - `aad`: must match the value used during `seal`.
pub fn open(
    stanzas: &[ShareStanza],
    k_share_root: &SecretKey32,
    aad: &[u8],
) -> Result<SecretKey32, ThresholdError> {
    if stanzas.is_empty() {
        return Err(ThresholdError::Shamir(ShamirError::NotEnoughShares { got: 0, need: 1 }));
    }

    // Validate parameter consistency across all stanzas.
    let t = stanzas[0].threshold_t;
    let n = stanzas[0].total_n;
    for s in stanzas {
        if s.threshold_t != t || s.total_n != n {
            return Err(ThresholdError::InconsistentParameters);
        }
    }

    if stanzas.len() < t as usize {
        return Err(ThresholdError::Shamir(ShamirError::NotEnoughShares {
            got: stanzas.len(),
            need: t as usize,
        }));
    }

    // Unwrap each share.
    let mut shamir_shares: Vec<ShamirShare> = Vec::with_capacity(stanzas.len());
    for stanza in stanzas {
        let kek = derive_share_kek(k_share_root, stanza.share_id);
        let share_aad = build_share_aad(aad, stanza.share_id, t, n);

        let mut wrapped_full = [0u8; WRAPPED_KEY_LEN];
        wrapped_full[..AES_GCM_SIV_NONCE_LEN].copy_from_slice(&stanza.wrap_nonce);
        wrapped_full[AES_GCM_SIV_NONCE_LEN..].copy_from_slice(&stanza.wrapped_share);

        let share_secret = unwrap_key(&kek, &wrapped_full, &share_aad)
            .map_err(|e| match e {
                WrapError::DecryptFailed => ThresholdError::UnwrapFailed,
                _ => ThresholdError::WrapFailed,
            })?;

        shamir_shares.push(ShamirShare { id: stanza.share_id, value: *share_secret.expose() });
    }

    let reconstructed = combine(&shamir_shares, t)?;
    Ok(SecretKey32::from_bytes(reconstructed))
}

/// Derive a per-share KEK from the share root key and the share's id.
///
/// KEK_i = HKDF-SHA-512(
///     ikm  = k_share_root,
///     salt = [] (empty),
///     info = "hydralock:v1:share-kek:" || share_id_byte,
/// ) → 32 bytes.
fn derive_share_kek(k_share_root: &SecretKey32, share_id: u8) -> Kek {
    let hk = Hkdf::<Sha512>::new(None, k_share_root.expose());
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 1);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.push(share_id);

    let mut kek_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(&info, kek_bytes.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-512 output length");

    Kek(crate::crypto::secret::SecretKey32::from_bytes(*kek_bytes))
}

/// Build the AAD for a specific share stanza.
///
/// Layout: outer_aad || share_id (1B) || threshold_t (1B) || total_n (1B).
fn build_share_aad(outer_aad: &[u8], share_id: u8, t: u8, n: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(outer_aad.len() + 3);
    aad.extend_from_slice(outer_aad);
    aad.push(share_id);
    aad.push(t);
    aad.push(n);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn seeded_rng() -> StdRng {
        StdRng::seed_from_u64(0xCAFE_BABE_1234_5678)
    }

    fn test_secret() -> SecretKey32 {
        SecretKey32::from_bytes([0xABu8; 32])
    }

    fn test_root() -> SecretKey32 {
        SecretKey32::from_bytes([0x77u8; 32])
    }

    fn test_aad() -> Vec<u8> {
        b"hydralock-threshold-test-aad".to_vec()
    }

    #[test]
    fn seal_open_1_of_1() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 1, 1, &test_root(), &test_aad(), &mut rng).unwrap();
        assert_eq!(stanzas.len(), 1);
        let recovered = open(&stanzas, &test_root(), &test_aad()).unwrap();
        assert_eq!(recovered.expose(), test_secret().expose());
    }

    #[test]
    fn seal_open_2_of_3_any_2_shares() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 2, 3, &test_root(), &test_aad(), &mut rng).unwrap();
        assert_eq!(stanzas.len(), 3);

        let r01 = open(&[stanzas[0].clone(), stanzas[1].clone()], &test_root(), &test_aad()).unwrap();
        let r02 = open(&[stanzas[0].clone(), stanzas[2].clone()], &test_root(), &test_aad()).unwrap();
        let r12 = open(&[stanzas[1].clone(), stanzas[2].clone()], &test_root(), &test_aad()).unwrap();
        assert_eq!(r01.expose(), test_secret().expose());
        assert_eq!(r02.expose(), test_secret().expose());
        assert_eq!(r12.expose(), test_secret().expose());
    }

    #[test]
    fn seal_open_3_of_5_all_combos() {
        let secret = SecretKey32::from_bytes((1u8..=32).collect::<Vec<_>>().try_into().unwrap());
        let mut rng = seeded_rng();
        let stanzas = seal(&secret, 3, 5, &test_root(), &test_aad(), &mut rng).unwrap();

        let r = open(&[stanzas[0].clone(), stanzas[1].clone(), stanzas[2].clone()], &test_root(), &test_aad()).unwrap();
        assert_eq!(r.expose(), secret.expose());
        let r = open(&[stanzas[1].clone(), stanzas[3].clone(), stanzas[4].clone()], &test_root(), &test_aad()).unwrap();
        assert_eq!(r.expose(), secret.expose());
        let r = open(&[stanzas[0].clone(), stanzas[2].clone(), stanzas[4].clone()], &test_root(), &test_aad()).unwrap();
        assert_eq!(r.expose(), secret.expose());
    }

    #[test]
    fn insufficient_shares_returns_error() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 3, 5, &test_root(), &test_aad(), &mut rng).unwrap();
        let err = open(&stanzas[..2], &test_root(), &test_aad()).unwrap_err();
        assert!(matches!(err, ThresholdError::Shamir(ShamirError::NotEnoughShares { got: 2, need: 3 })));
    }

    #[test]
    fn wrong_aad_fails_unwrap() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 2, 3, &test_root(), &test_aad(), &mut rng).unwrap();
        let err = open(&stanzas[..2], &test_root(), b"wrong-aad").unwrap_err();
        assert!(matches!(err, ThresholdError::UnwrapFailed));
    }

    #[test]
    fn wrong_root_key_fails_unwrap() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 2, 3, &test_root(), &test_aad(), &mut rng).unwrap();
        let wrong_root = SecretKey32::from_bytes([0x00u8; 32]);
        let err = open(&stanzas[..2], &wrong_root, &test_aad()).unwrap_err();
        assert!(matches!(err, ThresholdError::UnwrapFailed));
    }

    #[test]
    fn tampered_wrapped_share_fails_unwrap() {
        let mut rng = seeded_rng();
        let mut stanzas = seal(&test_secret(), 2, 3, &test_root(), &test_aad(), &mut rng).unwrap();
        stanzas[0].wrapped_share[0] ^= 0x01;
        let err = open(&stanzas[..2], &test_root(), &test_aad()).unwrap_err();
        assert!(matches!(err, ThresholdError::UnwrapFailed));
    }

    #[test]
    fn open_more_shares_than_threshold_works() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 2, 5, &test_root(), &test_aad(), &mut rng).unwrap();
        // Provide all 5, threshold is 2.
        let recovered = open(&stanzas, &test_root(), &test_aad()).unwrap();
        assert_eq!(recovered.expose(), test_secret().expose());
    }

    #[test]
    fn stanza_encode_decode_roundtrip() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 2, 3, &test_root(), &test_aad(), &mut rng).unwrap();
        for s in &stanzas {
            let encoded = s.encode();
            assert_eq!(encoded.len(), SHARE_STANZA_LEN);
            assert_eq!(SHARE_STANZA_LEN, 65);
            let decoded = ShareStanza::parse(&encoded).unwrap();
            assert_eq!(decoded.share_id, s.share_id);
            assert_eq!(decoded.threshold_t, s.threshold_t);
            assert_eq!(decoded.total_n, s.total_n);
            assert_eq!(decoded.wrap_nonce, s.wrap_nonce);
            assert_eq!(decoded.wrapped_share, s.wrapped_share);
        }
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = ShareStanza::parse(&[0u8; SHARE_STANZA_LEN - 1]).unwrap_err();
        assert!(matches!(err, ThresholdError::InvalidLength { expected: SHARE_STANZA_LEN, actual: _ }));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut bytes = [0u8; SHARE_STANZA_LEN];
        bytes[0..2].copy_from_slice(&9u16.to_be_bytes());
        let err = ShareStanza::parse(&bytes).unwrap_err();
        assert!(matches!(err, ThresholdError::UnsupportedStanzaVersion { expected: 1, actual: 9 }));
    }

    #[test]
    fn inconsistent_stanza_parameters_returns_error() {
        let mut rng = seeded_rng();
        let s1 = seal(&test_secret(), 2, 3, &test_root(), &test_aad(), &mut rng).unwrap();
        let mut rng2 = StdRng::seed_from_u64(1);
        let s2 = seal(&test_secret(), 3, 5, &test_root(), &test_aad(), &mut rng2).unwrap();
        // Mix stanzas with different (t, n).
        let mixed = vec![s1[0].clone(), s2[0].clone()];
        let err = open(&mixed, &test_root(), &test_aad()).unwrap_err();
        assert!(matches!(err, ThresholdError::InconsistentParameters));
    }

    #[test]
    fn share_ids_are_unique_and_sequential() {
        let mut rng = seeded_rng();
        let stanzas = seal(&test_secret(), 2, 5, &test_root(), &test_aad(), &mut rng).unwrap();
        let ids: Vec<u8> = stanzas.iter().map(|s| s.share_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn stanza_len_constant_correct() {
        // Verify the constant matches the expected layout.
        // 2 (version) + 1 (id) + 1 (t) + 1 (n) + 12 (nonce) + 48 (wrapped) = 65
        assert_eq!(SHARE_STANZA_LEN, 65);
    }
}
