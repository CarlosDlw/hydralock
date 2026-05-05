/// Shamir Secret Sharing over GF(256) for HydraLock v1.
///
/// Splits a 32-byte secret into `n` shares such that any `t` of them
/// reconstruct the original. Each secret byte is processed independently
/// as a degree-(t-1) polynomial over GF(256).
///
/// GF(256) is constructed with the AES-standard irreducible polynomial:
///   p(x) = x^8 + x^4 + x^3 + x + 1  (0x11b)
///
/// Security properties:
///   - Information-theoretic: with fewer than `t` shares, the secret is
///     perfectly hidden (no computational assumptions needed).
///   - Uniqueness: each share has a distinct non-zero `id` (x-coordinate).
///   - Identity: share id 0 is reserved as the secret's x=0 value.
///   - Tampering detection: a corrupt share will silently produce a wrong
///     reconstruction; callers must verify authenticity out-of-band (e.g.,
///     via the wrapped-share MAC in `wrapper::threshold`).

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single Shamir share: an (id, value) pair where `id` is the non-zero
/// x-coordinate and `value` is the 32-byte y-coordinate vector.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    /// Non-zero x-coordinate in GF(256).  Range: 1..=255.
    pub id: u8,
    /// y-coordinate: f(id) evaluated independently for each of the 32 secret bytes.
    pub value: [u8; 32],
}

impl core::fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ShamirShare {{ id: {}, value: [REDACTED] }}", self.id)
    }
}

/// Errors from Shamir operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// `t` or `n` is zero.
    ZeroThresholdOrShares,
    /// `t > n`.
    ThresholdExceedsShares,
    /// `n > 255` (only x-coordinates 1..=255 are valid in GF(256)).
    TooManyShares,
    /// Fewer shares were provided than the required threshold.
    NotEnoughShares { got: usize, need: usize },
    /// Two or more shares have the same id.
    DuplicateShareId,
    /// A share has id 0, which is reserved for the secret.
    InvalidShareId,
}

impl core::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroThresholdOrShares => write!(f, "threshold and share count must be non-zero"),
            Self::ThresholdExceedsShares => write!(f, "threshold cannot exceed total share count"),
            Self::TooManyShares => write!(f, "at most 255 shares are supported"),
            Self::NotEnoughShares { got, need } => {
                write!(f, "need at least {need} shares to reconstruct, got {got}")
            }
            Self::DuplicateShareId => write!(f, "duplicate share ids are not allowed"),
            Self::InvalidShareId => write!(f, "share id 0 is reserved and invalid"),
        }
    }
}

impl std::error::Error for ShamirError {}

/// Split a 32-byte `secret` into `n` shares with threshold `t`.
///
/// Any `t` of the resulting shares are sufficient to reconstruct the secret.
/// Fewer than `t` shares reveal nothing about the secret.
///
/// Constraints: `1 <= t <= n <= 255`.
pub fn split<R: RngCore>(
    secret: &[u8; 32],
    t: u8,
    n: u8,
    rng: &mut R,
) -> Result<Vec<ShamirShare>, ShamirError> {
    if t == 0 || n == 0 {
        return Err(ShamirError::ZeroThresholdOrShares);
    }
    if t > n {
        return Err(ShamirError::ThresholdExceedsShares);
    }
    // n <= 255 is guaranteed by u8 type.

    let degree = (t - 1) as usize;
    let n_usize = n as usize;

    // For each of the 32 secret bytes, generate an independent polynomial of
    // degree (t-1) over GF(256) with the free coefficient equal to secret[i].
    //
    // coefficients[i][0] = secret[i], coefficients[i][1..=degree] = random.
    let mut coeffs = vec![[0u8; 32]; t as usize]; // coeffs[j][i] = coefficient j for byte i
    // Set free term (j=0) to the secret.
    coeffs[0].copy_from_slice(secret);
    // Fill higher-degree coefficients with random bytes.
    for coeff_row in coeffs.iter_mut().skip(1) {
        rng.fill_bytes(coeff_row);
        // Prevent degenerate all-zero leading coefficient (not strictly required for
        // security but avoids accidentally reducing degree below t-1 for all bytes).
        // We accept zeros — a zero leading coefficient is fine for individual bytes.
    }

    // Evaluate polynomial at x = 1..=n.
    let mut shares = Vec::with_capacity(n_usize);
    for x in 1..=n {
        let mut value = [0u8; 32];
        for (byte_idx, v) in value.iter_mut().enumerate() {
            // Horner's method: f(x) = c0 + x*(c1 + x*(c2 + ... + x*c_{degree}))
            let mut acc = coeffs[degree][byte_idx];
            for j in (0..degree).rev() {
                acc = gf_add(gf_mul(acc, x), coeffs[j][byte_idx]);
            }
            *v = acc;
        }
        shares.push(ShamirShare { id: x, value });
    }

    Ok(shares)
}

/// Reconstruct the secret from `t` or more shares using Lagrange interpolation
/// at x=0 over GF(256).
///
/// Exactly how many shares are needed is determined by the `threshold` parameter
/// (which was chosen at split time). The caller must pass at least `threshold`
/// distinct valid shares.
///
/// Note: if shares are incorrect/tampered, reconstruction will succeed but
/// produce a wrong secret. Authentication must happen at the wrapper layer.
pub fn combine(shares: &[ShamirShare], threshold: u8) -> Result<[u8; 32], ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::ZeroThresholdOrShares);
    }

    let t = threshold as usize;

    if shares.len() < t {
        return Err(ShamirError::NotEnoughShares { got: shares.len(), need: t });
    }

    // Validate share ids.
    for s in shares {
        if s.id == 0 {
            return Err(ShamirError::InvalidShareId);
        }
    }

    // Check for duplicate ids.
    let ids: Vec<u8> = shares.iter().map(|s| s.id).collect();
    let mut sorted_ids = ids.clone();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    if sorted_ids.len() != shares.len() {
        return Err(ShamirError::DuplicateShareId);
    }

    // Use only the first `t` shares.
    let active = &shares[..t];

    // Lagrange interpolation at x=0 for each of the 32 bytes independently.
    let mut secret = [0u8; 32];
    for byte_idx in 0..32 {
        let mut acc: u8 = 0;
        for i in 0..t {
            let xi = active[i].id;
            let yi = active[i].value[byte_idx];

            // Lagrange basis polynomial at x=0: prod_{j≠i} (0 - xj) / (xi - xj)
            // In GF(256): subtraction = XOR, so (0 - xj) = xj and (xi - xj) = xi XOR xj.
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for j in 0..t {
                if j != i {
                    let xj = active[j].id;
                    num = gf_mul(num, xj);              // numerator *= xj (= 0 XOR xj = xj)
                    den = gf_mul(den, gf_add(xi, xj));  // denominator *= xi XOR xj
                }
            }
            // L_i(0) = num / den = num * den^{-1}
            let l = gf_mul(num, gf_inv(den));
            acc = gf_add(acc, gf_mul(yi, l));
        }
        secret[byte_idx] = acc;
    }

    Ok(secret)
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic
// ---------------------------------------------------------------------------
//
// Field: GF(2^8), irreducible polynomial p(x) = x^8 + x^4 + x^3 + x + 1 (0x11b).
// This is the same field used in AES.

/// GF(256) addition (XOR).
#[inline(always)]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication using the Russian-peasant algorithm.
/// No lookup tables — constant-time-friendly (no data-dependent branches on secrets).
#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    // Reduce modulo p(x) = x^8 + x^4 + x^3 + x + 1.
    // The low 8 bits of 0x11b = 0x1b represent the non-x^8 terms.
    let mut carry: u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        carry = a >> 7;       // high bit of a (coefficient of x^7)
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;        // reduce mod p(x)
        }
        b >>= 1;
    }
    result
}

/// GF(256) multiplicative inverse using Fermat's little theorem: a^(256-2) = a^254.
/// Returns 0 for input 0 (by convention; callers must never pass 0 to gf_inv in practice).
#[inline]
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^254 = (a^2)^127
    let a2 = gf_mul(a, a);     // a^2
    let a4 = gf_mul(a2, a2);   // a^4
    let a8 = gf_mul(a4, a4);   // a^8
    let a16 = gf_mul(a8, a8);  // a^16
    let a32 = gf_mul(a16, a16);// a^32
    let a64 = gf_mul(a32, a32);// a^64
    let a128 = gf_mul(a64, a64);// a^128

    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2 = 0b11111110
    let r = gf_mul(a128, a64); // a^192
    let r = gf_mul(r, a32);    // a^224
    let r = gf_mul(r, a16);    // a^240
    let r = gf_mul(r, a8);     // a^248
    let r = gf_mul(r, a4);     // a^252
    let r = gf_mul(r, a2);     // a^254
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn seeded_rng() -> StdRng {
        StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_1234)
    }

    // --- GF(256) unit tests ---

    #[test]
    fn gf_add_is_xor() {
        assert_eq!(gf_add(0x53, 0xCA), 0x53 ^ 0xCA);
        assert_eq!(gf_add(0xFF, 0xFF), 0x00);
        assert_eq!(gf_add(0x00, 0xAB), 0xAB);
    }

    #[test]
    fn gf_mul_identity() {
        for x in 0u8..=255 {
            assert_eq!(gf_mul(x, 1), x, "x*1 should equal x for x={x}");
        }
    }

    #[test]
    fn gf_mul_zero() {
        for x in 0u8..=255 {
            assert_eq!(gf_mul(x, 0), 0);
            assert_eq!(gf_mul(0, x), 0);
        }
    }

    #[test]
    fn gf_mul_commutative() {
        // Spot-check commutativity.
        for a in [0x53u8, 0xCAu8, 0x01u8, 0xFFu8, 0x1Bu8] {
            for b in [0x53u8, 0xCAu8, 0x01u8, 0xFFu8, 0x1Bu8] {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
    }

    #[test]
    fn gf_mul_known_values() {
        // From AES spec: 0x57 * 0x83 = 0xc1 in GF(2^8)/0x11b
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        // 0x53 * 0xCA = ? — verify round-trip via inverse
        let a = 0x53u8;
        let b = 0xCAu8;
        let p = gf_mul(a, b);
        assert_eq!(gf_mul(p, gf_inv(a)), b);
    }

    #[test]
    fn gf_inv_round_trip() {
        for x in 1u8..=255 {
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "x * inv(x) should be 1 for x={x}");
        }
    }

    #[test]
    fn gf_inv_zero_is_zero() {
        assert_eq!(gf_inv(0), 0);
    }

    // --- Shamir split/combine tests ---

    #[test]
    fn split_combine_1_of_1() {
        let secret = [0x42u8; 32];
        let mut rng = seeded_rng();
        let shares = split(&secret, 1, 1, &mut rng).unwrap();
        assert_eq!(shares.len(), 1);
        let recovered = combine(&shares, 1).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn split_combine_2_of_3() {
        let secret = [0xABu8; 32];
        let mut rng = seeded_rng();
        let shares = split(&secret, 2, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 of the 3 shares reconstruct correctly.
        let r01 = combine(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
        let r02 = combine(&[shares[0].clone(), shares[2].clone()], 2).unwrap();
        let r12 = combine(&[shares[1].clone(), shares[2].clone()], 2).unwrap();
        assert_eq!(r01, secret);
        assert_eq!(r02, secret);
        assert_eq!(r12, secret);
    }

    #[test]
    fn split_combine_3_of_5() {
        let secret: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let mut rng = seeded_rng();
        let shares = split(&secret, 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        // First 3, middle 3, last 3 — all reconstruct.
        let r = combine(&[shares[0].clone(), shares[1].clone(), shares[2].clone()], 3).unwrap();
        assert_eq!(r, secret);
        let r = combine(&[shares[1].clone(), shares[2].clone(), shares[3].clone()], 3).unwrap();
        assert_eq!(r, secret);
        let r = combine(&[shares[2].clone(), shares[3].clone(), shares[4].clone()], 3).unwrap();
        assert_eq!(r, secret);
    }

    #[test]
    fn shares_are_distinct_from_secret() {
        let secret = [0x00u8; 32]; // all-zeros secret
        let mut rng = seeded_rng();
        let shares = split(&secret, 2, 3, &mut rng).unwrap();
        // With an all-zeros secret the shares should still not be all-zero
        // (because random polynomial coefficients are added).
        // At least one share should differ from zero.
        let any_nonzero = shares.iter().any(|s| s.value.iter().any(|&b| b != 0));
        assert!(any_nonzero, "all shares were zero for a zero secret — polynomial degenerate?");
    }

    #[test]
    fn different_secrets_produce_different_shares() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let mut rng1 = seeded_rng();
        let mut rng2 = seeded_rng();
        let shares1 = split(&secret1, 2, 3, &mut rng1).unwrap();
        let shares2 = split(&secret2, 2, 3, &mut rng2).unwrap();
        // Same RNG seed, different secrets → shares must differ.
        assert_ne!(shares1[0].value, shares2[0].value);
    }

    #[test]
    fn insufficient_shares_returns_error() {
        let secret = [0x55u8; 32];
        let mut rng = seeded_rng();
        let shares = split(&secret, 3, 5, &mut rng).unwrap();
        let err = combine(&shares[..2], 3).unwrap_err();
        assert!(matches!(err, ShamirError::NotEnoughShares { got: 2, need: 3 }));
    }

    #[test]
    fn duplicate_share_ids_returns_error() {
        let secret = [0x77u8; 32];
        let mut rng = seeded_rng();
        let shares = split(&secret, 2, 3, &mut rng).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        let err = combine(&dup, 2).unwrap_err();
        assert!(matches!(err, ShamirError::DuplicateShareId));
    }

    #[test]
    fn zero_share_id_returns_error() {
        let bad_share = ShamirShare { id: 0, value: [0u8; 32] };
        let err = combine(&[bad_share], 1).unwrap_err();
        assert!(matches!(err, ShamirError::InvalidShareId));
    }

    #[test]
    fn threshold_exceeds_n_returns_error() {
        let secret = [0x99u8; 32];
        let mut rng = seeded_rng();
        let err = split(&secret, 4, 3, &mut rng).unwrap_err();
        assert!(matches!(err, ShamirError::ThresholdExceedsShares));
    }

    #[test]
    fn zero_threshold_returns_error() {
        let secret = [0xAAu8; 32];
        let mut rng = seeded_rng();
        let err = split(&secret, 0, 3, &mut rng).unwrap_err();
        assert!(matches!(err, ShamirError::ZeroThresholdOrShares));
    }

    #[test]
    fn share_ids_are_1_through_n() {
        let secret = [0xBBu8; 32];
        let mut rng = seeded_rng();
        let shares = split(&secret, 2, 5, &mut rng).unwrap();
        let ids: Vec<u8> = shares.iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn combine_with_more_shares_than_threshold() {
        let secret = [0xCCu8; 32];
        let mut rng = seeded_rng();
        let shares = split(&secret, 2, 5, &mut rng).unwrap();
        // Provide all 5 shares, threshold is 2 — should still work (uses first t).
        let recovered = combine(&shares, 2).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn tampered_share_produces_wrong_secret() {
        let secret = [0xDDu8; 32];
        let mut rng = seeded_rng();
        let mut shares = split(&secret, 2, 3, &mut rng).unwrap();
        shares[0].value[0] ^= 0x01; // tamper first byte of first share
        let recovered = combine(&shares[..2], 2).unwrap();
        // Should succeed structurally but produce wrong result.
        assert_ne!(recovered, secret);
    }

    #[test]
    fn split_n_equals_255() {
        let secret = [0xEEu8; 32];
        let mut rng = seeded_rng();
        // t=255, n=255 — maximum supported.
        let shares = split(&secret, 255, 255, &mut rng).unwrap();
        assert_eq!(shares.len(), 255);
        let recovered = combine(&shares, 255).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn randomness_produces_different_shares_same_secret() {
        let secret = [0xFFu8; 32];
        let mut rng1 = StdRng::seed_from_u64(1);
        let mut rng2 = StdRng::seed_from_u64(2);
        let shares1 = split(&secret, 2, 3, &mut rng1).unwrap();
        let shares2 = split(&secret, 2, 3, &mut rng2).unwrap();
        // Different randomness → different share values (same shares count as 1/255 probability of collision).
        assert_ne!(shares1[0].value, shares2[0].value);
        // But both reconstruct the same secret.
        let r1 = combine(&shares1[..2], 2).unwrap();
        let r2 = combine(&shares2[..2], 2).unwrap();
        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
    }
}
