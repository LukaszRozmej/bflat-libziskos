//! Windowed Straus-Shamir double-scalar multiplication `k1·G + k2·P` on secp256k1.
//!
//! - `k1` splits as `c0 + c1·2^128` against constant tables of `[d]G` and `[d](2^128·G)`.
//! - `k2` splits by GLV as `±b1 ± b2·λ`, against per-call tables of `[d]P` and `[d]φ(P)`.
//!
//! All four halves are below 2^128 and share one doubling chain of 128 doublings. Each half is
//! read in signed (Booth) digits: radix 2^8 for the constant tables and radix 2^4 for the
//! per-call ones, whose table costs precompile calls to build.

#[cfg(feature = "hints")]
extern crate alloc;
#[cfg(feature = "hints")]
use alloc::vec::Vec;

use crate::syscalls::{
    syscall_arith256_mod, syscall_secp256k1_add, syscall_secp256k1_dbl, SyscallArith256ModParams,
    SyscallPoint256,
};

use super::{
    constants::{BETA, P},
    g_tables::{G_SHIFTED_TABLE, G_TABLE, G_TABLE_MID},
    scalar::glv_decompose_fn_secp256k1,
};

/// Booth radix 2^4 digits cover a 128-bit half plus the carry out of its top digit.
const P_WINDOW: usize = 4;
const P_DIGITS: usize = 33;
const P_TABLE_MID: usize = 8;
/// Booth radix 2^8 digits of the halves of `k1`, at every other radix 2^4 position.
const G_WINDOW: usize = 8;

/// An affine accumulator with an explicit point at infinity.
struct Accumulator {
    point: SyscallPoint256,
    infinity: bool,
}

impl Accumulator {
    #[inline(always)]
    fn double(&mut self, #[cfg(feature = "hints")] hints: &mut Vec<u64>) {
        if !self.infinity {
            syscall_secp256k1_dbl(
                &mut self.point,
                #[cfg(feature = "hints")]
                hints,
            );
        }
    }

    /// Adds the canonical on-curve point `q`.
    ///
    /// The add precompile requires distinct x-coordinates, so `q = ±acc` is handled here.
    #[inline(always)]
    fn add(&mut self, q: &SyscallPoint256, #[cfg(feature = "hints")] hints: &mut Vec<u64>) {
        if self.infinity {
            self.point = *q;
            self.infinity = false;
            return;
        }
        if same_x(&self.point, q) {
            let y = &self.point.y;
            if y[0] == q.y[0] && y[1] == q.y[1] && y[2] == q.y[2] && y[3] == q.y[3] {
                syscall_secp256k1_dbl(
                    &mut self.point,
                    #[cfg(feature = "hints")]
                    hints,
                );
            } else {
                self.infinity = true;
            }
            return;
        }
        syscall_secp256k1_add(
            &mut self.point,
            q,
            #[cfg(feature = "hints")]
            hints,
        );
    }
}

/// Limb-wise, so that the common mismatch exits on the first limb without a memcmp call.
#[inline(always)]
fn same_x(a: &SyscallPoint256, b: &SyscallPoint256) -> bool {
    a.x[0] == b.x[0] && a.x[1] == b.x[1] && a.x[2] == b.x[2] && a.x[3] == b.x[3]
}

/// `v << 1` for `v = lo + hi·2^64`, so that bit `i - 1` of `v` sits at bit `i`.
#[inline(always)]
fn shifted_half(lo: u64, hi: u64) -> [u64; 3] {
    [lo << 1, (hi << 1) | (lo >> 63), hi >> 63]
}

/// Booth digit `i` of radix `2^w` of the half whose `shifted_half` is `s`:
/// `b[wi-1] + b[wi] + 2·b[wi+1] + … + 2^(w-2)·b[wi+w-2] - 2^(w-1)·b[wi+w-1]`, in `[-2^(w-1), 2^(w-1)]`.
#[inline(always)]
fn booth_digit(s: &[u64; 3], i: usize, w: usize) -> i64 {
    let position = w * i;
    let limb = position / 64;
    let offset = position % 64;
    let mut window = s[limb] >> offset;
    if offset + w + 1 > 64 {
        window |= s[limb + 1] << (64 - offset);
    }
    let window = window & ((1 << (w + 1)) - 1);
    ((window + 1) >> 1) as i64 - ((window >> w) << w) as i64
}

/// `p - y` for `y ∈ [1, p)`.
#[inline(always)]
fn neg_y(y: &[u64; 4]) -> [u64; 4] {
    let (l0, b0) = P[0].overflowing_sub(y[0]);
    let (l1, b1a) = P[1].overflowing_sub(y[1]);
    let (l1, b1b) = l1.overflowing_sub(b0 as u64);
    let (l2, b2a) = P[2].overflowing_sub(y[2]);
    let (l2, b2b) = l2.overflowing_sub((b1a | b1b) as u64);
    let l3 = P[3].wrapping_sub(y[3]).wrapping_sub((b2a | b2b) as u64);
    [l0, l1, l2, l3]
}

/// Given scalars `k1, k2 ∈ [0, N-1]` and a point `p`, computes `k1·G + k2·p`.
///
/// Returns `None` if the result is the point at infinity.
///
/// # Soundness
/// `p` must be on-curve, non-identity, and have **canonical** coordinates (`x, y < p`).
pub(crate) fn straus_double_scalar_mul_with_g_secp256k1(
    k1: &[u64; 4],
    k2: &[u64; 4],
    p: &[u64; 8],
    #[cfg(feature = "hints")] hints: &mut Vec<u64>,
) -> Option<[u64; 8]> {
    let c0 = shifted_half(k1[0], k1[1]);
    let c1 = shifted_half(k1[2], k1[3]);

    // k2 = (-1)^σ1·b1 + (-1)^σ2·b2·λ (mod n), b1, b2 < 2^128, checked by the decomposition.
    let (b1, b2, sigma1, sigma2) = glv_decompose_fn_secp256k1(
        k2,
        #[cfg(feature = "hints")]
        hints,
    );
    let b1 = shifted_half(b1[0], b1[1]);
    let b2 = shifted_half(b2[0], b2[1]);

    // p_table[8 + d] = [d]p and phi_table[8 + d] = [d]φ(p) = (β·x, y) for d ∈ [-8, 8], d ≠ 0.
    // p has prime order n, so no two of [1]p..[8]p share an x-coordinate.
    let mut p_table = [SyscallPoint256 { x: [0; 4], y: [0; 4] }; 2 * P_TABLE_MID + 1];
    let mut phi_table = [SyscallPoint256 { x: [0; 4], y: [0; 4] }; 2 * P_TABLE_MID + 1];
    p_table[P_TABLE_MID + 1] =
        SyscallPoint256 { x: [p[0], p[1], p[2], p[3]], y: [p[4], p[5], p[6], p[7]] };
    for d in 2..=P_TABLE_MID {
        let (lower, upper) = p_table.split_at_mut(P_TABLE_MID + d);
        let entry = &mut upper[0];
        if d % 2 == 0 {
            *entry = lower[P_TABLE_MID + d / 2];
            syscall_secp256k1_dbl(
                entry,
                #[cfg(feature = "hints")]
                hints,
            );
        } else {
            *entry = lower[P_TABLE_MID + d - 1];
            let base = &lower[P_TABLE_MID + 1];
            assert!(!same_x(entry, base), "table points must have distinct x");
            syscall_secp256k1_add(
                entry,
                base,
                #[cfg(feature = "hints")]
                hints,
            );
        }
    }
    for d in 1..=P_TABLE_MID {
        let positive = &p_table[P_TABLE_MID + d];
        let minus_y = neg_y(&positive.y);
        let y = positive.y;
        let mut params = SyscallArith256ModParams {
            a: &BETA,
            b: &positive.x,
            c: &[0, 0, 0, 0],
            module: &P,
            d: &mut phi_table[P_TABLE_MID + d].x,
        };
        syscall_arith256_mod(
            &mut params,
            #[cfg(feature = "hints")]
            hints,
        );
        phi_table[P_TABLE_MID + d].y = y;
        let phi_x = phi_table[P_TABLE_MID + d].x;
        phi_table[P_TABLE_MID - d] = SyscallPoint256 { x: phi_x, y: minus_y };
        p_table[P_TABLE_MID - d] = SyscallPoint256 { x: p_table[P_TABLE_MID + d].x, y: minus_y };
    }
    // The signs of the GLV halves flip their digits: m = 0 keeps d, m = -1 negates it.
    let m1 = -(sigma1 as i64);
    let m2 = -(sigma2 as i64);

    let mut acc = Accumulator { point: SyscallPoint256 { x: [0; 4], y: [0; 4] }, infinity: true };
    for i in (0..P_DIGITS).rev() {
        for _ in 0..P_WINDOW {
            acc.double(
                #[cfg(feature = "hints")]
                hints,
            );
        }
        if i % 2 == 0 {
            let d = booth_digit(&c0, i / 2, G_WINDOW);
            if d != 0 {
                acc.add(
                    &G_TABLE[(G_TABLE_MID as i64 + d) as usize],
                    #[cfg(feature = "hints")]
                    hints,
                );
            }
            let d = booth_digit(&c1, i / 2, G_WINDOW);
            if d != 0 {
                acc.add(
                    &G_SHIFTED_TABLE[(G_TABLE_MID as i64 + d) as usize],
                    #[cfg(feature = "hints")]
                    hints,
                );
            }
        }
        let d = (booth_digit(&b1, i, P_WINDOW) ^ m1) - m1;
        if d != 0 {
            acc.add(
                &p_table[(P_TABLE_MID as i64 + d) as usize],
                #[cfg(feature = "hints")]
                hints,
            );
        }
        let d = (booth_digit(&b2, i, P_WINDOW) ^ m2) - m2;
        if d != 0 {
            acc.add(
                &phi_table[(P_TABLE_MID as i64 + d) as usize],
                #[cfg(feature = "hints")]
                hints,
            );
        }
    }

    if acc.infinity {
        None
    } else {
        let q = acc.point;
        Some([q.x[0], q.x[1], q.x[2], q.x[3], q.y[0], q.y[1], q.y[2], q.y[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub_p(y: &[u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let d = (P[i] as u128).wrapping_sub(y[i] as u128).wrapping_sub(borrow);
            out[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        out
    }

    #[test]
    fn neg_y_borrows_across_limbs() {
        let edges = [0, 1, P[0] - 1, P[0], P[0] + 1, u64::MAX];
        for &a in &edges {
            for &b in &[0, 1, u64::MAX - 1, u64::MAX] {
                for &c in &[0, u64::MAX] {
                    let y = [a, b, c, if b == u64::MAX && c == u64::MAX { 0 } else { u64::MAX }];
                    if y == [0; 4] {
                        continue;
                    }
                    assert_eq!(neg_y(&y), sub_p(&y), "y = {y:x?}");
                }
            }
        }
    }

    #[test]
    fn booth_digits_recompose() {
        let halves = [[0, 0], [1, 0], [u64::MAX, 0], [0, u64::MAX], [u64::MAX, u64::MAX], [0x8000_0000_0000_0000, 1]];
        for h in halves {
            let s = shifted_half(h[0], h[1]);
            for (w, digits) in [(P_WINDOW, P_DIGITS), (G_WINDOW, (P_DIGITS + 1) / 2)] {
                let mut acc: i128 = 0;
                for i in (0..digits).rev() {
                    let d = booth_digit(&s, i, w);
                    assert!(d.abs() <= 1 << (w - 1));
                    acc = acc.wrapping_shl(w as u32).wrapping_add(d as i128);
                }
                assert_eq!(acc as u128, (h[1] as u128) << 64 | h[0] as u128, "w = {w}, half = {h:x?}");
            }
        }
    }
}
