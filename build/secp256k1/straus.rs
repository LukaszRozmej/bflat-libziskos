//! Windowed Straus-Shamir double-scalar multiplication `k1·G + k2·P` on secp256k1.
//!
//! - `k1` splits as `c0 + c1·2^128`, read in unsigned radix 2^12 digits against constant tables of
//!   `[d]G` and `[d](2^128·G)`.
//! - `k2` splits by GLV as `±b1 ± b2·λ`, read in signed (Booth) radix 2^4 digits against per-call
//!   tables of `[d]P` and `[d]φ(P)`, whose entries cost precompile calls to build.
//!
//! All four halves are below 2^128 and share one chain of 128 doublings. The accumulator starts at
//! `OFFSET`, a point nobody knows a logarithm of, so it never reaches infinity and the walk needs no
//! checks for it; `[2^128]OFFSET` is subtracted at the end. Should an addition still meet equal
//! x-coordinates, the walk runs again on an accumulator that handles infinity and doubling exactly.

#[cfg(feature = "hints")]
extern crate alloc;
#[cfg(feature = "hints")]
use alloc::vec::Vec;

use crate::syscalls::{
    syscall_arith256_mod, syscall_secp256k1_add, syscall_secp256k1_dbl, SyscallArith256ModParams,
    SyscallPoint256, SyscallSecp256k1AddParams,
};

use super::{
    constants::{BETA, P},
    g_tables::{G_SHIFTED_TABLE, G_TABLE, G_WINDOW, OFFSET, OFFSET_SHIFTED_NEG},
    scalar::glv_decompose_fn_secp256k1,
};

const P_TABLE_MID: usize = 8;
const POINT_BYTES: usize = core::mem::size_of::<SyscallPoint256>();
/// The byte offset of the unused middle entry, which a zero Booth digit maps to.
const ZERO_DIGIT: usize = P_TABLE_MID * POINT_BYTES;
const G_MASK: u64 = (1 << G_WINDOW) - 1;
const ZERO_POINT: SyscallPoint256 = SyscallPoint256 { x: [0; 4], y: [0; 4] };

/// For each 5-bit Booth window `w` of radix 2^4, the byte offset of entry `P_TABLE_MID + d` of a
/// per-call table, `d = ⌈w/2⌉ - 16·(w >> 4)`; row 1 negates `d` for a GLV half of negative sign.
static P_OFFSETS: [[usize; 32]; 2] = p_offsets();

const fn p_offsets() -> [[usize; 32]; 2] {
    let mut table = [[0; 32]; 2];
    let mut w = 0;
    while w < 32 {
        let d = ((w as i64 + 1) >> 1) - ((w as i64 >> 4) << 4);
        table[0][w] = (P_TABLE_MID as i64 + d) as usize * POINT_BYTES;
        table[1][w] = (P_TABLE_MID as i64 - d) as usize * POINT_BYTES;
        w += 1;
    }
    table
}

/// Cuts the 192-bit value `s0 + s1·2^64 + s2·2^128` into the words `s`, `s >> 60` and `s >> 120`, so
/// that every window the walk reads lies in one word: walk position `i = 15·word + k` reads
/// `word >> 4k`.
#[inline(always)]
fn words(s0: u64, s1: u64, s2: u64) -> [u64; 3] {
    [s0, (s0 >> 60) | (s1 << 4), (s1 >> 56) | (s2 << 8)]
}

/// The words of `v << 1` for a 128-bit `v = lo + hi·2^64`, so that the 5-bit window at walk
/// position `i` holds bits `4i - 1 ..= 4i + 3` of `v`, the inputs of its Booth digit.
#[inline(always)]
fn booth_words(lo: u64, hi: u64) -> [u64; 3] {
    words(lo << 1, (hi << 1) | (lo >> 63), hi >> 63)
}

#[inline(always)]
fn entry<'t>(table: &'t [SyscallPoint256; 2 * P_TABLE_MID + 1], offset: usize) -> &'t SyscallPoint256 {
    debug_assert!(offset % POINT_BYTES == 0 && offset < (2 * P_TABLE_MID + 1) * POINT_BYTES);
    // SAFETY: P_OFFSETS holds only offsets of entries of a (2·P_TABLE_MID + 1)-entry table.
    unsafe { &*(table.as_ptr() as *const u8).add(offset).cast::<SyscallPoint256>() }
}

/// Limb-wise, so that the common mismatch exits on the first limb without a memcmp call.
#[inline(always)]
fn same_x(a: &SyscallPoint256, b: &SyscallPoint256) -> bool {
    a.x[0] == b.x[0] && a.x[1] == b.x[1] && a.x[2] == b.x[2] && a.x[3] == b.x[3]
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

trait Accumulator<'p> {
    fn double(&mut self, #[cfg(feature = "hints")] hints: &mut Vec<u64>);

    /// Adds the canonical on-curve point `q`; `false` stops the walk.
    fn add(&mut self, q: &'p SyscallPoint256, #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> bool;
}

/// Starts at `OFFSET` and stops the walk on equal x-coordinates, which the add precompile rejects.
struct OffsetAccumulator {
    point: SyscallPoint256,
}

impl<'p> Accumulator<'p> for OffsetAccumulator {
    #[inline(always)]
    fn double(&mut self, #[cfg(feature = "hints")] hints: &mut Vec<u64>) {
        syscall_secp256k1_dbl(
            &mut self.point,
            #[cfg(feature = "hints")]
            hints,
        );
    }

    #[inline(always)]
    fn add(&mut self, q: &'p SyscallPoint256, #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> bool {
        if same_x(&self.point, q) {
            return false;
        }
        let mut params = SyscallSecp256k1AddParams { p1: &mut self.point, p2: q };
        syscall_secp256k1_add(
            &mut params,
            #[cfg(feature = "hints")]
            hints,
        );
        true
    }
}

/// An affine accumulator with an explicit point at infinity, exact on every input.
struct ExactAccumulator {
    point: SyscallPoint256,
    infinity: bool,
}

impl<'p> Accumulator<'p> for ExactAccumulator {
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

    /// The add precompile requires distinct x-coordinates, so `q = ±acc` is handled here.
    #[inline(always)]
    fn add(&mut self, q: &'p SyscallPoint256, #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> bool {
        if self.infinity {
            self.point = *q;
            self.infinity = false;
        } else if same_x(&self.point, q) {
            if self.point.y == q.y {
                syscall_secp256k1_dbl(
                    &mut self.point,
                    #[cfg(feature = "hints")]
                    hints,
                );
            } else {
                self.infinity = true;
            }
        } else {
            let mut params = SyscallSecp256k1AddParams { p1: &mut self.point, p2: q };
            syscall_secp256k1_add(
                &mut params,
                #[cfg(feature = "hints")]
                hints,
            );
        }
        true
    }
}

/// The digits of the four halves and the tables they index.
struct Walk<'a> {
    c0: [u64; 3],
    c1: [u64; 3],
    b1: [u64; 3],
    b2: [u64; 3],
    b1_offsets: &'static [usize; 32],
    b2_offsets: &'static [usize; 32],
    p_table: &'a [SyscallPoint256; 2 * P_TABLE_MID + 1],
    phi_table: &'a [SyscallPoint256; 2 * P_TABLE_MID + 1],
}

impl<'a> Walk<'a> {
    /// Adds the digits at walk position `15·word + k`; those of `k1` sit at every third position.
    #[inline(always)]
    fn add_digits<'p, A: Accumulator<'p>>(
        &'p self,
        acc: &mut A,
        word: usize,
        k: u32,
        with_g: bool,
        #[cfg(feature = "hints")] hints: &mut Vec<u64>,
    ) -> bool {
        let shift = 4 * k;
        if with_g {
            let d = ((self.c0[word] >> shift) & G_MASK) as usize;
            // SAFETY: d < 2^G_WINDOW, the length of the table.
            if d != 0
                && !acc.add(
                    unsafe { G_TABLE.get_unchecked(d) },
                    #[cfg(feature = "hints")]
                    hints,
                )
            {
                return false;
            }
            let d = ((self.c1[word] >> shift) & G_MASK) as usize;
            // SAFETY: d < 2^G_WINDOW, the length of the table.
            if d != 0
                && !acc.add(
                    unsafe { G_SHIFTED_TABLE.get_unchecked(d) },
                    #[cfg(feature = "hints")]
                    hints,
                )
            {
                return false;
            }
        }
        let offset = self.b1_offsets[((self.b1[word] >> shift) & 31) as usize];
        if offset != ZERO_DIGIT
            && !acc.add(
                entry(self.p_table, offset),
                #[cfg(feature = "hints")]
                hints,
            )
        {
            return false;
        }
        let offset = self.b2_offsets[((self.b2[word] >> shift) & 31) as usize];
        offset == ZERO_DIGIT
            || acc.add(
                entry(self.phi_table, offset),
                #[cfg(feature = "hints")]
                hints,
            )
    }

    #[inline(always)]
    fn double4<'p, A: Accumulator<'p>>(acc: &mut A, #[cfg(feature = "hints")] hints: &mut Vec<u64>) {
        for _ in 0..4 {
            acc.double(
                #[cfg(feature = "hints")]
                hints,
            );
        }
    }

    /// Walks positions 32 down to 0 with 128 doublings; `false` if the accumulator stopped it.
    #[inline(always)]
    fn run<'p, A: Accumulator<'p>>(&'p self, acc: &mut A, #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> bool {
        macro_rules! digits {
            ($word:expr, $k:expr, $with_g:expr) => {
                if !self.add_digits(
                    acc,
                    $word,
                    $k,
                    $with_g,
                    #[cfg(feature = "hints")]
                    hints,
                ) {
                    return false;
                }
            };
        }
        macro_rules! double4 {
            () => {
                Self::double4(
                    acc,
                    #[cfg(feature = "hints")]
                    hints,
                )
            };
        }
        digits!(2, 2, false);
        double4!();
        digits!(2, 1, false);
        double4!();
        digits!(2, 0, true);
        for word in [1, 0] {
            for m in (0..5).rev() {
                double4!();
                digits!(word, 3 * m + 2, false);
                double4!();
                digits!(word, 3 * m + 1, false);
                double4!();
                digits!(word, 3 * m, true);
            }
        }
        true
    }

    /// The walk from `OFFSET`, or `None` if it met equal x-coordinates.
    #[inline(always)]
    fn run_offset(&self, #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> Option<SyscallPoint256> {
        let mut acc = OffsetAccumulator { point: OFFSET };
        let complete = self.run(
            &mut acc,
            #[cfg(feature = "hints")]
            hints,
        ) && acc.add(
            &OFFSET_SHIFTED_NEG,
            #[cfg(feature = "hints")]
            hints,
        );
        if complete {
            Some(acc.point)
        } else {
            None
        }
    }

    /// The walk from infinity, or `None` if the result is infinity.
    #[cold]
    #[inline(never)]
    fn run_exact(&self, #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> Option<SyscallPoint256> {
        let mut acc = ExactAccumulator { point: ZERO_POINT, infinity: true };
        self.run(
            &mut acc,
            #[cfg(feature = "hints")]
            hints,
        );
        if acc.infinity {
            None
        } else {
            Some(acc.point)
        }
    }
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
    // k2 = (-1)^σ1·b1 + (-1)^σ2·b2·λ (mod n), b1, b2 < 2^128, checked by the decomposition.
    let (b1, b2, sigma1, sigma2) = glv_decompose_fn_secp256k1(
        k2,
        #[cfg(feature = "hints")]
        hints,
    );
    let tables = PointTables::new(
        p,
        #[cfg(feature = "hints")]
        hints,
    );
    let walk = Walk::new(k1, &b1, &b2, sigma1, sigma2, &tables);
    let q = match walk.run_offset(
        #[cfg(feature = "hints")]
        hints,
    ) {
        Some(q) => q,
        None => walk.run_exact(
            #[cfg(feature = "hints")]
            hints,
        )?,
    };
    Some([q.x[0], q.x[1], q.x[2], q.x[3], q.y[0], q.y[1], q.y[2], q.y[3]])
}

/// `p[8 + d] = [d]p` and `phi[8 + d] = [d]φ(p) = (β·x, y)` for `d ∈ [-8, 8]`, `d ≠ 0`.
struct PointTables {
    p: [SyscallPoint256; 2 * P_TABLE_MID + 1],
    phi: [SyscallPoint256; 2 * P_TABLE_MID + 1],
}

impl PointTables {
    #[inline(always)]
    fn new(p: &[u64; 8], #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> Self {
        // p has prime order n, so no two of [1]p..[8]p share an x-coordinate.
        let mut p_table = [ZERO_POINT; 2 * P_TABLE_MID + 1];
        let mut phi_table = [ZERO_POINT; 2 * P_TABLE_MID + 1];
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
                let mut params = SyscallSecp256k1AddParams { p1: entry, p2: base };
                syscall_secp256k1_add(
                    &mut params,
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
        PointTables { p: p_table, phi: phi_table }
    }
}

impl<'a> Walk<'a> {
    #[inline(always)]
    fn new(
        k1: &[u64; 4],
        b1: &[u64; 4],
        b2: &[u64; 4],
        sigma1: u64,
        sigma2: u64,
        tables: &'a PointTables,
    ) -> Self {
        Walk {
            c0: words(k1[0], k1[1], 0),
            c1: words(k1[2], k1[3], 0),
            b1: booth_words(b1[0], b1[1]),
            b2: booth_words(b2[0], b2[1]),
            b1_offsets: &P_OFFSETS[sigma1 as usize],
            b2_offsets: &P_OFFSETS[sigma2 as usize],
            p_table: &tables.p,
            phi_table: &tables.phi,
        }
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

    /// The order in which `Walk::run` visits (word, k) pairs, as walk positions.
    fn positions() -> Vec<(usize, u32, bool)> {
        let mut out = vec![(2, 2, false), (2, 1, false), (2, 0, true)];
        for word in [1, 0] {
            for m in (0..5u32).rev() {
                out.push((word, 3 * m + 2, false));
                out.push((word, 3 * m + 1, false));
                out.push((word, 3 * m, true));
            }
        }
        out
    }

    #[test]
    fn digits_recompose() {
        let halves = [
            [0, 0],
            [1, 0],
            [u64::MAX, 0],
            [0, u64::MAX],
            [u64::MAX, u64::MAX],
            [0x8000_0000_0000_0000, 1],
            [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210],
        ];
        let walk = positions();
        assert_eq!(walk.len(), 33);
        for h in halves {
            let value = (h[1] as u128) << 64 | h[0] as u128;
            let booth = booth_words(h[0], h[1]);
            let unsigned = words(h[0], h[1], 0);
            for sign in 0..2 {
                let mut acc: i128 = 0;
                for &(word, k, _) in &walk {
                    acc = acc.wrapping_shl(4);
                    let offset = P_OFFSETS[sign][((booth[word] >> (4 * k)) & 31) as usize];
                    acc = acc.wrapping_add((offset / POINT_BYTES) as i128 - P_TABLE_MID as i128);
                }
                let expected = if sign == 0 { value as i128 } else { (value as i128).wrapping_neg() };
                assert_eq!(acc, expected, "booth, sign = {sign}, half = {h:x?}");
            }
            let mut acc: u128 = 0;
            for &(word, k, with_g) in &walk {
                acc = acc.wrapping_shl(4);
                if with_g {
                    acc = acc.wrapping_add(((unsigned[word] >> (4 * k)) & G_MASK) as u128);
                }
            }
            assert_eq!(acc, value, "unsigned, half = {h:x?}");
        }
    }

    /// Points whose multiples meet the walk's table entries: small multiples of G and of 2^128·G.
    fn bases() -> Vec<[u64; 8]> {
        let mut out = Vec::new();
        for d in [1usize, 4095] {
            for t in [&G_TABLE[d], &G_SHIFTED_TABLE[d]] {
                out.push([t.x[0], t.x[1], t.x[2], t.x[3], t.y[0], t.y[1], t.y[2], t.y[3]]);
                let y = neg_y(&t.y);
                out.push([t.x[0], t.x[1], t.x[2], t.x[3], y[0], y[1], y[2], y[3]]);
            }
        }
        out
    }

    /// Scalars with few or repeated digits, and their negations modulo n.
    fn scalars() -> Vec<[u64; 4]> {
        const N: [u64; 4] = super::super::constants::N;
        let mut out = vec![[0u64; 4]];
        for v in [1u64, 3, 9, 4095, u64::MAX] {
            for limb in [0, 2] {
                let mut k = [0u64; 4];
                k[limb] = v;
                out.push(k);
            }
        }
        out.push([1, 0, 1, 0]);
        out.push([u64::MAX, u64::MAX, 0, 0]);
        out.push([0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210, 0x1111_2222_3333_4444, 0x0555_6666_7777_8888]);
        let negated: Vec<[u64; 4]> = out
            .iter()
            .filter(|k| **k != [0; 4])
            .map(|k| {
                let mut r = [0u64; 4];
                let mut borrow = 0u128;
                for i in 0..4 {
                    let d = (N[i] as u128).wrapping_sub(k[i] as u128).wrapping_sub(borrow);
                    r[i] = d as u64;
                    borrow = (d >> 127) & 1;
                }
                r
            })
            .collect();
        out.extend(negated);
        out.into_iter().filter(|k| k.iter().rev().cmp(N.iter().rev()).is_lt()).collect()
    }

    /// The offset walk either stops or agrees with the exact one.
    #[test]
    fn offset_walk_matches_exact_walk() {
        let mut offset_done = 0;
        let mut cases = 0;
        for p in bases() {
            for k1 in scalars() {
                for k2 in scalars() {
                    let (b1, b2, sigma1, sigma2) = glv_decompose_fn_secp256k1(&k2);
                    let tables = PointTables::new(&p);
                    let walk = Walk::new(&k1, &b1, &b2, sigma1, sigma2, &tables);
                    let exact = walk.run_exact().map(|q| (q.x, q.y));
                    if let Some(q) = walk.run_offset() {
                        assert_eq!(Some((q.x, q.y)), exact, "k1 = {k1:x?}, k2 = {k2:x?}, p = {p:x?}");
                        offset_done += 1;
                    }
                    cases += 1;
                }
            }
        }
        assert!(offset_done > cases / 2, "{offset_done} of {cases}");
    }
}
