// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Host harness for run.sh: compiles zisklib's secp256k1 sources as they are, with strict
//! stand-ins for the ZisK precompiles and free-input calls. A stand-in panics on any input the precompile would not
//! prove (an add with equal x, a point off the curve or at infinity, a non-canonical coordinate).
//!
//! stdin:  recover <msg32 hex> <sig64 hex> <recid>
//! stdout: ok <pubkey64 hex> <dbl> <add> <arith>   |   fail <code> <dbl> <add> <arith>   |   panic <message>
#![allow(dead_code, unused_imports, unexpected_cfgs)]
extern crate alloc;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub static DBL: AtomicU64 = AtomicU64::new(0);
pub static ADD: AtomicU64 = AtomicU64::new(0);
pub static ARITH: AtomicU64 = AtomicU64::new(0);

pub fn big(v: &[u64]) -> BigUint {
    let mut r = BigUint::zero();
    for &l in v.iter().rev() {
        r = (r << 64) + BigUint::from(l);
    }
    r
}

pub fn limbs(v: &BigUint) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, d) in v.to_u64_digits().iter().enumerate() {
        assert!(i < 4, "value exceeds 256 bits");
        out[i] = *d;
    }
    out
}

pub fn field_p() -> BigUint {
    (BigUint::one() << 256) - (BigUint::one() << 32) - BigUint::from(977u32)
}

pub fn order_n() -> BigUint {
    BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

pub mod syscalls {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct SyscallPoint256 {
        pub x: [u64; 4],
        pub y: [u64; 4],
    }

    #[repr(C)]
    pub struct SyscallSecp256k1AddParams<'a> {
        pub p1: &'a mut SyscallPoint256,
        pub p2: &'a SyscallPoint256,
    }

    pub struct SyscallArith256ModParams<'a> {
        pub a: &'a [u64; 4],
        pub b: &'a [u64; 4],
        pub c: &'a [u64; 4],
        pub module: &'a [u64; 4],
        pub d: &'a mut [u64; 4],
    }

    fn check_point(what: &str, p: &SyscallPoint256) -> (BigUint, BigUint) {
        let fp = field_p();
        let (x, y) = (big(&p.x), big(&p.y));
        assert!(x < fp && y < fp, "PRECONDITION {what}: non-canonical point");
        assert!(!(x.is_zero() && y.is_zero()), "PRECONDITION {what}: point at infinity");
        let lhs = &y * &y % &fp;
        let rhs = (&x * &x * &x + BigUint::from(7u32)) % &fp;
        assert!(lhs == rhs, "PRECONDITION {what}: point off the curve");
        (x, y)
    }

    fn inv(v: &BigUint, m: &BigUint) -> BigUint {
        v.modpow(&(m - BigUint::from(2u32)), m)
    }

    fn store(p: &mut SyscallPoint256, x: BigUint, y: BigUint) {
        p.x = limbs(&x);
        p.y = limbs(&y);
    }

    pub fn syscall_secp256k1_add(params: &mut SyscallSecp256k1AddParams) {
        ADD.fetch_add(1, Relaxed);
        let fp = field_p();
        let (x1, y1) = check_point("add", params.p1);
        let (x2, y2) = check_point("add", params.p2);
        assert!(x1 != x2, "PRECONDITION add: equal x");
        let m = ((&y2 + &fp - &y1) % &fp) * inv(&((&x2 + &fp - &x1) % &fp), &fp) % &fp;
        let x3 = (&m * &m + &fp * 2u32 - &x1 - &x2) % &fp;
        let y3 = (&m * ((&x1 + &fp - &x3) % &fp) + &fp - &y1) % &fp;
        store(params.p1, x3, y3);
    }

    pub fn syscall_secp256k1_dbl(p: &mut SyscallPoint256) {
        DBL.fetch_add(1, Relaxed);
        let fp = field_p();
        let (x1, y1) = check_point("dbl", p);
        let m = BigUint::from(3u32) * &x1 * &x1 % &fp * inv(&(&y1 * 2u32 % &fp), &fp) % &fp;
        let x3 = (&m * &m + &fp * 2u32 - &x1 * 2u32) % &fp;
        let y3 = (&m * ((&x1 + &fp - &x3) % &fp) + &fp - &y1) % &fp;
        store(p, x3, y3);
    }

    pub fn syscall_arith256_mod(params: &mut SyscallArith256ModParams) {
        ARITH.fetch_add(1, Relaxed);
        let m = big(params.module);
        assert!(!m.is_zero(), "PRECONDITION arith256_mod: zero module");
        let r = (big(params.a) * big(params.b) + big(params.c)) % m;
        *params.d = limbs(&r);
    }
}

pub mod zisklib {
    use super::*;
    pub use crate::secp::*;

    pub const ZERO_256: [u64; 4] = [0, 0, 0, 0];
    pub const ONE_256: [u64; 4] = [1, 0, 0, 0];
    pub const TWO_256: [u64; 4] = [2, 0, 0, 0];

    pub fn gt(x: &[u64], y: &[u64]) -> bool {
        big(x) > big(y)
    }
    pub fn lt(x: &[u64], y: &[u64]) -> bool {
        big(x) < big(y)
    }
    pub fn eq(x: &[u64], y: &[u64]) -> bool {
        x == y
    }
    pub fn is_zero(x: &[u64]) -> bool {
        x.iter().all(|&w| w == 0)
    }
    pub fn is_one(x: &[u64]) -> bool {
        x[0] == 1 && x[1..].iter().all(|&w| w == 0)
    }
    pub fn is_two(x: &[u64]) -> bool {
        x[0] == 2 && x[1..].iter().all(|&w| w == 0)
    }

    pub fn be_bytes_to_u64_4(bytes: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        ]
    }

    pub fn u64_4_to_be_bytes(limbs: &[u64; 4]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&limbs[3 - i].to_be_bytes());
        }
        out
    }

    fn msb(values: &[&[u64; 4]]) -> (u64, u64) {
        for limb in (0..4).rev() {
            let word = values.iter().map(|v| v[limb]).max().unwrap();
            if word != 0 {
                return (limb as u64, 63 - word.leading_zeros() as u64);
            }
        }
        panic!("msb of zero");
    }
    pub fn fcall_msb_pos_256(x: &[u64; 4]) -> (u64, u64) {
        msb(&[x])
    }
    pub fn fcall_msb_pos_256_2(x: &[u64; 4], y: &[u64; 4]) -> (u64, u64) {
        msb(&[x, y])
    }
    pub fn fcall_msb_pos_256_4(a: &[u64; 4], b: &[u64; 4], c: &[u64; 4], d: &[u64; 4]) -> (u64, u64) {
        msb(&[a, b, c, d])
    }

    pub fn fcall_secp256k1_fn_inv(x: &[u64; 4]) -> [u64; 4] {
        let n = order_n();
        limbs(&big(x).modpow(&(&n - BigUint::from(2u32)), &n))
    }
    pub fn fcall_secp256k1_fp_inv(x: &[u64; 4]) -> [u64; 4] {
        let p = field_p();
        limbs(&big(x).modpow(&(&p - BigUint::from(2u32)), &p))
    }
    pub fn fcall_secp256k1_fp_sqrt(x: &[u64; 4], parity: u64) -> [u64; 5] {
        let p = field_p();
        let e = (&p + BigUint::one()) >> 2;
        let a = big(x);
        let mut s = a.modpow(&e, &p);
        let mut out = [0u64; 5];
        if &s * &s % &p != a {
            let a3 = a * BigUint::from(3u32) % &p;
            out[1..5].copy_from_slice(&limbs(&a3.modpow(&e, &p)));
            return out;
        }
        if limbs(&s)[0] & 1 != parity {
            s = (&p - &s) % &p;
        }
        out[0] = 1;
        out[1..5].copy_from_slice(&limbs(&s));
        out
    }

    /// The same lattice split as zisk's fcall: k = (-1)^σ1·k1 + (-1)^σ2·k2·λ, |k1|, |k2| < 2^128.
    pub fn fcall_secp256k1_glv_decompose(k: &[u64; 4]) -> [u64; 10] {
        use num_bigint::{BigInt, Sign};
        use num_traits::Signed;
        let n = BigInt::from(order_n());
        let a1 = BigInt::parse_bytes(b"3086D221A7D46BCDE86C90E49284EB15", 16).unwrap();
        let minus_b1 = BigInt::parse_bytes(b"E4437ED6010E88286F547FA90ABFE4C3", 16).unwrap();
        let a2 = BigInt::parse_bytes(b"114CA50F7A8E2F3F657C1108D9D44CFD8", 16).unwrap();
        let b2 = a1.clone();
        let round = |num: BigInt| -> BigInt {
            let two_den = &n << 1;
            if num.is_negative() {
                let q: BigInt = (-num * 2 + &n) / &two_den;
                -q
            } else {
                (num * 2 + &n) / &two_den
            }
        };
        let kk = BigInt::from(big(k));
        let c1 = round(&b2 * &kk);
        let c2 = round(&minus_b1 * &kk);
        let k1 = &kk - &c1 * &a1 - &c2 * &a2;
        let k2 = &c1 * &minus_b1 - &c2 * &b2;
        let mut out = [0u64; 10];
        let (s1, m1) = k1.into_parts();
        let (s2, m2) = k2.into_parts();
        out[0..4].copy_from_slice(&limbs(&m1));
        out[4..8].copy_from_slice(&limbs(&m2));
        out[8] = (s1 == Sign::Minus) as u64;
        out[9] = (s2 == Sign::Minus) as u64;
        out
    }
}

pub mod secp {
    mod constants;
    mod curve;
    mod ecdsa;
    mod field;
    mod g_tables;
    mod glv;
    mod scalar;
    mod straus;

    pub use curve::*;
    pub use ecdsa::*;
    pub use field::*;
    pub use glv::*;
    pub use scalar::*;
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        assert_eq!(f[0], "recover");
        let msg = hex(f[1]);
        let sig = hex(f[2]);
        let recid: u8 = f[3].parse().unwrap();
        DBL.store(0, Relaxed);
        ADD.store(0, Relaxed);
        ARITH.store(0, Relaxed);
        let result = std::panic::catch_unwind(|| {
            let mut output = [0u8; 64];
            let code = unsafe { secp::secp256k1_ecdsa_recover_c(sig.as_ptr(), recid, msg.as_ptr(), output.as_mut_ptr()) };
            (code, output)
        });
        let counts = format!("{} {} {}", DBL.load(Relaxed), ADD.load(Relaxed), ARITH.load(Relaxed));
        match result {
            Ok((0, output)) => {
                let h: String = output.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(out, "ok {h} {counts}").unwrap();
            }
            Ok((code, _)) => writeln!(out, "fail {code} {counts}").unwrap(),
            Err(e) => {
                let m = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                writeln!(out, "panic {}", m.replace('\n', " ")).unwrap();
            }
        }
    }
}
