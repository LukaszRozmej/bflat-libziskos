#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
"""Differential test of zisklib's secp256k1 ecrecover (zkvm_secp256k1_ecrecover) against a
plain Python ECDSA recovery.

The harness (src/main.rs, built by run.sh) compiles zisklib's patched secp256k1 sources with
strict stand-ins for the precompiles: an add with equal x, a point off the curve, at infinity or
non-canonical panics. Vector classes:
  - known vectors (go-ethereum's ecrecover precompile tests),
  - random valid signatures, low- and high-s, wrong parity, hashes of n and above,
  - malformed input: r or s out of range, x off the curve, recovery ids above 1,
  - attacker-chosen u1, u2 and R that walk the accumulator into table points,
    their negations, and infinity.

    test_ecrecover.py HARNESS [--seed N] [--random N]
    test_ecrecover.py --zisk-vectors FILE   write the vectors for guest.cs to FILE and
                                            print the 32-byte digest the guest must output, then exit
"""

import argparse
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72

HERE = Path(__file__).resolve().parent

# ---- Reference -----------------------------------------------------------


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, P)
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, P)
    x = (m * m - a[0] - b[0]) % P
    return x, (m * (a[0] - x) - a[1]) % P


def point_mul(k, a):
    result = None
    for bit in bin(k % N)[2:]:
        result = point_add(result, result)
        if bit == "1":
            result = point_add(result, a)
    return result


def lift_x(x, odd):
    if x >= P:
        return None
    a = (x * x * x + 7) % P
    y = pow(a, (P + 1) // 4, P)
    if y * y % P != a:
        return None
    return (x, y if y % 2 == odd else P - y)


def recover(msg, sig, recid):
    """The public key (x, y), or None where ecrecover must fail. ZisK takes recovery ids 0 and 1."""
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if recid > 1 or not 0 < r < N or not 0 < s < N:
        return None
    big_r = lift_x(r, recid & 1)
    if big_r is None:
        return None
    z = int.from_bytes(msg, "big") % N
    r_inverse = pow(r, -1, N)
    return point_add(point_mul(-z * r_inverse, G), point_mul(s * r_inverse, big_r))


# ---- Vectors -------------------------------------------------------------


def b32(v):
    return v.to_bytes(32, "big")


def signature(z, d, k):
    """(msg, sig, recid) signing z with key d and nonce k, or None if k is unusable."""
    big_r = point_mul(k, G)
    r = big_r[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    if r == 0 or s == 0:
        return None
    return b32(z), b32(r) + b32(s), (big_r[1] & 1) | (2 if big_r[0] >= N else 0)


def high_s(msg, sig, recid):
    s = int.from_bytes(sig[32:], "big")
    return msg, sig[:32] + b32(N - s), recid ^ 1


def chosen(u1, u2, t, odd=0):
    """A vector whose recovery computes u1*G + u2*R for R = t*G (or -t*G).

    The precompile takes any hash and s, so for R = (x, y) with x < n the caller
    picks u1 and u2 outright: s = u2 * r and z = -u1 * r (mod n)."""
    big_r = point_mul(t, G)
    if big_r is None or big_r[0] >= N:
        return None
    if big_r[1] % 2 != odd:
        big_r = (big_r[0], P - big_r[1])
    r = big_r[0]
    s = u2 * r % N
    if s == 0:
        return None
    return b32(-u1 * r % N), b32(r) + b32(s), odd


def geth_vectors():
    # go-ethereum core/vm/testdata/precompiles/ecRecover.json (43b7b4e8): the inputs
    # (hash | v | r | s, the rest ignored) whose v is 27 or 28, with the expected address.
    vectors = [
        ("a8b53bdf3306a35a7103ab5504a0c9b492295564b6202b1942a84ef300107281"
         "000000000000000000000000000000000000000000000000000000000000001b"
         "3078356531653033663533636531386237373263636230303933666637316633"
         "6635336635633735623734646362333161383561613862383839326234653862"
         "1122334455667788991011121314151617181920212223242526272829303132", None),
        ("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
         "000000000000000000000000000000000000000000000000000000000000001c"
         "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
         "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
         "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"),
    ]
    out = []
    for hex_input, address in vectors:
        data = bytes.fromhex(hex_input)
        out.append(((data[:32], data[64:128], data[63] - 27), address))
    return out


def malformed(rng):
    d, k, z = rng.randrange(1, N), rng.randrange(1, N), rng.randrange(N)
    msg, sig, recid = signature(z, d, k)
    r, s = sig[:32], sig[32:]
    yield msg, b32(0) + s, recid
    yield msg, r + b32(0), recid
    yield msg, b32(N) + s, recid
    yield msg, r + b32(N), recid
    yield msg, b32(2**256 - 1) + s, recid
    yield msg, r + b32(2**256 - 1), recid
    yield msg, b32(N - 1) + s, recid
    yield msg, r + b32(N - 1), recid
    for bad in (2, 3, 4, 5, 27, 28, 255):
        yield msg, sig, bad
    # r whose x is off the curve.
    while True:
        x = rng.randrange(1, N)
        if lift_x(x, 0) is None:
            yield msg, b32(x) + s, 0
            yield msg, b32(x) + s, 1
            break
    # Hashes of n and above reduce mod n.
    for z in (0, N - 1, N, N + 1, N + 2, 2**256 - 1):
        yield b32(z), sig, recid
        yield b32(z), sig, recid ^ 1


def adversarial(rng):
    lam2 = LAMBDA * LAMBDA % N
    small = list(range(1, 18)) + [127, 128, 129, 255, 256, 257]
    specials = small + [N - v for v in small] + [LAMBDA, N - LAMBDA, lam2, N - lam2, LAMBDA + 1, LAMBDA - 1,
                                                 2**128, 2**128 - 1, 2**128 + 1, 2**129, N // 2, N // 2 + 1]
    ts = [1, 2, 3, 5, 15, 16, 17, 127, N - 1, N - 2, N - 3, N - 15, LAMBDA, N - LAMBDA, lam2, LAMBDA * 3 % N]
    for t in ts:
        for odd in (0, 1):
            for _ in range(10):
                u1 = rng.choice(specials)
                u2 = rng.choice(specials)
                yield chosen(u1, u2, t, odd)
            for u2 in (1, 2, 3, LAMBDA, N - 1):
                # Q = infinity, and neighbours of it.
                for delta in (0, 1, N - 1, 2, LAMBDA):
                    sign = 1 if odd == (point_mul(t, G)[1] & 1) else -1
                    yield chosen((-u2 * t * sign + delta) % N, u2, t, odd)
            yield chosen(0, rng.randrange(1, N), t, odd)
            # Small multiples of G, 2^128 G, R and lambda R: partial sums meet table entries.
            for _ in range(10):
                u1 = (rng.randrange(-300, 300) + rng.randrange(-300, 300) * 2**128) % N
                u2 = (rng.randrange(-300, 300) + rng.randrange(-300, 300) * LAMBDA) % N
                yield chosen(u1, u2, t, odd)
    for _ in range(40):
        t = rng.randrange(1, N)
        u2 = rng.randrange(1, N)
        yield chosen(-u2 * t % N, u2, t)


def random_valid(rng, count):
    for _ in range(count):
        d, k, z = rng.randrange(1, N), rng.randrange(1, N), rng.randrange(2**256)
        vector = signature(z % N, d, k)
        if vector is None:
            continue
        msg = b32(z)
        yield (msg,) + vector[1:]
        yield high_s(msg, vector[1], vector[2])
        # A wrong parity recovers a different key and must agree with the reference too.
        yield msg, vector[1], vector[2] ^ 1
        # A hash of n or more signs its residue.
        z = rng.randrange(2**256 - N)
        vector = signature(z, d, k)
        if vector is not None:
            yield b32(z + N), vector[1], vector[2]


def random_garbage(rng, count):
    for _ in range(count):
        yield b32(rng.randrange(2**256)), b32(rng.randrange(1, N)) + b32(rng.randrange(1, N)), rng.randrange(4)


def replay_regressions():
    # These inputs force equal coordinates at offset removal and at the last phi(R) addition,
    # respectively. Both recover non-infinity keys, but an offset/replay walk doubles its work.
    vectors = [
        ("3f3f0c5de03c2b42f763614056d5a22211e74851da205e2ce72f2095c6bd9417",
         "49e5474bedb5c8daf98555048d06c774b3cb3a37ec558d88c2dff40f4d12ab016"
         "6c8f78e75526783d17996ce78241f8a031a3b76c36040980e5814843a1ab035", 0),
        ("23b04ce8c9b278d364a800a8d73aff4d7b3e822d01d36b0057524c772dc595e2",
         "60deef56c73e4820f97071b2b89c53cf49822c4e0740cfa794c56e331ba3bbbf"
         "cc1c1f1dabe4cdb4096b143cacff6f3ec2722529034151b7d5e3c5dfc0dd06a5", 1),
    ]
    return [(bytes.fromhex(msg), bytes.fromhex(sig), recid) for msg, sig, recid in vectors]


# ---- Driver --------------------------------------------------------------


def run(exe, commands):
    result = subprocess.run([str(exe)], input="".join(commands), capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"harness failed ({result.returncode}): {result.stderr.strip()}")
    lines = result.stdout.splitlines()
    if len(lines) != len(commands):
        sys.exit(f"harness returned {len(lines)} results for {len(commands)} commands")
    return lines


def all_vectors(rng, count):
    cases = [(v, None) for v in malformed(rng)]
    cases += [(v, None) for v in adversarial(rng) if v is not None]
    cases += [(v, None) for v in replay_regressions()]
    first_random = len(cases)
    cases += [(v, None) for v in random_valid(rng, count)]
    random_range = range(first_random, len(cases))
    cases += [(v, None) for v in random_garbage(rng, count)]
    cases += geth_vectors()
    return cases, random_range


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("harness", type=Path, nargs="?")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--random", type=int, default=150)
    parser.add_argument("--zisk-vectors", type=Path)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    if args.zisk_vectors:
        write_zisk_vectors(rng, args.zisk_vectors, args.random)
        return

    cases, random_range = all_vectors(rng, args.random)
    known_inputs = {v for v, a in cases if a is not None}
    replay_inputs = set(replay_regressions())

    failures = 0
    stats = []
    expected = [recover(*v) for v, _ in cases]
    commands = [f"recover {m.hex()} {s.hex()} {r}\n" for (m, s, r), _ in cases]
    for index, (((msg, sig, recid), address), want, line) in enumerate(zip(cases, expected, run(args.harness, commands))):
        fields = line.split()
        if fields[0] == "panic":
            failures += 1
            print(f"PANIC msg={msg.hex()} sig={sig.hex()} recid={recid}: {line}")
            continue
        got = None if fields[0] == "fail" else (int(fields[1][:64], 16), int(fields[1][64:], 16))
        if got != want:
            failures += 1
            print(f"MISMATCH msg={msg.hex()} sig={sig.hex()} recid={recid}\n  got  {got}\n  want {want}")
        if (msg, sig, recid) in replay_inputs:
            doubles, adds = map(int, fields[-3:-1])
            if doubles > 140 or adds > 100:
                failures += 1
                print(f"REPLAY REGRESSION msg={msg.hex()}: {doubles} doubles, {adds} adds")
        if (msg, sig, recid) in known_inputs:
            from_got = None if got is None else address_of(got)
            if from_got != address:
                failures += 1
                print(f"KNOWN VECTOR {address}: got {from_got}")
        if got is not None and index in random_range:
            stats.append(tuple(int(v) for v in fields[-3:]))

    if stats:
        k = len(stats)
        print(f"{k} random signatures: mean {sum(d for d, _, _ in stats) / k:.1f} doubles, "
              f"{sum(a for _, a, _ in stats) / k:.1f} adds, {sum(r for _, _, r in stats) / k:.1f} arith256_mod")
    print(f"{len(cases)} vectors: {'FAILED' if failures else 'OK'} ({failures} failures)")
    sys.exit(1 if failures else 0)


def write_zisk_vectors(rng, path, count):
    """Records (msg | sig | recid) for the vector guest, which outputs keccak256 over
    (ok | pubkey or zeros) per record followed by the u32le number of successes."""
    cases, _ = all_vectors(rng, count)
    data, results, ok = bytearray(), bytearray(), 0
    for (msg, sig, recid), _ in cases:
        data += msg + sig + bytes([recid & 0xFF])
        point = recover(msg, sig, recid)
        if point is None:
            results += bytes(65)
        else:
            ok += 1
            results += bytes([1]) + b32(point[0]) + b32(point[1])
    path.write_bytes(bytes(data))
    print(f"{len(cases)} records, {ok} recover: {keccak256(bytes(results) + ok.to_bytes(4, 'little')).hex()}")


def address_of(point):
    return keccak256(b32(point[0]) + b32(point[1]))[12:].hex()


def keccak256(data):
    """Keccak-256 (the pre-NIST padding Ethereum uses), for the known-vector addresses."""
    rate = 136
    state = [0] * 25
    data = bytearray(data) + b"\x01"
    data += b"\x00" * (-len(data) % rate)
    data[-1] |= 0x80
    rotations = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
    constants = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
                 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
                 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    mask = 2**64 - 1

    def rotl(v, n):
        return ((v << n) | (v >> (64 - n))) & mask if n else v

    for offset in range(0, len(data), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(data[offset + 8 * i:offset + 8 * i + 8], "little")
        for rc in constants:
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
            state = [state[i] ^ d[i % 5] for i in range(25)]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], rotations[x + 5 * y])
            state = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
            state[0] ^= rc
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


class DriverTests(unittest.TestCase):
    def test_harness_result_count(self):
        commands = ["recover first\n", "recover second\n"]
        for count in (0, 1, 2, 3):
            with self.subTest(count=count):
                result = subprocess.CompletedProcess([], 0, stdout="fail 1 0 0 0\n" * count)
                with patch.object(subprocess, "run", return_value=result):
                    if count == len(commands):
                        self.assertEqual(run(Path("harness"), commands), ["fail 1 0 0 0"] * count)
                    else:
                        with self.assertRaises(SystemExit):
                            run(Path("harness"), commands)

    def test_keccak_padding_boundaries(self):
        # Keccak-256 of zero bytes, cross-checked with PyCryptodome.
        vectors = [
            (0, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (134, "20926439d7d1663c4d224931643bb513f3ebf181ab353278b24399f518dc5f97"),
            (135, "29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e"),
            (136, "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9"),
            (271, "3bb611e98ca876adc01436a582979ecfd012389033aca7dbf76dcb424fe02a0c"),
        ]
        for length, expected in vectors:
            with self.subTest(length=length):
                self.assertEqual(keccak256(bytes(length)).hex(), expected)


if __name__ == "__main__":
    main()
