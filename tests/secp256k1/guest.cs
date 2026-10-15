// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

// Runs every (msg32 | sig64 | recid) record of the input through zkvm_secp256k1_ecrecover and
// publishes keccak256 over (ok | pubkey or 64 zero bytes) per record, then the u32le success
// count. Expected output: test_ecrecover.py --zisk-vectors.
using System.Runtime.InteropServices;

internal static class Accel
{
    [DllImport("__Internal")] internal static extern int zkvm_keccak256(ref byte data, nuint len, ref byte output);
    [DllImport("__Internal")] internal static extern int zkvm_secp256k1_ecrecover(ref byte m, ref byte s, byte recid, ref byte o);
    [DllImport("__Internal")] internal static extern unsafe void read_input(byte** buf, nuint* size);
    [DllImport("__Internal")] internal static extern unsafe void write_output(ulong* output, nuint size);
    [DllImport("__Internal")] internal static extern unsafe void sys_write(uint fd, byte* data, nuint size);
}

internal static class Program
{
    private static unsafe int Main()
    {
        byte* p; nuint n;
        Accel.read_input(&p, &n);
        int count = (int)n / 97;
        byte[] results = new byte[count * 65 + 4];
        byte[] msg = new byte[32], sig = new byte[64], pub = new byte[64];
        int ok = 0;
        for (int i = 0; i < count; i++)
        {
            byte* rec = p + i * 97;
            for (int j = 0; j < 32; j++) msg[j] = rec[j];
            for (int j = 0; j < 64; j++) sig[j] = rec[32 + j];
            for (int j = 0; j < 64; j++) pub[j] = 0;
            int rc = Accel.zkvm_secp256k1_ecrecover(ref msg[0], ref sig[0], rec[96], ref pub[0]);
            results[i * 65] = rc == 0 ? (byte)1 : (byte)0;
            if (rc == 0) { ok++; for (int j = 0; j < 64; j++) results[i * 65 + 1 + j] = pub[j]; }
        }
        int tail = count * 65;
        results[tail] = (byte)ok; results[tail + 1] = (byte)(ok >> 8); results[tail + 2] = (byte)(ok >> 16); results[tail + 3] = (byte)(ok >> 24);
        // ulong storage keeps the buffer 8-byte aligned, as the output window requires.
        ulong* output = stackalloc ulong[4];
        Accel.zkvm_keccak256(ref results[0], (nuint)results.Length, ref *(byte*)output);
        Accel.write_output(output, 32);
        byte* line = stackalloc byte[65];
        for (int i = 0; i < 32; i++)
        {
            byte b = ((byte*)output)[i];
            line[2 * i] = (byte)"0123456789abcdef"[b >> 4];
            line[2 * i + 1] = (byte)"0123456789abcdef"[b & 15];
        }
        line[64] = (byte)'\n';
        Accel.sys_write(1, line, 65);
        return 0;
    }
}
