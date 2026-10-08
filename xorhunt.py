#!/usr/bin/env python3
"""
xorhunt - find XOR encoded PE files and obfuscated strings hidden inside
other files (droppers, memory dumps, pcaps, document macros...).

Multi byte keys are recovered with a known plaintext trick instead of brute
force, see find_embedded_pe() for how it works.
"""
import argparse
import os
import struct
import sys

__version__ = "0.3"

# the DOS stub message every MS / mingw linker writes at 0x4E
DOS_MSG = b"This program cannot be run in DOS mode"
DOS_MSG_OFF = 0x4E

# first 16 bytes of a normal DOS header (MZ, 0x90 bytes in last page, ...)
DOS_HDR = bytes.fromhex("4d5a90000300000004000000ffff0000")

PROBES = [(DOS_MSG, DOS_MSG_OFF), (DOS_HDR, 0)]

DEFAULT_WORDS = [
    b"http://", b"https://", b"kernel32", b"ntdll", b"cmd.exe",
    b"powershell", b"SOFTWARE\\Microsoft", b"CurrentVersion\\Run",
    b"VirtualAlloc", b"LoadLibrary", b".onion",
]

MIN_PATTERN = 12


def xor_shift(data, n):
    """data[i] ^ data[i + n] for the whole buffer.

    Done with big ints, a python loop over a few MB takes forever."""
    if n >= len(data):
        return b""
    a = int.from_bytes(data[:-n], "little")
    b = int.from_bytes(data[n:], "little")
    return (a ^ b).to_bytes(len(data) - n, "little")


def xor_with_key(buf, key, phase=0):
    """xor buf with a repeating key, key[phase] lines up with buf[0]"""
    if not buf:
        return b""
    n = len(key)
    rot = key[phase % n:] + key[:phase % n]
    stream = (rot * (len(buf) // n + 1))[:len(buf)]
    x = int.from_bytes(buf, "little") ^ int.from_bytes(stream, "little")
    return x.to_bytes(len(buf), "little")


def smallest_period(key):
    """b'abab' -> b'ab'"""
    for p in range(1, len(key)):
        if len(key) % p == 0 and key[:p] * (len(key) // p) == key:
            return key[:p]
    return key


def find_all(hay, needle):
    i = hay.find(needle)
    while i != -1:
        yield i
        i = hay.find(needle, i + 1)


def parse_pe_header(head):
    """returns (size_on_disk, description) or None if this isn't a sane PE"""
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if lfanew > len(head) - 24 or head[lfanew:lfanew + 4] != b"PE\0\0":
        return None

    machine, nsect = struct.unpack_from("<HH", head, lfanew + 4)
    opt_size = struct.unpack_from("<H", head, lfanew + 20)[0]
    opt = lfanew + 24
    if opt + 64 > len(head):
        return None

    magic = struct.unpack_from("<H", head, opt)[0]
    size_of_headers = struct.unpack_from("<I", head, opt + 60)[0]
    end = size_of_headers

    sh = opt + opt_size
    for i in range(min(nsect, 96)):
        off = sh + i * 40
        if off + 40 > len(head):
            break
        raw_size, raw_ptr = struct.unpack_from("<II", head, off + 16)
        if raw_size:
            end = max(end, raw_ptr + raw_size)

    kind = {0x10b: "PE32", 0x20b: "PE32+"}.get(magic, "PE?")
    arch = {0x14c: "i386", 0x8664: "AMD64", 0xaa64: "ARM64"}.get(machine, hex(machine))
    return end, f"{kind} {arch}, {nsect} sections"


def find_embedded_pe(data, max_key=16):
    """Find PE files xored with a repeating key of up to max_key bytes.

    If plaintext P is xored with a key of length n, then
        C[i] ^ C[i+n] = P[i] ^ P[i+n]
    because the key byte is the same for i and i+n and cancels out. So we
    xor the file with itself shifted by n and look for (P xor P shifted by n)
    of a plaintext we know is in every PE (the DOS stub message). That's a
    plain bytes.find, no brute forcing. Once we have a hit the key is just
    C ^ P at that spot.
    """
    found = {}

    for n in range(1, max_key + 1):
        shifted = xor_shift(data, n)
        for plain, plain_off in PROBES:
            if len(plain) - n < MIN_PATTERN:
                continue
            pattern = xor_shift(plain, n)

            for q in find_all(shifted, pattern):
                base = q - plain_off
                if base < 0 or base in found:
                    continue

                # key byte for file offset base + j is key[j % n]
                key = bytearray(n)
                for i in range(n):
                    key[(plain_off + i) % n] = data[q + i] ^ plain[i]
                key = smallest_period(bytes(key))

                if base == 0 and not any(key):
                    continue  # the file itself is a PE, not interesting

                head = xor_with_key(data[base:base + 0x1000], key)
                info = parse_pe_header(head)
                if not info:
                    continue
                size, desc = info
                size = min(size, len(data) - base)
                found[base] = (key, size, desc)

    return [(base, *found[base]) for base in sorted(found)]


def _rol(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xFF


def diff(data):
    """data[i+1] - data[i] mod 256"""
    return bytes((b - a) & 0xFF for a, b in zip(data, data[1:]))


XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]
SUB_TABLES = [bytes((b - k) & 0xFF for b in range(256)) for k in range(256)]
ROL_TABLES = [bytes(_rol(b, k) for b in range(256)) for k in range(8)]


def _printable(c):
    return 0x20 <= c < 0x7F or c in (9, 10, 13)


def _grow(data, off, length, dec, context):
    """extend a hit both ways while the decoded bytes stay printable"""
    start = off
    while start > 0 and off - start < 64 and _printable(dec[data[start - 1]]):
        start -= 1
    end = off + length
    while end < len(data) and end - off < context and _printable(dec[data[end]]):
        end += 1
    return start, data[start:end].translate(dec).decode("latin-1")


def find_strings(data, words, context=200):
    """XORSearch style search for keywords hidden with single byte xor, add
    or rol. Returns (offset, transform, decoded text).

    Same idea as the PE search: neighbouring bytes xored together cancel a
    single byte xor key, and neighbouring bytes subtracted cancel an add key.
    So all 255 keys of each are covered by one search per keyword."""
    hits = {}
    xd = xor_shift(data, 1)
    ad = diff(data)

    def add(off, w, name, dec):
        raw = data[off:off + len(w)]
        if raw.lower() == w.lower():
            return  # plain text with different case, eg. xor 0x20 on letters
        start, text = _grow(data, off, len(w), dec, context)
        hits.setdefault((start, text), name)

    for w in words:
        if len(w) < 4:
            continue

        for off in find_all(xd, xor_shift(w, 1)):
            k = data[off] ^ w[0]
            if k:
                add(off, w, f"xor {k:#04x}", XOR_TABLES[k])

        for off in find_all(ad, diff(w)):
            k = (data[off] - w[0]) & 0xFF
            if k:
                add(off, w, f"add {k:#04x}", SUB_TABLES[k])

        for k in range(1, 8):
            for off in find_all(data, w.translate(ROL_TABLES[k])):
                add(off, w, f"rol {k}", ROL_TABLES[8 - k])

    return sorted((start, name, text) for (start, text), name in hits.items())


def main(argv=None):
    ap = argparse.ArgumentParser(description="find xor encoded PE files and strings")
    ap.add_argument("file")
    ap.add_argument("-k", "--keyword", action="append",
                    help="string to search for (can repeat), default list if not given")
    ap.add_argument("-m", "--max-key", type=int, default=16,
                    help="longest xor key to try for embedded PEs (default 16)")
    ap.add_argument("-x", "--extract", metavar="DIR",
                    help="write decoded PE files to DIR")
    ap.add_argument("--no-strings", action="store_true")
    ap.add_argument("--no-pe", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    with open(args.file, "rb") as f:
        data = f.read()

    status = 1

    if not args.no_pe:
        pes = find_embedded_pe(data, args.max_key)
        print(f"embedded PE files: {len(pes)}")
        for base, key, size, desc in pes:
            ks = key.hex(" ") if any(key) else "none (plain)"
            print(f"  {base:#010x}  {size:>9} bytes  {desc}  key: {ks}")
            if args.extract:
                os.makedirs(args.extract, exist_ok=True)
                out = os.path.join(args.extract, f"{os.path.basename(args.file)}_{base:08x}.bin")
                with open(out, "wb") as f:
                    f.write(xor_with_key(data[base:base + size], key))
                print(f"    -> {out}")
        if pes:
            status = 0

    if not args.no_strings:
        words = [w.encode() for w in args.keyword] if args.keyword else DEFAULT_WORDS
        hits = find_strings(data, words)
        print(f"\nencoded strings: {len(hits)}")
        for off, name, text in hits:
            print(f"  {off:#010x}  {name:<9}  {text!r}")
        if hits:
            status = 0

    return status


if __name__ == "__main__":
    sys.exit(main())
