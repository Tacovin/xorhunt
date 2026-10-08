import os
import random
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import xorhunt  # noqa: E402


def make_pe(body_size=3000, seed=1):
    """smallest thing that still looks like a real PE to the parser"""
    rnd = random.Random(seed)

    dos = bytearray(0x80)
    dos[0:16] = xorhunt.DOS_HDR
    struct.pack_into("<I", dos, 0x3C, 0x80)
    dos[0x4E:0x4E + len(xorhunt.DOS_MSG)] = xorhunt.DOS_MSG

    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 60, 0x200)

    sect = bytearray(40)
    sect[:5] = b".text"
    struct.pack_into("<IIII", sect, 8, body_size, 0x1000, body_size, 0x200)

    hdr = (bytes(dos) + coff + bytes(opt) + bytes(sect)).ljust(0x200, b"\0")
    return hdr + bytes(rnd.randrange(256) for _ in range(body_size))


def noise(n, seed):
    return random.Random(seed).randbytes(n)


class EmbeddedPE(unittest.TestCase):

    def test_key_lengths(self):
        pe = make_pe()
        for klen in (1, 2, 3, 5, 7, 13, 16):
            with self.subTest(klen=klen):
                rnd = random.Random(klen)
                key = bytes(rnd.randrange(1, 256) for _ in range(klen))
                key = xorhunt.smallest_period(key)
                pre = noise(rnd.randrange(100, 5000), klen)
                blob = pre + xorhunt.xor_with_key(pe, key) + noise(777, 99)

                res = xorhunt.find_embedded_pe(blob)
                self.assertEqual(len(res), 1)
                base, got_key, size, _ = res[0]
                self.assertEqual(base, len(pre))
                self.assertEqual(got_key, key)
                self.assertEqual(size, len(pe))
                self.assertEqual(xorhunt.xor_with_key(blob[base:base + size], got_key), pe)

    def test_plain_pe_inside_file(self):
        pe = make_pe()
        blob = noise(1234, 5) + pe
        res = xorhunt.find_embedded_pe(blob)
        self.assertEqual([r[0] for r in res], [1234])
        self.assertFalse(any(res[0][1]))

    def test_file_itself_not_reported(self):
        self.assertEqual(xorhunt.find_embedded_pe(make_pe()), [])

    def test_two_pes(self):
        a = xorhunt.xor_with_key(make_pe(seed=1), b"\x13\x37")
        b = xorhunt.xor_with_key(make_pe(seed=2), b"secret")
        blob = noise(300, 1) + a + noise(300, 2) + b
        res = xorhunt.find_embedded_pe(blob)
        self.assertEqual([r[1] for r in res], [b"\x13\x37", b"secret"])

    def test_key_too_long(self):
        key = bytes(range(1, 21))
        blob = noise(500, 3) + xorhunt.xor_with_key(make_pe(), key)
        self.assertEqual(xorhunt.find_embedded_pe(blob, max_key=16), [])
        self.assertEqual(len(xorhunt.find_embedded_pe(blob, max_key=20)), 1)

    def test_random_data_is_clean(self):
        self.assertEqual(xorhunt.find_embedded_pe(noise(1 << 20, 42)), [])

    def test_real_exe(self):
        # python.exe on windows is a real PE, skip elsewhere
        with open(sys.executable, "rb") as f:
            exe = f.read()
        if exe[:2] != b"MZ":
            self.skipTest("not on windows")
        blob = noise(4096, 7) + xorhunt.xor_with_key(exe, b"\xde\xad\xbe\xef")
        res = xorhunt.find_embedded_pe(blob)
        self.assertEqual(res[0][0], 4096)
        self.assertEqual(res[0][1], b"\xde\xad\xbe\xef")


class Strings(unittest.TestCase):

    def check(self, encoded, expect, words=None):
        blob = noise(2000, 1) + encoded + b"\0" + noise(2000, 2)
        hits = xorhunt.find_strings(blob, words or xorhunt.DEFAULT_WORDS)
        texts = [h[2] for h in hits]
        self.assertTrue(any(expect in t for t in texts), texts)
        return hits

    def test_xor(self):
        url = b"http://update.example.com/gate.php?id=7"
        enc = url.translate(bytes(b ^ 0x5A for b in range(256)))
        hits = self.check(enc, url.decode())
        self.assertIn("xor 0x5a", [h[1] for h in hits])

    def test_add(self):
        s = b"cmd.exe /c whoami"
        enc = s.translate(bytes((b + 3) & 0xFF for b in range(256)))
        self.check(enc, s.decode())

    def test_rol(self):
        s = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        enc = s.translate(bytes(xorhunt._rol(b, 3) for b in range(256)))
        self.check(enc, s.decode())

    def test_case_flip_ignored(self):
        blob = noise(500, 1) + b"KERNEL32.dll\0" + noise(500, 2)
        hits = xorhunt.find_strings(blob, [b"kernel32"])
        self.assertEqual([h for h in hits if h[1] == "xor 0x20"], [])


class Helpers(unittest.TestCase):

    def test_smallest_period(self):
        self.assertEqual(xorhunt.smallest_period(b"abab"), b"ab")
        self.assertEqual(xorhunt.smallest_period(b"aaaa"), b"a")
        self.assertEqual(xorhunt.smallest_period(b"abc"), b"abc")

    def test_xor_roundtrip(self):
        data = noise(1001, 3)
        key = b"k3y!"
        self.assertEqual(xorhunt.xor_with_key(xorhunt.xor_with_key(data, key), key), data)


if __name__ == "__main__":
    unittest.main()
