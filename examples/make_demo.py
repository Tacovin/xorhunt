"""
Builds demo.bin: some junk, a real exe xored with a 5 byte key, and a couple
of encoded strings, roughly how a lazy dropper stores its payload.

    python examples/make_demo.py C:/Windows/System32/calc.exe
    python xorhunt.py demo.bin -x out
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xorhunt import xor_with_key  # noqa: E402

exe = open(sys.argv[1] if len(sys.argv) > 1 else sys.executable, "rb").read()

url = b"https://cdn-update.example.net/v2/check.php?uid="
run = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

blob = bytearray(os.urandom(3000))
blob += bytes(b ^ 0x37 for b in url + b"\0")
blob += os.urandom(500)
blob += bytes((b + 0x0D) & 0xFF for b in run + b"\0")
blob += os.urandom(1000)
payload_at = len(blob)
blob += xor_with_key(exe, b"\x8b\x1f\x52\xe0\x07")
blob += os.urandom(2000)

open("demo.bin", "wb").write(blob)
print(f"demo.bin: {len(blob)} bytes, payload at {payload_at:#x}")
