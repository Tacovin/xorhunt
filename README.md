# xorhunt

Finds PE files and strings hidden with XOR (and a few other single byte tricks) inside other files: dropper resources, memory dumps, carved network streams, document macros and so on. Pure Python 3, no dependencies, one file, so it's easy to drop into an analysis VM.

```
$ python xorhunt.py demo.bin -x out
embedded PE files: 1
  0x000011f3      27648 bytes  PE32+ AMD64, 6 sections  key: 8b 1f 52 e0 07
    -> out\demo.bin_000011f3.bin

encoded strings: 2
  0x00000bb8  xor 0x37   'https://cdn-update.example.net/v2/check.php?uid='
  0x00000ddd  add 0x0d   'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
```

(`demo.bin` is made by `examples/make_demo.py`: calc.exe xored with a 5 byte key between random junk, plus two encoded strings. The extracted file has the same SHA-256 as the original calc.exe.)

## How it finds multi byte keys without brute force

Brute forcing a 5 byte key is 2^40 tries. But if a plaintext `P` is xored with a repeating key of length `n`:

```
C[i] ^ C[i+n] = (P[i] ^ K[i%n]) ^ (P[i+n] ^ K[i%n]) = P[i] ^ P[i+n]
```

The key cancels out. So for each key length `n` (1 to 16 by default) the file is xored with itself shifted by `n`, and then searched for `P ^ P shifted by n` of a plaintext that every PE has: the `This program cannot be run in DOS mode` stub, or the standard first 16 bytes of the DOS header. That's a plain `bytes.find`, so it runs at C speed. When it hits, the key is just `C ^ P` at that spot. Then the PE header is decoded and checked (`MZ`, `PE\0\0`, section table) before it's reported, and the section table gives the size to carve.

The shifting itself is done by turning the whole buffer into one big Python int and xoring that, a Python loop over a few MB would be way too slow.

The string search uses the same idea for single byte transforms. Neighbouring bytes xored together cancel a 1 byte XOR key, and neighbouring bytes *subtracted* cancel an ADD key, so all 255 keys of each are covered with one search per keyword instead of 255. On a 7.8 MB file (shell32.dll) that took the string search from 21 s to 1.6 s.

## Usage

```
python xorhunt.py FILE [-k KEYWORD ...] [-m MAX_KEY] [-x DIR] [--no-strings] [--no-pe]

  -k, --keyword   string to look for, can be repeated (default: urls, cmd.exe,
                  powershell, Run key, kernel32, VirtualAlloc, ...)
  -m, --max-key   longest xor key to try for embedded PEs (default 16)
  -x, --extract   write decoded PE files to DIR
```

Exit code is 0 if something was found, 1 if not, so it can be used in scripts.

## What it covers

| | |
|---|---|
| embedded PE | xor with a repeating key of 1-16 bytes (more with `-m`), also plain unencoded PEs inside other files |
| strings | single byte xor, add, rol |

## Tests

```
python -m unittest discover -s tests -v
```

Tests build a minimal PE in memory, hide it with keys of different lengths inside random data and check the offset, key, size and decoded bytes. There's also a test with the real `python.exe` on Windows, and one making sure 1 MB of random data gives no false positives.

## Limitations

- rolling / incrementing keys (`key = key + 1` every byte) and RC4 are not covered, that needs actual emulation of the decoder
- the carved size comes from the section table, so an overlay or signature after the last section of the embedded file is not included
- files that use a custom DOS stub and a non standard DOS header won't match either probe

## Related

- Didier Stevens' [XORSearch](https://blog.didierstevens.com/programs/xorsearch/) does the brute force version of the string search and has many more transforms
- [FLOSS](https://github.com/mandiant/flare-floss) for strings that are decoded by the program at runtime
