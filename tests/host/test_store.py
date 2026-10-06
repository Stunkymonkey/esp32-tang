#!/usr/bin/env python3
"""Checks key_store, built for the host as store_host: PBKDF2 against
hashlib, and the stored record against the layout in the design, decrypted
independently with Python's cryptography. Run by run.sh; STORE_HOST is the
driver binary."""
import hashlib
import os
import struct
import subprocess
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DRIVER = os.environ["STORE_HOST"]
# KeyStore::LoadResult
OK, ABSENT, ERROR, NEEDS_PASSWORD, NOT_ENCRYPTED, WRONG_PASSWORD = range(6)
failures = 0


def check(name, ok):
    global failures
    print(("ok   " if ok else "FAIL ") + name)
    failures += not ok


def run(*args):
    out = subprocess.run([DRIVER, *map(str, args)], capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stderr)
        sys.exit(f"{DRIVER} {args[0]} failed with {out.returncode}")
    return out.stdout.split("\n")


def load(record, *password):
    out = run("load", record.hex(), *password)
    return int(out[0]), out[1]


for password, salt, iterations in [("pw", os.urandom(16), 1), ("pässwörd", os.urandom(16), 2),
                                   ("x" * 100, os.urandom(16), 1000), ("p", b"salt", 4096)]:
    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()
    check(f"PBKDF2-HMAC-SHA256, {iterations} iterations", run("pbkdf2", password, salt.hex(), iterations)[0] == expected)

payload = '{"keys":[{"kty":"EC","d":"secret"}]}'

# Encrypted: magic | version 2 | iterations | salt | nonce | ciphertext | tag
record = bytes.fromhex(run("store", payload, "hunter2", 1234)[0])
check("encrypted record layout", record[:4] == b"TANG" and record[4] == 2
      and struct.unpack(">I", record[5:9])[0] == 1234 and len(record) == 37 + len(payload) + 16)
key = hashlib.pbkdf2_hmac("sha256", b"hunter2", record[9:25], 1234)
try:
    decrypted = AESGCM(key).decrypt(record[25:37], record[37:], record[:37]).decode()
except InvalidTag:
    decrypted = None
check("decrypts independently, with bytes 0-36 as additional data", decrypted == payload)
check("no plaintext in the encrypted record", b"secret" not in record)
check("fresh salt and nonce on every store", bytes.fromhex(run("store", payload, "hunter2", 1234)[0])[9:37] != record[9:37])

check("load with the right password", load(record, "hunter2") == (OK, payload))
check("load with a wrong password -> WRONG_PASSWORD", load(record, "hunter3") == (WRONG_PASSWORD, ""))
check("load without a password -> NEEDS_PASSWORD", load(record)[0] == NEEDS_PASSWORD)
for offset, field in [(8, "iteration count"), (40, "ciphertext"), (len(record) - 1, "tag")]:
    tampered = bytearray(record)
    tampered[offset] ^= 1
    check(f"tampered {field} -> WRONG_PASSWORD", load(bytes(tampered), "hunter2")[0] == WRONG_PASSWORD)
zero = bytearray(record)
zero[5:9] = struct.pack(">I", 0)
check("zero iterations -> ERROR", load(bytes(zero), "hunter2")[0] == ERROR)
check("truncated -> ERROR", load(record[:40], "hunter2")[0] == ERROR)

# Plaintext: magic | version 1 | payload
plain = bytes.fromhex(run("store", payload)[0])
check("plaintext record layout", plain == b"TANG\x01" + payload.encode())
check("load plaintext", load(plain) == (OK, payload))
check("plaintext with a password -> NOT_ENCRYPTED", load(plain, "pw")[0] == NOT_ENCRYPTED)
check("unknown format version -> ERROR", load(b"TANG\x07x")[0] == ERROR)
check("wrong magic number -> ERROR", load(b"NOPE\x01{}")[0] == ERROR)

print(f"{failures} failures")
sys.exit(failures != 0)
