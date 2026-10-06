#!/usr/bin/env python3
"""Checks tang_crypto, built for the host as crypto_host, against Python's
cryptography: /adv signatures, /rec exchanges, thumbprints, key parsing and
the stored payload. Run by run.sh; CRYPTO_HOST is the driver binary."""
import json
import os
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# verify_tang.py brings key generation, thumbprints and Base64URL.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import verify_tang as vt  # noqa: E402

DRIVER = os.environ["CRYPTO_HOST"]
failures = 0


def check(name, ok):
    global failures
    print(("ok   " if ok else "FAIL ") + name)
    failures += not ok


def run(keys, *args, body=None):
    """Runs the driver on a {"keys": [...]} payload. Returns the status and
    the remaining output lines."""
    with tempfile.TemporaryDirectory() as tmp:
        keys_file = os.path.join(tmp, "keys.json")
        with open(keys_file, "w") as f:
            json.dump(vt.provision_payload(*keys), f)
        cmd = [DRIVER, keys_file, *args]
        if body is not None:
            body_file = os.path.join(tmp, "body.json")
            with open(body_file, "w") as f:
                f.write(body if isinstance(body, str) else json.dumps(body))
            cmd.append(body_file)
        out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stderr)
        sys.exit(f"{DRIVER} failed with {out.returncode}")
    lines = out.stdout.split("\n")
    return int(lines[0]), lines[1:]


def check_adv(crv, coord_len, hash_alg, sign, exch):
    for thp, expected in [
        ("", 200),
        (vt.jwk_thumbprint(sign), 200),
        (vt.jwk_thumbprint(sign, "sha1"), 200),
        (vt.jwk_thumbprint(sign, "sha512"), 200),
        ("test-signing-key", 200),
        (vt.jwk_thumbprint(exch), 404),
        ("not-a-thumbprint", 404),
    ]:
        status, out = run([sign, exch], "adv", thp)
        ok = status == expected
        if ok and status == 200:
            ok = out[0] == "application/jose+json"
            jws = json.loads(out[1])
            signature = vt.base64url_decode(jws["signature"])
            der = encode_dss_signature(int.from_bytes(signature[:coord_len], "big"),
                                       int.from_bytes(signature[coord_len:], "big"))
            try:
                sign["_pub"].verify(der, f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hash_alg))
            except Exception:
                ok = False
            header = json.loads(vt.base64url_decode(jws["protected"]))
            adv = json.loads(vt.base64url_decode(jws["payload"]))
            ok &= header == {"alg": "ES512" if crv == "P-521" else "ES256", "cty": "jwk-set+json"}
            ok &= len(adv["keys"]) == 2 and all("kid" not in k and "d" not in k for k in adv["keys"])
        check(f"{crv} adv {thp[:16] or '(none)'} -> {expected}", ok)


def check_rec(crv, coord_len, sign, exch):
    curve = ec.SECP521R1() if crv == "P-521" else ec.SECP256R1()
    for hash_name in ["sha256", "sha1", "sha384"]:
        client = ec.generate_private_key(curve)
        nums = client.public_key().public_numbers()
        body = {"kty": "EC", "crv": crv, "x": vt.base64url_encode(nums.x.to_bytes(coord_len, "big")),
                "y": vt.base64url_encode(nums.y.to_bytes(coord_len, "big"))}
        status, out = run([sign, exch], "rec", vt.jwk_thumbprint(exch, hash_name), body=body)
        ok = status == 200 and out[0] == "application/jwk+json"
        if ok:
            resp = json.loads(out[1])
            ok = resp["alg"] == "ECMR" and vt.base64url_decode(resp["x"]) == client.exchange(ec.ECDH(), exch["_pub"])
        check(f"{crv} rec with {hash_name} thumbprint", ok)

    thp = vt.jwk_thumbprint(exch)
    off_curve = dict(body, y=vt.base64url_encode((nums.y + 1).to_bytes(coord_len, "big")))
    check(f"{crv} rec off-curve point -> 400", run([sign, exch], "rec", thp, body=off_curve)[0] == 400)
    check(f"{crv} rec curve mismatch -> 400", run([sign, exch], "rec", thp, body=dict(body, crv="P-384"))[0] == 400)
    check(f"{crv} rec invalid JSON -> 400", run([sign, exch], "rec", thp, body="{nope")[0] == 400)
    check(f"{crv} rec empty body -> 400", run([sign, exch], "rec", thp, body="")[0] == 400)
    check(f"{crv} rec with the signing key -> 404",
          run([sign, exch], "rec", vt.jwk_thumbprint(sign), body=body)[0] == 404)


def check_parse(crv, sign, exch):
    status, out = run([sign, exch], "parse")
    check(f"{crv} parse and thumbprints",
          status == 200 and out[0].split() == [vt.jwk_thumbprint(sign, "sha1"), vt.jwk_thumbprint(sign)])

    mismatched = dict(sign, d=exch["d"])
    without_d = {k: v for k, v in sign.items() if k != "d"}
    by_alg = {k: v for k, v in exch.items() if k != "key_ops"}
    by_alg["alg"] = "ECMR"
    for name, keys, expected in [
        ("d not matching x/y", [mismatched, exch], 400),
        ("a single mismatched key", [mismatched], 400),
        ("only a signing key", [sign], 400),
        ("only an exchange key", [exch], 400),
        ("missing d", [without_d, exch], 400),
        ("kty RSA", [dict(sign, kty="RSA"), exch], 400),
        ("usage from alg instead of key_ops", [sign, by_alg], 200),
    ]:
        status, out = run(keys, "parse")
        check(f"{crv} parse {name} -> {expected}" + (f" ({out[0]})" if status == 400 else ""), status == expected)

    status, out = run([sign, exch], "roundtrip")
    check(f"{crv} stored payload parses back to the same keys ({out[0]} bytes)", status == 200)


for crv, coord_len, hash_alg in [("P-256", 32, hashes.SHA256()), ("P-521", 66, hashes.SHA512())]:
    sign = vt.generate_key(["sign", "verify"], crv, kid="test-signing-key")
    exch = vt.generate_key(["deriveKey"], crv)
    check_parse(crv, sign, exch)
    check_adv(crv, coord_len, hash_alg, sign, exch)
    check_rec(crv, coord_len, sign, exch)

print(f"{failures} failures")
sys.exit(failures != 0)
