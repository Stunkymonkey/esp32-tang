#!/usr/bin/env python3
"""Checks a running ESP32 Tang server against the Tang protocol and the
management API of the ESPHome tang_server component (key_storage: ram).

Every run starts with /wipe, so it replaces whatever the device serves."""
import argparse
import base64
import hashlib
import json
import sys

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ESP_IP = ""  # Will be set via arguments
TOKEN = None  # admin_token, sent as a Bearer token when set
TIMEOUT = 10


def parse_args():
    global ESP_IP, TOKEN
    parser = argparse.ArgumentParser(description='Verify ESP32 Tang Server')
    parser.add_argument('url', help='Base URL of the ESP32 Tang server (e.g., http://192.168.4.1)')
    parser.add_argument('--token', help="the device's admin_token; leave out if none is configured")
    args = parser.parse_args()

    ESP_IP = args.url.rstrip('/')
    if not ESP_IP.startswith("http"):
        ESP_IP = "http://" + ESP_IP
    TOKEN = args.token


def fail(message):
    print(f"FAILED: {message}")
    sys.exit(1)


def request(method, path, expected, json_body=None, token=True):
    """Sends a request and fails unless it returns `expected`.

    Bodies always go through `json=`, so they carry Content-Type and
    Content-Length; a POST without a body still sends Content-Length: 0.
    `token` is True for the configured token, None for no header, or a
    string to send instead."""
    headers = {}
    if token is True:
        token = TOKEN
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.request(method, f"{ESP_IP}{path}", json=json_body, headers=headers, timeout=TIMEOUT)
    except Exception as e:
        fail(f"{method} {path}: {e}")
    if r.status_code != expected:
        fail(f"{method} {path} returned {r.status_code}, expected {expected}: {r.text}")
    return r


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)


def jwk_thumbprint(jwk, hash_name="sha256"):
    """RFC 7638 JWK thumbprint: hash of the required members only, in
    lexicographic order and without whitespace. This is how clevis derives the
    key ID it uses for /rec, so the server must accept the same value."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(',', ':'),
        sort_keys=True
    ).encode('utf-8')
    return base64url_encode(hashlib.new(hash_name, canonical).digest())


def generate_key(ops, curve_name="P-256", kid=None):
    if curve_name == "P-521":
        private_key = ec.generate_private_key(ec.SECP521R1())
        coord_len = 66
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        coord_len = 32

    numbers = private_key.private_numbers()

    # Export raw bytes
    d = numbers.private_value.to_bytes(coord_len, 'big')
    x = numbers.public_numbers.x.to_bytes(coord_len, 'big')
    y = numbers.public_numbers.y.to_bytes(coord_len, 'big')

    key = {
        "key_ops": ops,
        "kty": "EC",
        "crv": curve_name,
        "d": base64url_encode(d),
        "x": base64url_encode(x),
        "y": base64url_encode(y),
        "_priv": private_key,
        "_pub": private_key.public_key()
    }

    # tang's own .jwk files have no "kid"; keys are addressed by thumbprint.
    # An explicit kid is optional and only used by clients that ask for it.
    if kid is not None:
        key["kid"] = kid

    print(f"Generated key for {ops} ({curve_name}): {jwk_thumbprint(key)}")

    return key


def provision_payload(*keys):
    return {"keys": [{k: v for k, v in key.items() if not k.startswith('_')} for key in keys]}


# --- Management API ---

def get_status(token=True):
    r = request("GET", "/status", 200, token=token)
    try:
        status = r.json()
    except ValueError:
        fail(f"/status is not JSON: {r.text}")
    # No private key material, whatever the view.
    if '"d"' in r.text:
        fail(f"/status contains a private key member: {r.text}")
    return status


def check_state(expected):
    state = get_status().get("state")
    if state != expected:
        fail(f"state is '{state}', expected '{expected}'")
    print(f"State: {state}")


def check_public_status():
    """With admin_token, /status without a token shows only the state. Without
    admin_token, it shows the same as with one. A wrong token is refused
    rather than falling back to the public view."""
    print("\n[status] Checking the public /status...")
    public = get_status(token=None)
    if "state" not in public:
        fail(f"/status has no state: {public}")
    if TOKEN is not None:
        if set(public) != {"state"}:
            fail(f"public /status shows more than the state: {public}")
        request("GET", "/status", 401, token="wrong-" + TOKEN)
        print("OK: public view shows only the state, a wrong token gets 401")
    else:
        if public != get_status():
            fail("/status differs between requests without a token")
        print(f"OK: no admin_token, /status is public: {public}")


def check_auth():
    """Every management endpoint refuses a missing or wrong token. The bodies
    would be accepted, so a 401 can only come from the token check."""
    print("\n[auth] Checking that management endpoints need the token...")
    wrong = "wrong-" + TOKEN
    for path in ["/provision", "/deactivate", "/wipe"]:
        body = {"keys": []} if path == "/provision" else None
        request("POST", path, 401, json_body=body, token=None)
        request("POST", path, 401, json_body=body, token=wrong)
        print(f"OK: {path} -> 401 without and with a wrong token")


def check_inactive(sign_key=None, exch_key=None):
    """/adv and /rec answer 503 while no keys are loaded, also for thumbprints
    that were valid before."""
    print("\n[inactive] Checking /adv and /rec answer 503...")
    adv_paths = ["/adv", "/adv/"]
    rec_paths = ["/rec/not-a-thumbprint"]
    if sign_key is not None:
        adv_paths.append(f"/adv/{jwk_thumbprint(sign_key)}")
    if exch_key is not None:
        rec_paths.append(f"/rec/{jwk_thumbprint(exch_key)}")
    for path in adv_paths:
        request("GET", path, 503)
    client = {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
    for path in rec_paths:
        request("POST", path, 503, json_body=client)
    print(f"OK: {', '.join(adv_paths + rec_paths)} -> 503")


def wipe():
    print(f"\n[wipe] Wiping {ESP_IP}...")
    request("POST", "/wipe", 200)
    check_state("unprovisioned")


def deactivate():
    print(f"\n[deactivate] Deactivating {ESP_IP}...")
    request("POST", "/deactivate", 200)
    # With key_storage: ram, RAM holds the only copy.
    check_state("unprovisioned")


# --- Tang protocol ---

def provision(sign_key, exch_key):
    print(f"\n[1] Provisioning keys to {ESP_IP}...")
    r = request("POST", "/provision", 200, json_body=provision_payload(sign_key, exch_key))
    print(f"Response: {r.text}")
    check_state("active")


def verify_second_provision_refused(sign_key, exch_key):
    """Replacing keys always takes a /wipe first."""
    print("\n[1b] Provisioning again without a wipe (expect 409)...")
    r = request("POST", "/provision", 409, json_body=provision_payload(sign_key, exch_key))
    print(f"Refused: {r.text}")


def verify_advertisement(sign_key):
    print(f"\n[2] Fetching advertisement from {ESP_IP}/adv...")
    r = request("GET", "/adv", 200)

    try:
        jws_json = r.json()
        header = jws_json['protected']
        payload = jws_json['payload']
        signature = base64url_decode(jws_json['signature'])
    except Exception as e:
        fail(f"/adv is not a flattened JWS: {e}: {r.text[:200]}")

    signing_input = f"{header}.{payload}".encode('utf-8')

    curve_name = sign_key.get("crv", "P-256")
    if curve_name == "P-521":
        coord_len = 66
        hash_alg = hashes.SHA512()
    else:
        coord_len = 32
        hash_alg = hashes.SHA256()

    r_int = int.from_bytes(signature[:coord_len], 'big')
    s_int = int.from_bytes(signature[coord_len:], 'big')
    try:
        sign_key['_pub'].verify(encode_dss_signature(r_int, s_int), signing_input, ec.ECDSA(hash_alg))
    except Exception as e:
        fail(f"signature verification: {e!r}")
    print("Signature VERIFIED!")

    ctype = r.headers.get('Content-Type', '')
    if ctype != "application/jose+json":
        print(f"WARNING: /adv Content-Type is '{ctype}', tang sends 'application/jose+json'")

    adv = json.loads(base64url_decode(payload))

    # tang advertises the raw JWKs, which carry no "kid". A kid here would
    # be ignored by clevis, which always addresses keys by thumbprint.
    for k in adv.get('keys', []):
        if 'kid' in k:
            print(f"WARNING: advertised key contains a 'kid' ({k['kid']}); tang does not send one")
        if 'd' in k:
            fail("advertisement contains a private key")

    print("Advertisement Payload:")
    print(json.dumps(adv, indent=2))


def verify_advertisement_paths(sign_key, exch_key):
    """clevis fetches "$url/adv/$thp", which is "/adv/" when no thumbprint is
    pinned in its config, so both spellings have to be served. Like tangd, a
    thumbprint that is not a signing key's must yield 404."""
    thp = jwk_thumbprint(sign_key)
    checks = [
        ("/adv", 200),
        ("/adv/", 200),
        (f"/adv/{thp}", 200),
        (f"/adv/{jwk_thumbprint(sign_key, 'sha1')}", 200),
        (f"/adv/{jwk_thumbprint(exch_key)}", 404),
        ("/adv/not-a-thumbprint", 404),
    ]
    for path, expected in checks:
        print(f"\n[2b] Fetching {ESP_IP}{path} (expect {expected}) ...")
        r = request("GET", path, expected)
        print(f"OK ({r.status_code}, {len(r.text)} bytes)")


def verify_mismatched_key_rejected(sign_key, exch_key):
    """A key whose "d" does not belong to its x/y must not be loaded."""
    print(f"\n[0] Provisioning a mismatched key pair to {ESP_IP} (expect 400)...")
    bad = {k: v for k, v in sign_key.items() if not k.startswith('_')}
    bad["d"] = exch_key["d"]
    r = request("POST", "/provision", 400, json_body={"keys": [bad]})
    print(f"Rejected: {r.text}")
    check_state("unprovisioned")


def perform_exchange(exch_key, hash_name="sha256"):
    # clevis computes this thumbprint from the advertised JWK and POSTs to
    # /rec/<thumbprint>; it never uses a "kid". S256 is its default, S1 appears
    # in JWEs written by older versions - tang accepts both.
    kid = jwk_thumbprint(exch_key, hash_name)
    print(f"\n[3] Performing Exchange on {ESP_IP}/rec/{kid} ({hash_name} thumbprint)...")

    curve_name = exch_key.get("crv", "P-256")
    if curve_name == "P-521":
        cli_priv = ec.generate_private_key(ec.SECP521R1())
        coord_len = 66
    else:
        cli_priv = ec.generate_private_key(ec.SECP256R1())
        coord_len = 32

    cli_nums = cli_priv.public_key().public_numbers()
    payload = {
        "kty": "EC",
        "crv": curve_name,
        "x": base64url_encode(cli_nums.x.to_bytes(coord_len, 'big')),
        "y": base64url_encode(cli_nums.y.to_bytes(coord_len, 'big'))
    }

    r = request("POST", f"/rec/{kid}", 200, json_body=payload)

    ctype = r.headers.get('Content-Type', '')
    if ctype != "application/jwk+json":
        print(f"WARNING: /rec Content-Type is '{ctype}', tang sends 'application/jwk+json'")

    resp = r.json()
    print("Received Server Share:", resp)

    if resp.get('alg') != "ECMR":
        print(f"WARNING: /rec reply has alg '{resp.get('alg')}', tang sends 'ECMR'")

    # Expected shared secret, computed locally: ClientPriv * ServerPub.
    # mbedTLS might strip leading zeros, so pad the server's X.
    shared_key = cli_priv.exchange(ec.ECDH(), exch_key['_pub'])
    srv_x = base64url_decode(resp['x']).rjust(len(shared_key), b'\x00')
    if srv_x != shared_key:
        fail(f"shared secret mismatch\nExpected: {shared_key.hex()}\nGot:      {srv_x.hex()}")
    print("Shared Secret VALIDATED! (X coordinate matches)")


def run_test_suite(curve_name, finish):
    print(f"\n{'='*20} Testing Curve: {curve_name} {'='*20}")

    print("Generating Keys...")
    # The signing key carries an explicit kid to cover the optional-kid path;
    # the exchange key has none, matching the .jwk files tang ships.
    sign_key = generate_key(["sign", "verify"], curve_name, kid="test-signing-key")
    exch_key = generate_key(["deriveKey"], curve_name)

    verify_mismatched_key_rejected(sign_key, exch_key)
    provision(sign_key, exch_key)
    verify_second_provision_refused(sign_key, exch_key)
    verify_advertisement(sign_key)
    verify_advertisement_paths(sign_key, exch_key)
    perform_exchange(exch_key, "sha256")
    perform_exchange(exch_key, "sha1")
    get_status()  # the detailed view while keys are loaded, checked for "d"
    finish()
    check_inactive(sign_key, exch_key)
    print(f"{'='*20} {curve_name} Test Complete {'='*20}\n")


if __name__ == "__main__":
    parse_args()
    print(f"Targeting: {ESP_IP} ({'with' if TOKEN else 'without'} admin token)")

    # Ensure fresh state
    wipe()
    check_inactive()
    check_public_status()
    if TOKEN is not None:
        check_auth()

    # /deactivate and /wipe both leave a ram device unprovisioned; use each once.
    run_test_suite("P-256", deactivate)
    run_test_suite("P-521", wipe)

    print("All checks passed.")
