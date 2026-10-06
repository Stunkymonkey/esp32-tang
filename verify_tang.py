#!/usr/bin/env python3
"""Checks a running ESP32 Tang server against the Tang protocol and the
management API of the ESPHome tang_server component.

Every run starts with /wipe, so it replaces whatever the device serves and
erases the keys it has stored."""
import argparse
import base64
import hashlib
import json
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ESP_IP = ""  # Will be set via arguments
TOKEN = None  # admin_token, sent as a Bearer token when set
STORAGE = "ram"  # the device's key_storage
PASSWORD = None  # the key password of a require_password device
CHECK_REBOOT = False
CHECK_LOCKOUT = False
CHECK_TIMERS = False
TIMEOUT = 10


def parse_args():
    global ESP_IP, TOKEN, STORAGE, PASSWORD, CHECK_REBOOT, CHECK_LOCKOUT, CHECK_TIMERS
    parser = argparse.ArgumentParser(description='Verify ESP32 Tang Server')
    parser.add_argument('url', help='Base URL of the ESP32 Tang server (e.g., http://192.168.4.1)')
    parser.add_argument('--token', help="the device's admin_token; leave out if none is configured")
    parser.add_argument('--storage', choices=['ram', 'nvs'],
                        help="the device's key_storage (default: ram, or nvs with --password)")
    parser.add_argument('--password',
                        help='key password for a require_password device; implies --storage nvs. '
                             'The first /activate of each run sets it.')
    parser.add_argument('--check-reboot', action='store_true',
                        help='ask for a power cycle and check which keys survive it')
    parser.add_argument('--check-lockout', action='store_true',
                        help='check the auth backoff and lockout; needs --token, and locks the device '
                             'for its configured lockout time')
    parser.add_argument('--check-timers', action='store_true',
                        help='check max_active_time and idle_timeout; takes as long as they are set to')
    args = parser.parse_args()
    if args.check_lockout and args.token is None:
        parser.error('--check-lockout needs --token')
    CHECK_LOCKOUT = args.check_lockout
    CHECK_TIMERS = args.check_timers
    PASSWORD = args.password
    if PASSWORD is not None and args.storage == 'ram':
        parser.error('--password needs --storage nvs')
    STORAGE = args.storage or ('nvs' if PASSWORD is not None else 'ram')
    CHECK_REBOOT = args.check_reboot

    ESP_IP = args.url.rstrip('/')
    if not ESP_IP.startswith("http"):
        ESP_IP = "http://" + ESP_IP
    TOKEN = args.token


def fail(message):
    print(f"FAILED: {message}")
    sys.exit(1)


def send(method, path, json_body=None, token=True, timeout=TIMEOUT):
    """Sends a request and returns the response, whatever its status.

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
        return requests.request(method, f"{ESP_IP}{path}", json=json_body, headers=headers, timeout=timeout)
    except Exception as e:
        fail(f"{method} {path}: {e}")


def request(method, path, expected, json_body=None, token=True, timeout=TIMEOUT):
    """Sends a request and fails unless it returns `expected`."""
    r = send(method, path, json_body, token, timeout)
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


def wait_out_backoff(method="GET", path="/status", json_body=None):
    """After a failed secret, the device refuses the next attempt for a
    while (auth_backoff). Waits until a request that checks the same secret
    is no longer refused. The default, /status with the token, also resets
    the token's failure count; without admin_token it is never refused."""
    while True:
        r = send(method, path, json_body)
        if r.status_code != 429:
            return r
        wait = int(r.headers.get("Retry-After", "1"))
        print(f"Auth backoff: waiting {wait} s")
        time.sleep(wait)


def wait_out_password_backoff():
    """/activate without a password checks the password backoff but no
    password, so it never counts as a failure."""
    wait_out_backoff("POST", "/activate")


def thumbprints(*keys):
    """What /status lists for the given keys."""
    return sorted((jwk_thumbprint(k, "sha1"), jwk_thumbprint(k), "sign" if "sign" in k["key_ops"] else "exchange",
                   k["crv"]) for k in keys)


def check_detailed_status(state, keys):
    """The detailed /status: the configuration, the keys it lists (none, or
    the given ones) and the timers and counters."""
    status = get_status()
    for field in ["state", "key_storage", "require_password", "flash_encryption", "nvs_encryption", "admin_token", "keys",
                  "active_since_s", "deactivates_in_s", "idle_deactivates_in_s", "auth_failures",
                  "lockout_remaining_s", "counters"]:
        if field not in status:
            fail(f"detailed /status has no {field}: {status}")
    expected = {
        "state": state,
        "key_storage": STORAGE,
        "require_password": PASSWORD is not None,
        "admin_token": TOKEN is not None,
    }
    for field, value in expected.items():
        if status[field] != value:
            fail(f"/status {field} is {status[field]!r}, expected {value!r}")
    listed = sorted((k["thp"]["S1"], k["thp"]["S256"], k["use"], k["crv"]) for k in status["keys"])
    if listed != thumbprints(*keys):
        fail(f"/status lists keys {listed}, expected {thumbprints(*keys)}")
    if (status["active_since_s"] is None) != (state != "active"):
        fail(f"/status active_since_s is {status['active_since_s']} while {state}")
    if set(status["counters"]) != {"activation", "recovery", "adv", "auth_failure"}:
        fail(f"/status counters: {status['counters']}")
    print(f"Detailed status OK: {state}, {len(keys)} keys, flash_encryption={status['flash_encryption']}")
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
        wait_out_backoff()
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
        wait_out_backoff()
        request("POST", path, 401, json_body=body, token=wrong)
        wait_out_backoff()
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


def deactivate(expected_state):
    print(f"\n[deactivate] Deactivating {ESP_IP} (expect {expected_state})...")
    request("POST", "/deactivate", 200)
    check_state(expected_state)


def activate_request(expected, password=None):
    """/activate, with a password in the body if one is given. With
    require_password it runs PBKDF2, which takes seconds."""
    body = None if password is None else {"password": password}
    start = time.monotonic()
    r = request("POST", "/activate", expected, json_body=body, timeout=120)
    print(f"/activate -> {r.status_code} in {time.monotonic() - start:.1f} s: {r.text}")
    return r


def activate():
    print(f"\n[activate] Activating {ESP_IP}...")
    activate_request(200, PASSWORD)
    check_state("active")


# --- Tang protocol ---

def provision(sign_key, exch_key):
    """Provisioning activates directly with ram. With nvs, the keys wait in
    RAM, unserved, until the first /activate stores them."""
    print(f"\n[1] Provisioning keys to {ESP_IP}...")
    r = request("POST", "/provision", 200, json_body=provision_payload(sign_key, exch_key))
    print(f"Response: {r.text}")
    check_detailed_status("active" if STORAGE == "ram" else "pending", [sign_key, exch_key])


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


def verify_serving(sign_key, exch_key):
    verify_advertisement(sign_key)
    verify_advertisement_paths(sign_key, exch_key)
    perform_exchange(exch_key, "sha256")
    perform_exchange(exch_key, "sha1")


def provision_and_activate_nvs(sign_key, exch_key):
    """The nvs path from provision to the first activation, with the
    checks along the way."""
    provision(sign_key, exch_key)
    check_inactive(sign_key, exch_key)
    verify_second_provision_refused(sign_key, exch_key)

    print("\n[1c] Deactivating while pending drops the keys...")
    deactivate("unprovisioned")
    request("POST", "/activate", 409)
    provision(sign_key, exch_key)

    if PASSWORD is None:
        print("\n[1d] Activating with a password on a device without require_password (expect 400)...")
        activate_request(400, "not-expected")
    else:
        print("\n[1d] Activating without a password on a require_password device (expect 400)...")
        activate_request(400)
    check_state("pending")

    activate()
    request("POST", "/activate", 409)


def run_test_suite(curve_name):
    print(f"\n{'='*20} Testing Curve: {curve_name} {'='*20}")

    print("Generating Keys...")
    # The signing key carries an explicit kid to cover the optional-kid path;
    # the exchange key has none, matching the .jwk files tang ships.
    sign_key = generate_key(["sign", "verify"], curve_name, kid="test-signing-key")
    exch_key = generate_key(["deriveKey"], curve_name)

    verify_mismatched_key_rejected(sign_key, exch_key)
    if STORAGE == "ram":
        print("\n[1a] /activate with ram storage (expect 404)...")
        request("POST", "/activate", 404)
        provision(sign_key, exch_key)
    else:
        provision_and_activate_nvs(sign_key, exch_key)
    verify_second_provision_refused(sign_key, exch_key)
    verify_serving(sign_key, exch_key)
    check_detailed_status("active", [sign_key, exch_key])

    if STORAGE == "nvs":
        # The stored keys stay and come back on /activate.
        deactivate("locked")
        check_inactive(sign_key, exch_key)
        # Listed while locked, unless they are encrypted.
        check_detailed_status("locked", [] if PASSWORD is not None else [sign_key, exch_key])
        verify_second_provision_refused(sign_key, exch_key)
        if PASSWORD is not None:
            print("\n[locked] Activating with a wrong password (expect 401)...")
            activate_request(401, "wrong-" + PASSWORD)
            check_state("locked")
            check_inactive(sign_key, exch_key)
            wait_out_password_backoff()
        activate()
        verify_serving(sign_key, exch_key)

    # ram holds the only copy, so deactivating leaves nothing.
    deactivate("unprovisioned" if STORAGE == "ram" else "locked")
    check_inactive(sign_key, exch_key)
    wipe()
    check_inactive(sign_key, exch_key)
    check_detailed_status("unprovisioned", [])
    if STORAGE == "nvs":
        print("\n[wipe] Nothing left to activate (expect 409)...")
        request("POST", "/activate", 409)
    print(f"{'='*20} {curve_name} Test Complete {'='*20}\n")


def wait_for_device(timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            requests.get(f"{ESP_IP}/status", timeout=3)
            return
        except requests.RequestException:
            time.sleep(2)
    fail(f"device did not come back within {timeout} s")


def provision_and_activate(sign_key, exch_key):
    provision(sign_key, exch_key)
    if STORAGE == "nvs":
        activate()


def wait_for_state_change(timeout, keep_busy=None):
    """Polls until the device leaves `active` and returns the seconds it
    took. `keep_busy` runs between polls."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if get_status().get("state") != "active":
            return time.monotonic() - start
        if keep_busy is not None:
            keep_busy()
        time.sleep(0.5)
    fail(f"still active after {timeout:.0f} s")


def check_timers():
    """max_active_time and idle_timeout, read from /status. Only a successful
    /rec restarts the idle timer; /adv does not."""
    print(f"\n{'='*20} Timers {'='*20}")
    sign_key = generate_key(["sign", "verify"], "P-256")
    exch_key = generate_key(["deriveKey"], "P-256")
    after = "locked" if STORAGE == "nvs" else "unprovisioned"

    provision_and_activate(sign_key, exch_key)
    status = get_status()
    idle, max_active = status["idle_deactivates_in_s"], status["deactivates_in_s"]
    if idle is None and max_active is None:
        fail("no timer configured: set max_active_time or idle_timeout")
    print(f"idle_deactivates_in_s={idle}, deactivates_in_s={max_active}")

    if idle is not None:
        print(f"\n[timers] A /rec halfway restarts the idle timer...")
        time.sleep(idle / 2)
        perform_exchange(exch_key)
        left = get_status()["idle_deactivates_in_s"]
        if left < idle - 1:
            fail(f"/rec did not restart the idle timer: {left} s left of {idle}")
        print(f"\n[timers] /adv alone does not keep it active ({idle} s)...")
        took = wait_for_state_change(idle + 10, lambda: request("GET", "/adv", 200))
        if abs(took - idle) > 2:
            fail(f"idle_timeout fired after {took:.1f} s, expected {idle} s")
        check_state(after)
        check_inactive(sign_key, exch_key)
        print(f"OK: idle_timeout after {took:.1f} s")
        if max_active is not None:
            if STORAGE == "nvs":
                activate()
            else:
                provision(sign_key, exch_key)

    if max_active is not None:
        max_active = get_status()["deactivates_in_s"]
        print(f"\n[timers] Recoveries do not extend max_active_time ({max_active} s)...")
        last = [0.0]

        def keep_recovering():
            # Often enough to keep the idle timer from firing first.
            if time.monotonic() - last[0] >= (min(idle / 3, 5) if idle else 5):
                perform_exchange(exch_key)
                last[0] = time.monotonic()

        took = wait_for_state_change(max_active + 10, keep_recovering)
        if abs(took - max_active) > 2:
            fail(f"max_active_time fired after {took:.1f} s, expected {max_active} s")
        check_state(after)
        print(f"OK: max_active_time after {took:.1f} s")

    wipe()
    print(f"{'='*20} Timers Complete {'='*20}\n")


def check_lockout():
    """Each failure delays the next attempt: 1 s, 2 s, 4 s, ... After
    max_failures in a row, the lockout. The token and the key password are
    counted separately."""
    print(f"\n{'='*20} Lockout {'='*20}")
    wrong = "wrong-" + TOKEN
    failures = 0
    while True:
        request("GET", "/status", 401, token=wrong)
        failures += 1
        # Even the right token is refused until the wait is over.
        r = request("GET", "/status", 429)
        retry = int(r.headers["Retry-After"])
        backoff = 2 ** (failures - 1)
        print(f"Failure {failures}: Retry-After {retry} s")
        if retry not in (backoff, backoff - 1) or failures >= 20:
            break
        time.sleep(retry)
    if failures < 2:
        fail(f"locked out after {failures} failure, expected a backoff first")
    print(f"Locked out after {failures} failures for {retry} s")

    print("\n[lockout] Protected endpoints answer 429, the rest still works...")
    for method, path in [("POST", "/wipe"), ("POST", "/deactivate"), ("POST", "/provision")]:
        r = request(method, path, 429, json_body={"keys": []} if path == "/provision" else None)
        if "Retry-After" not in r.headers:
            fail(f"{path} 429 without Retry-After")
    public = get_status(token=None)
    if set(public) != {"state"}:
        fail(f"public /status during lockout: {public}")
    if send("GET", "/adv").status_code == 429:
        fail("/adv is refused during the lockout")

    print(f"\n[lockout] Waiting {retry} s for the lockout to end...")
    time.sleep(retry + 1)
    status = get_status()
    if status["auth_failures"] != 0 or status["lockout_remaining_s"] != 0:
        fail(f"a valid token did not reset the backoff: {status}")
    print("OK: a valid token after the lockout resets the count")

    if PASSWORD is not None:
        print("\n[lockout] A wrong password delays the next /activate, but not the token...")
        sign_key = generate_key(["sign", "verify"], "P-256")
        exch_key = generate_key(["deriveKey"], "P-256")
        provision_and_activate(sign_key, exch_key)
        deactivate("locked")
        activate_request(401, "wrong-" + PASSWORD)
        r = activate_request(429, PASSWORD)
        get_status()  # the token is still accepted
        time.sleep(int(r.headers["Retry-After"]))
        activate()
        wipe()
    print(f"{'='*20} Lockout Complete {'='*20}\n")


def check_reboot():
    """With nvs, the device activates its stored keys at boot, or waits for
    the password with require_password. With ram, they are gone."""
    print(f"\n{'='*20} Reboot {'='*20}")
    sign_key = generate_key(["sign", "verify"], "P-256")
    exch_key = generate_key(["deriveKey"], "P-256")
    provision_and_activate(sign_key, exch_key)

    input("\nPower-cycle the device, then press Enter... ")
    wait_for_device()

    if STORAGE == "ram":
        check_state("unprovisioned")
        check_inactive(sign_key, exch_key)
    elif PASSWORD is not None:
        # A require_password device waits for the password after a reboot.
        check_state("locked")
        check_inactive(sign_key, exch_key)
        activate()
        verify_serving(sign_key, exch_key)
    else:
        check_state("active")
        verify_serving(sign_key, exch_key)
    wipe()
    print(f"{'='*20} Reboot Complete {'='*20}\n")


if __name__ == "__main__":
    parse_args()
    print(f"Targeting: {ESP_IP} (key_storage: {STORAGE}, {'with' if PASSWORD else 'without'} password, "
          f"{'with' if TOKEN else 'without'} admin token)")

    # Ensure fresh state, after any lockout left by an earlier run
    wait_out_backoff()
    wipe()
    check_inactive()
    check_public_status()
    if TOKEN is not None:
        check_auth()

    run_test_suite("P-256")
    run_test_suite("P-521")
    if CHECK_TIMERS:
        check_timers()
    if CHECK_LOCKOUT:
        check_lockout()
    if CHECK_REBOOT:
        check_reboot()

    print("All checks passed.")
