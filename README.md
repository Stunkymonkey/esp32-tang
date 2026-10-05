# ESP32 Tang Server

An experimental implementation of a **Tang server** running directly on an **ESP32** device.
The server is written in **C++**, using **mbedTLS** and the **ESP-IDF** framework.

## Overview

The goal of this project is to implement the core Tang functionality — **advertisement** and **activation** — directly on the ESP32, demonstrating that a small embedded system can operate as a self-contained cryptographic service.

In future iterations, this implementation will be **integrated into ESPHome**, enabling seamless use with **Home Assistant**. This will allow ESP-based devices to provide secure key exchange mechanisms within **IoT** or **home automation** environments.
Because HTTPS/SSL will be handled by ESPHome, it is **not** a primary focus of this standalone implementation.

A distributed deployment with multiple ESP32 Tang servers could further enhance security by requiring responses from several devices for key recovery, reducing single points of failure.

## Usage

### 0. Prerequisites

Generate the keys using `jose`:

```bash
jose jwk gen -i '{"alg":"ES512"}' -o sign.jwk
jose jwk gen -i '{"alg":"ECMR"}' -o exc.jwk
```

### 1. Provision the Server
Since this ESP32 implementation uses **volatile memory** (keys are lost on reboot), you must "provision" the server with keys after every startup.

This is done by sending a JSON payload containing all your keys (Signing and Exchange) to the `/provision` endpoint.

**If you have standard Tang key files** (e.g., `sign.jwk`, `exc.jwk` or named by thumbprint):
You can bundle them using `jq`:

```bash
# Bundle separate JWK files into the payload structure
jq -s '{keys: .}' *.jwk > payload.json

# Send to ESP32
curl -X POST -H "Content-Type: application/json" -d @payload.json http://<esp-ip>/provision
```

**Manual JSON Construction:**
```json
{
  "keys": [
    { "alg": "ES512", "key_ops": ["sign", "verify"], "kty": "EC", "crv": "P-521", "d": "...", "x": "...", "y": "..." },
    { "alg": "ECMR", "key_ops": ["deriveKey"], "kty": "EC", "crv": "P-521", "d": "...", "x": "...", "y": "..." }
  ]
}
```

### 2. Standard Tang Usage
Once provisioned, the ESP32 behaves like a standard Tang server.

**Advertise Keys:**
```bash
curl http://<esp-ip>/adv
```

**Key Exchange (Recovery):**
Standard clients (like Clevis) or manual requests can target the recovery endpoint:
```bash
curl -X POST -H "Content-Type: application/json" -d @client_key.jwk http://<esp-ip>/rec/<kid>
```

## Verification

Both checks below talk to a real ESP32 on your network and **replace the keys on it**: they deactivate the device, provision their own test keys, and leave it deactivated or holding those keys. Provision your own keys again afterwards.

### Protocol check: `verify_tang.py`

Starts with `/wipe`, then runs the Tang endpoints against the device for both P-256 and P-521:
- It generates fresh keys and provisions them, and checks that a key whose `d` does not match its `x`/`y` is rejected, and that a second provision without a wipe gets 409.
- It verifies the `/adv` signature, and checks that `/adv`, `/adv/` and `/adv/<thp>` behave like tangd (404 for a thumbprint that is not a signing key's).
- It performs `/rec/<thp>` exchanges using the S256 and S1 thumbprints.
- It checks that `/adv` and `/rec` answer 503 while no keys are loaded, and that `/deactivate` and `/wipe` leave the device `unprovisioned`.
- It checks `/status`. With `--token`, it also checks that the management endpoints answer 401 without the token or with a wrong one, and that `/status` without a token shows only the state.

- With `--storage nvs`, it checks the `pending` and `locked` states: nothing is served before the first `/activate`, `/deactivate` keeps the stored keys and `/activate` brings the same ones back, and a password on `/activate` is refused.
- With `--password`, for a `require_password` device, it also checks that `/activate` needs the password and that a wrong one gets 401 and leaves the device `locked`. `--password` implies `--storage nvs`.
- With `--check-timers`, it checks `idle_timeout` and `max_active_time`, reading their values from `/status`. It takes as long as they are set to; `tests/tang-test.yaml` sets them short.
- With `--check-lockout` (needs `--token`), it checks the auth backoff: 1 s, 2 s, 4 s, … after each wrong token, then the lockout. Running it locks the device for its configured lockout time.
- `tests/tang-test.yaml` also logs every trigger and has every entity. `tests/tang_api.py <host> <api_encryption_key> <command>` talks to it through the ESPHome API as Home Assistant would: `run <action> [password]` for its API actions (`tang_activate`, `tang_deactivate`, `tang_wipe`, `tang_conditions`), `entities`, `watch <seconds>`, `press <button name>` and `text <text name> <value>`.
- With `--check-reboot`, it provisions keys, asks you to power-cycle the device and checks that they are back (`nvs`), waiting for the password (`require_password`) or gone (`ram`).

Run it through the flake, which brings the Python dependencies. Pass the device's `admin_token` with `--token`, or leave it out if none is configured, and its `key_storage` with `--storage` (default `ram`):

```bash
nix run .#verify -- http://<esp-ip> --token <admin_token> --storage nvs
```

Inside `nix develop` the same command is available as `verify-tang`. Without Nix, run `python3 verify_tang.py` with `requests` and `cryptography` installed.

### End-to-end check: NixOS VM test

`tests/luks-clevis.nix` boots a NixOS VM whose root filesystem is LUKS-encrypted and bound to the ESP32 with Clevis:
1. It checks that the initrd unlocks the root through the ESP32.
2. It then deactivates the device and checks that the next boot falls back to the passphrase prompt.

This exercises the real Clevis client, including the blinded exchange it performs.

The VM reaches the ESP32 through QEMU's user-mode network, which the Nix sandbox blocks. The test is therefore exposed as a package rather than a flake check, and has to be run through its driver on a Linux host with KVM:

```bash
nix build .#luks-clevis-test.driver
TANG_URL=http://<esp-ip> ./result/bin/nixos-test-driver
```

The driver writes VM disk images into the current directory, so run it from a scratch directory. To step through the test interactively, build `.#luks-clevis-test.driverInteractive` instead, then call `test_script()` or drive `machine` from the Python prompt.

## Useful Links

- [Tang Server (reference implementation)](https://github.com/latchset/tang)
