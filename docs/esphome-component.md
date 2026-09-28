# Design: ESPHome `tang_server` component

Status: draft, agreed in planning, not implemented yet.

This document describes how the ESP-IDF firmware in `main/` becomes an ESPHome external component. It covers configuration, HTTP endpoints, automations and entities, and how the tests move over. The Tang protocol code (JWK parsing, `/adv` signing, `/rec` exchange) is carried over. What changes is everything around it: how keys get onto the device, when they are usable, and how Home Assistant sees and controls that.

## Scope

- **ESPHome only.** The standalone ESP-IDF build (`main/`, `CMakeLists.txt`, `Makefile`, `Kconfig.projbuild`, `sdkconfig.defaults`, `dependencies.lock`) is removed. There is no second, non-ESPHome entry point.
- **Framework:** ESP-IDF, ESPHome's default for ESP32. HTTP goes through `web_server_base`, so the component does not bring its own server or Wi-Fi handling. The AP fallback and the serial `NUKE` command go away; ESPHome's `wifi` and `captive_portal` cover the former.
- **Plain HTTP.** ESPHome has no TLS server on ESP32. Bearer tokens and the key password travel in cleartext, so the device is meant for a trusted LAN. This is a known limitation, not something the component tries to work around.
- **Out of scope for now:** key rotation (hidden, non-advertised keys) and on-device key generation. Keys are always created off-device with `jose`. The blob format leaves room for rotation (see [Encrypted key blob](#encrypted-key-blob)).

## Terms and states

| State | Meaning |
|---|---|
| `unprovisioned` | No keys on the device at all. |
| `locked` | Encrypted keys are in the firmware, but not decrypted. |
| `active` | Keys are decrypted in RAM, and `/adv` and `/rec` are served. |

- **Provision:** upload plaintext keys to a device that has none. The keys live in RAM only.
- **Activate:** decrypt keys that are already on the device, using the key password.
- **Deactivate:** drop the keys from RAM.

## Key storage modes

`key_storage` in YAML fixes the mode at compile time. One firmware image supports exactly one mode, and only that mode's endpoints are registered (the other mode's endpoints return 404).

| | `none` | `encrypted` |
|---|---|---|
| State at boot | `unprovisioned` | `locked` |
| Where keys come from | `POST /provision` with a JWK set | JWK files encrypted by ESPHome at compile time and embedded in the firmware |
| How the server becomes `active` | provision | `POST /activate` with the key password |
| Deactivate goes to | `unprovisioned` | `locked` |
| Keys after reboot | gone | still in firmware, `locked` |
| Removing the keys for good | deactivate, wipe or reboot | reflash without them |

Nothing is written to NVS in either mode. Only the firmware image holds key material, and only encrypted.

### Provision vs. activate

Both ways end in `active`, so the automations, actions, counters and entities treat them as one event:
- a single `on_activate(success)` trigger;
- one `activation_count` counter;
- one `tang_server.activate` action.

There is no separate `on_provision`. Because the mode is fixed at compile time, a YAML file never needs to tell the two cases apart.

The HTTP endpoints stay separate (`/provision` and `/activate`). Their bodies are different (a full JWK set vs. a password), and a request aimed at the wrong mode should fail with a clear 404 rather than a confusing 400.

## Encrypted key blob

In `encrypted` mode, ESPHome's code generation reads the JWK files and encrypts them with the key password. The resulting bytes are embedded as a `const uint8_t[]`. The password is used only during the build and is **not** part of the firmware. The build needs the `cryptography` Python package, which ESPHome already depends on.

Format (all integers big-endian):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | format version, `1` |
| 1 | 4 | PBKDF2 iterations |
| 5 | 16 | random salt |
| 21 | 12 | random GCM nonce |
| 33 | n | ciphertext |
| 33+n | 16 | GCM tag |

- **Key derivation:** PBKDF2-HMAC-SHA256(password, salt, iterations) produces a 32-byte AES-256-GCM key.
- **Additional authenticated data:** bytes 0–32 (the header), so the version and parameters cannot be changed without failing the tag check.
- **Plaintext:** the same `{"keys": [...]}` JSON that `/provision` accepts, so both modes share one parser and one set of checks. A later version can add per-key flags, such as `advertise: false`, for rotation.
- **Wrong password:** the GCM tag check fails. The device cannot tell a wrong password from a corrupted blob, and treats both as an authentication failure.

The build fails early if a key file is not valid JWK, if a private key's `d` does not match its `x`/`y`, or if a signing or exchange key is missing. This is the same check the device already does on provision.

A new salt and nonce are generated on every build, so rebuilding changes the firmware even when the keys do not. That is expected.

## Configuration

```yaml
web_server_base:            # pulled in automatically; the port is set here or via web_server
  port: 80

tang_server:
  id: tang
  key_storage: encrypted          # none | encrypted (required)
  admin_token: !secret tang_admin_token   # required, Bearer token for management endpoints

  # encrypted mode only (required there, rejected in none mode)
  keys:
    files:
      - keys/sign.jwk
      - keys/exc.jwk
    password: !secret tang_key_password
    pbkdf2_iterations: 100000     # optional, default 100000

  # none mode only (rejected in encrypted mode)
  provision_requires_auth: true   # optional, default true

  # auto-deactivation, both optional and off by default
  max_active_time: 12h            # deactivate this long after becoming active
  idle_timeout: 30min             # deactivate after this long without a successful /rec

  # brute-force protection for everything that checks a secret
  auth_backoff:
    max_failures: 5               # optional, default 5
    lockout: 5min                 # optional, default 5min

  on_activate: ...
  on_deactivate: ...
  on_state_change: ...
  on_recovery: ...
  on_adv: ...
  on_request: ...
  on_auth_failure: ...
  on_rejected: ...
```

**`admin_token`** protects `/provision` (unless `provision_requires_auth: false`), `/activate`, `/deactivate`, `/wipe` and the detailed part of `/status`. It is compared in constant time. It sits in the firmware, which is acceptable because it only guards management actions. It is **not** used to encrypt the keys: a flash dump reveals the token, but not the keys.

**`max_active_time` and `idle_timeout`** can be combined. Whichever expires first deactivates the server. The idle timer starts when the server becomes active and restarts on every successful `/rec`.

**`auth_backoff`** counts failures across the whole device, not per client. Failures include a missing or wrong Bearer token, and a wrong key password on `/activate`. After each failure, the next attempt is refused for an exponentially growing time (1 s, 2 s, 4 s, …). After `max_failures` failures in a row, every protected endpoint answers 429 for `lockout`. A success resets the counter. Because the counter is global, an attacker can also lock out the legitimate admin. On a LAN device that is the better trade-off than allowing unlimited guessing. `on_auth_failure` makes such attempts visible. The PBKDF2 cost adds its own delay to each password guess.

## HTTP endpoints

All endpoints are at the root, so the Clevis URL is `http://<device>`. The paths do not collide with `web_server`'s UI. Management endpoints take `Authorization: Bearer <admin_token>`.

| Method and path | Mode | Auth | Purpose |
|---|---|---|---|
| `GET /adv`, `/adv/`, `/adv/<thp>` | both | none | Signed advertisement, as tangd. `/adv/<thp>` returns 404 for a thumbprint that is not a signing key's. |
| `POST /rec/<thp>` | both | none | Key exchange, as tangd. |
| `POST /provision` | `none` | Bearer (configurable) | Body `{"keys": [...]}`. Loads the keys into RAM, and the state becomes `active`. |
| `POST /activate` | `encrypted` | Bearer | Body `{"password": "..."}`. Decrypts the embedded blob, and the state becomes `active`. |
| `POST /deactivate` | both | Bearer | Wipes the keys from RAM. The state becomes `unprovisioned` in `none` mode, `locked` in `encrypted` mode. |
| `POST /wipe` | both | Bearer | Same effect as `/deactivate`, but `on_deactivate` gets the reason `wipe`. See [Deactivate and wipe](#deactivate-and-wipe). |
| `GET /status` | both | optional | See below. |

`/reboot` is removed; ESPHome's `restart` button and action replace it.

### Deactivate and wipe

Both endpoints exist in both modes, so either workflow can be scripted the same way whichever mode the device runs. Each one drops the keys from RAM, and they differ only in the `reason` passed to `on_deactivate`:
- `/deactivate` passes `manual`.
- `/wipe` passes `wipe`.

Neither writes to flash. In `encrypted` mode the blob stays in the firmware, and `/wipe` leaves the device `locked` just like `/deactivate` does. Removing the blob for good means reflashing.

### Status codes

| Code | When |
|---|---|
| 200 | success |
| 400 | malformed body, invalid JWK, `d` not matching `x`/`y`, missing signing or exchange key |
| 401 | Bearer token missing or wrong, or wrong key password on `/activate` |
| 404 | unknown path, a path for the other `key_storage` mode, `/adv/<thp>` or `/rec/<thp>` for an unknown thumbprint |
| 409 | `/provision` or `/activate` while already `active` (deactivate first, as today) |
| 429 | auth backoff or lockout; `Retry-After` gives the seconds left |
| 503 | `/adv` or `/rec` while `unprovisioned` or `locked`. Clevis treats this as a failure and falls back to the passphrase. |

### `/status`

Without a token, `/status` returns the state only:

```json
{"state": "locked"}
```

With a valid token, it adds details. No private key material is ever included.

```json
{
  "state": "active",
  "key_storage": "encrypted",
  "keys": [
    {"thp": "…", "use": "sign", "crv": "P-521"},
    {"thp": "…", "use": "exchange", "crv": "P-521"}
  ],
  "active_since_s": 1234,
  "deactivates_in_s": 41966,
  "idle_deactivates_in_s": 512,
  "auth_failures": 0,
  "lockout_remaining_s": 0,
  "counters": {"activation": 1, "recovery": 3, "adv": 5, "auth_failure": 0}
}
```

A wrong token on `/status` counts as an auth failure and returns 401; it does not fall back to the public view. Leave the header out entirely for the public view.

## Automations

### Triggers

| Trigger | Variables | Fires when |
|---|---|---|
| `on_activate` | `bool success` | every provision or activate attempt that passed the Bearer check, with its result |
| `on_deactivate` | `std::string reason` | keys are removed from RAM. `reason` is `manual`, `max_active_time`, `idle_timeout` or `wipe`. |
| `on_state_change` | `std::string state` | the state changes. `state` is `unprovisioned`, `locked` or `active`. Also fires once at boot with the initial state. |
| `on_recovery` | `std::string kid`, `bool success` | every `/rec/<thp>` request that reached an active server |
| `on_adv` | `std::string thp` | every successful `/adv` request. `thp` is empty for `/adv` and `/adv/`. |
| `on_request` | `std::string path`, `std::string method`, `int status` | every request handled by the component, after the response is sent |
| `on_auth_failure` | `std::string path` | wrong or missing Bearer token, wrong key password, or a request refused by backoff or lockout |
| `on_rejected` | `std::string path`, `std::string reason` | `/adv` or `/rec` refused with 503. `reason` is `unprovisioned` or `locked`. In practice, a client is waiting to be unlocked. |

There is no `on_wipe`; `on_deactivate` with `reason == "wipe"` covers it.

`on_deactivate` with reason `manual` covers HTTP, the action and the button alike. A `/deactivate` request on an inactive server succeeds but fires nothing, because there was nothing to remove.

Example: notify Home Assistant when a machine is waiting to be unlocked.

```yaml
tang_server:
  on_rejected:
    - homeassistant.event:
        event: esphome.tang_waiting
        data:
          path: !lambda "return path;"
          reason: !lambda "return reason;"
```

### Actions

| Action | Mode | Notes |
|---|---|---|
| `tang_server.activate` | `encrypted` | `password:` is templatable. Goes through the same backoff as HTTP. |
| `tang_server.deactivate` | both | Reason `manual`. |
| `tang_server.wipe` | both | Reason `wipe`. |

Actions do not need `admin_token`: whoever can run them already controls the device through the ESPHome API. To call them from Home Assistant, expose them through `api: actions:`:

```yaml
api:
  actions:
    - action: tang_activate
      variables:
        password: string
      then:
        - tang_server.activate:
            password: !lambda "return password;"
```

### Conditions

`tang_server.is_active`, `tang_server.is_locked` and `tang_server.is_provisioned`. `is_provisioned` is true when the state is `locked` or `active`.

## Entities

All entities are optional and use `tang_server_id` to refer to the component. The component starts from zero at every boot, so the counters are `total_increasing`, and Home Assistant handles the reset.

```yaml
binary_sensor:
  - platform: tang_server
    active:
      name: Tang active

text_sensor:
  - platform: tang_server
    state:
      name: Tang state
    last_path:
      name: Tang last path
    last_error:
      name: Tang last error
    last_client_ip:
      name: Tang last client

sensor:
  - platform: tang_server
    activation_count:
      name: Tang activations
    recovery_count:
      name: Tang recoveries
    adv_count:
      name: Tang advertisements
    auth_failure_count:
      name: Tang auth failures

text:
  - platform: template
    id: tang_password
    name: Tang key password
    mode: password
    optimistic: true

button:
  - platform: tang_server
    deactivate:
      name: Tang deactivate
    wipe:
      name: Tang wipe
    activate:                     # encrypted mode only
      name: Tang activate
      password_id: tang_password  # reads the text entity, then clears it
```

- `last_error` holds a short, safe message, never key material or the submitted password.
- `last_client_ip` is the IP of the last request the component handled.
- The activate button clears the text entity after each attempt, whatever the result, so the password does not stay in Home Assistant's state.

## Repository layout after the migration

```
components/tang_server/
  __init__.py          schema, blob encryption, triggers, actions, conditions
  binary_sensor.py
  sensor.py
  text_sensor.py
  button.py
  tang_server.h/.cpp   component: state machine, timers, backoff, entities
  http_handler.h/.cpp  AsyncWebHandler registered on web_server_base
  tang_crypto.h/.cpp   JWK parsing, adv signing, ECMR exchange, blob decryption (from helpers.h)
  automation.h         trigger, action and condition classes
example/
  tang-none.yaml
  tang-encrypted.yaml
  secrets.yaml.example
tests/
  luks-clevis.nix
verify_tang.py
docs/esphome-component.md
```

`main/`, `CMakeLists.txt`, `Makefile`, `sdkconfig.defaults` and `dependencies.lock` are deleted. The flake's dev shell swaps the ESP-IDF toolchain for `esphome`, and gains a check that runs `esphome config` on both example files.

## Tests

Both tests keep talking to a real device and keep replacing whatever it currently serves.

### `verify_tang.py`

It gains `--token` for the Bearer header, and `--mode none|encrypted`.

- **`none`**: works as today. It generates fresh P-256 and P-521 keys, provisions them, and checks the adv signature, the adv paths and the exchanges. It checks that a key whose `d` does not match `x`/`y` is rejected. Then it deactivates.
- **`encrypted`**: the keys are fixed at build time, so the script cannot generate them. It takes `--keys sign.jwk exc.jwk` and `--password`. It checks the adv signature against the given public keys, and runs the exchanges with the given exchange key. It checks that a wrong password returns 401, and that the device is `locked` after deactivate.

New checks for both modes:
- 503 on `/adv` and `/rec` while inactive;
- 401 without the token, and 401 with a wrong one;
- 404 for the other mode's endpoint;
- 409 on a second provision or activate;
- `/wipe` behaves like `/deactivate` (`unprovisioned` in `none` mode, `locked` in `encrypted` mode);
- `/status`: the public view shows only the state, and the detailed view never contains `d`.

Backoff and lockout are only covered with `--check-lockout`, because running it locks the device for the configured time.

### `tests/luks-clevis.nix`

It keeps the same flow, driven by environment variables:
- `TANG_URL` (as today)
- `TANG_TOKEN`
- `TANG_MODE`
- in `encrypted` mode, `TANG_KEY_PASSWORD`, used to activate before the boot and checked against the `/adv` the VM binds to

In `none` mode, the test generates and provisions keys as today. It then deactivates and checks that the next boot falls back to the passphrase prompt, now via a 503 from the device.

## Implementation order

1. Component skeleton: `__init__.py` schema, the state machine, and the `web_server_base` handler with the Tang endpoints ported from `handlers.h` (`none` mode only).
2. `verify_tang.py`: `--token` and the `none` mode checks. Run it against the new firmware before continuing.
3. Blob encryption in codegen, `/activate`, and the `encrypted` mode checks in `verify_tang.py`.
4. Auth backoff, auto-deactivation and `/status`.
5. Triggers, actions and conditions.
6. Entities and buttons.
7. Port `luks-clevis.nix`, update the flake and README, and delete the ESP-IDF build.
