# Design: ESPHome `tang_server` component

Status: draft, agreed in planning, not implemented yet.

This document describes how the ESP-IDF firmware in `main/` becomes an ESPHome external component. It covers configuration, HTTP endpoints, automations and entities, and how the tests move over. The Tang protocol code (JWK parsing, `/adv` signing, `/rec` exchange) is carried over. What changes is everything around it: how keys get onto the device, whether they survive a reboot, when they are usable, and how Home Assistant sees and controls that.

## Scope

- **ESPHome only.** The standalone ESP-IDF build (`main/`, `CMakeLists.txt`, `Makefile`, `Kconfig.projbuild`, `sdkconfig.defaults`, `dependencies.lock`) is removed. There is no second, non-ESPHome entry point.
- **Framework:** ESP-IDF, ESPHome's default for ESP32. HTTP goes through `web_server_base`, so the component does not bring its own server or Wi-Fi handling. The AP fallback and the serial `NUKE` command go away; ESPHome's `wifi` and `captive_portal` cover the former.
- **Plain HTTP.** ESPHome has no TLS server on ESP32. Bearer tokens, the key password and, on provision, the private keys travel in cleartext. The device is meant for a trusted LAN. This is a known limitation, not something the component tries to work around.
- **Out of scope for now:**
  - key rotation, i.e. hidden, non-advertised keys and removing single keys;
  - changing the key password without re-provisioning;
  - on-device key generation. Keys are always created off-device with `jose`.

  The stored key format leaves room for rotation (see [Stored key format](#stored-key-format)).

## Terms and states

| State | Meaning |
|---|---|
| `unprovisioned` | No keys on the device at all. |
| `pending` | `nvs` only: keys were provisioned into RAM but are not stored yet, and nothing is served. |
| `locked` | Keys are stored on the device (NVS) but not loaded into RAM. |
| `active` | Keys are in RAM, and `/adv` and `/rec` are served. |

- **Provision:** upload keys to a device that has none. Provisioning never writes to flash.
- **Activate:** start serving.
  - **First activation (`pending`):** stores the provisioned keys in NVS, encrypted with the password if one is required.
  - **Later activations (`locked`):** load the stored keys into RAM, decrypting them with the password if one is required.
- **Deactivate:** drop the keys from RAM. Stored keys stay.
- **Wipe:** drop the keys from RAM and erase the stored keys.

## Key storage

Two YAML options fix the behaviour at compile time:
- `key_storage` decides whether keys survive a reboot.
- `require_password` decides whether stored keys are encrypted and need a password before they can be used.

Together they give three setups:

| | `ram` | `nvs` | `nvs` + `require_password` |
|---|---|---|---|
| Keys stored | nowhere, RAM only | NVS, plaintext | NVS, encrypted |
| After `POST /provision` | `active` | `pending` | `pending` |
| `POST /activate` body | — (404) | none | `{"password": "..."}` |
| First activate | — | stores the keys, then `active` | encrypts the keys with the password, stores them, then `active` |
| State at boot once activated | — | `active` (activates itself) | `locked` |
| Deactivate goes to | `unprovisioned` | `locked` (`unprovisioned` from `pending`) | `locked` (`unprovisioned` from `pending`) |
| Wipe goes to | `unprovisioned` | `unprovisioned` | `unprovisioned` |
| After a power loss | keys gone, provision again | serving again without any interaction | waits for `/activate` |

The password only ever goes to `/activate`. In short, `require_password` decides whether the device unlocks itself after a reboot or waits to be unlocked.

### Choosing a setup

- **`ram`** keeps today's behaviour. A stolen device holds nothing, but every power loss needs a new provision.
- **`nvs`** behaves like tangd on a Linux box. It survives power loss with no interaction, but a stolen device keeps serving the keys wherever it is powered up. It is only safe against someone reading the flash if [flash encryption](#flash-encryption) is enabled.
- **`nvs` + `require_password`** survives power loss without exposing the keys at rest. Someone or something has to activate it after every boot. That something can be Home Assistant: an automation can call `tang_server.activate` with the password from HA's secrets when the device connects (see [Actions](#actions)). Then the device comes back on its own as long as HA is reachable, and a stolen ESP32 stays locked.

### Provision vs. activate

In `ram` mode, there is nothing to store, so provisioning makes the server `active` directly, as today.

In the `nvs` setups, provisioning and activating are two steps:
1. `/provision` uploads the keys into RAM, and the state becomes `pending`.
2. The first `/activate` decides how the keys are kept. With `require_password`, the password it carries encrypts them. They are then written to NVS, and the server starts serving.

After that, every boot goes through activation: automatic without a password, `/activate` with one.

**Choose the password carefully on the first activation.** There is no confirmation step. A mistyped password locks the stored keys away for good. The keys are always created off-device, so the fix is to `/wipe`, provision the backed-up JWKs again, and activate with the right password.

**Until the first activation, the keys exist only in RAM.** A power loss in the `pending` state loses them, and the device is `unprovisioned` again.

The automations, actions, counters and entities treat "becoming `active`" as one event, whether it comes from a `ram` provision, a first activation or a later one. This means:
- a single `on_activate(success)` trigger;
- one `activation_count` counter;
- one `tang_server.activate` action.

There is no separate `on_provision`; `on_state_change` reports `pending`.

### Stored key format

The keys are stored as one NVS blob, key `keys` in the namespace `tang_server`. The component uses the ESP-IDF NVS API directly rather than ESPHome's preferences, for three reasons:
- **Copies:** preferences keep every write in a heap buffer until the next sync and free it without wiping. Comparing with the stored value reads it into another unwiped buffer.
- **Erasing:** preferences cannot erase a record.
- **Threads:** preferences may only be used from the main loop. NVS is thread-safe, so the httpd task stores and erases the record itself and answers only once the change is committed.

ESPHome initializes NVS at boot for its own preferences, so the component only opens its namespace. Every store and erase ends with `nvs_commit()`, so a power loss right after the first `/activate` or a `/wipe` cannot lose the change or bring back wiped keys.

The record starts with a fixed magic number and a format version, followed by the payload. The payload is the `{"keys": [...]}` JSON that `/provision` accepts, written compactly from the parsed keys rather than copied from the request: `kty`, `crv`, `kid` if one was given, `key_ops`, `d`, `x`, `y`.

- **Without a password:** format version `1`, the payload in plaintext.

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 4 | magic number, `TANG` |
  | 4 | 1 | format version, `1` |
  | 5 | n | the `{"keys": [...]}` JSON |

- **With `require_password`:** format version `2`, the payload encrypted. All integers are big-endian.

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 4 | magic number, `TANG` |
  | 4 | 1 | format version, `2` |
  | 5 | 4 | PBKDF2 iterations |
  | 9 | 16 | random salt |
  | 25 | 12 | random GCM nonce |
  | 37 | n | ciphertext of the `{"keys": [...]}` JSON |
  | 37+n | 16 | GCM tag |

  - **Key derivation:** PBKDF2-HMAC-SHA256(password, salt, iterations) produces a 32-byte AES-256-GCM key.
  - **Additional authenticated data:** bytes 0–36 (the header), so the version and parameters cannot be changed without failing the tag check.
  - **Wrong password:** the GCM tag check fails. The device cannot tell a wrong password from a corrupted record, and treats both as an authentication failure.
  - **When it runs:** encryption runs once, on the first `/activate`, which also generates the salt and nonce on the device. Decryption runs on every later `/activate`. Both use mbedTLS. The password is never stored.
  - **Cost:** on an ESP32, one PBKDF2 iteration takes about 100 µs, so the default of 20000 iterations makes every `/activate` take about 2 s. 100000 took 10 s. The derivation yields every 1000 iterations, so the task watchdog does not trip at any count. The count is stored in the record, so changing `pbkdf2_iterations` only affects keys stored afterwards.

Both payloads are the same JSON `/provision` accepts, so every path goes through one parser with one set of checks. These checks are:
- valid JWK;
- `d` matches `x`/`y`;
- a signing key and an exchange key are present.

A later format version can add per-key flags, such as `advertise: false`, for rotation.

**Loading the record at boot.** The component ignores the record if:
- it cannot be read;
- the magic number is wrong;
- the format version is unknown;
- the plaintext payload fails the checks above.

The same applies to a record that does not match the configuration: a plaintext record on a device with `require_password`, or an encrypted one on a device without it.

In that case the device boots `unprovisioned`, logs a warning and sets the `last_error` text sensor. The record stays in NVS until `/wipe` or the next store, so that a firmware downgrade does not destroy a record written by a newer version. An encrypted record can only be checked on `/activate`. If it is corrupt, `/activate` fails with 401, as for a wrong password.

### Secrets in RAM

Deactivate and wipe overwrite the private keys in RAM with `mbedtls_platform_zeroize` before freeing them. The same applies to:
- the password from `/activate`, the action or the button, once the attempt has finished;
- the derived AES key;
- the decrypted `{"keys": [...]}` JSON, once it has been parsed;
- the request body buffers of `/provision` and `/activate`;
- the parsed JSON documents of `/provision`, `/activate` and the stored record.

The last point needs care: ArduinoJson 7, which ESPHome uses, has no zero-copy parsing, so the document copies every string, including `d`, into its own memory pool. Every JSON document that may hold a secret therefore uses an `ArduinoJson::Allocator` that wipes memory before it frees it. Its `reallocate()` allocates, copies and wipes the old block rather than calling `realloc()`, which could leave a copy behind. `deallocate()` gets no size, so it uses `heap_caps_get_allocated_size()`.

This keeps secrets in RAM only while they are needed. Someone who can read the RAM of an `active` device still gets the keys.

### Flash encryption

Without ESP32 flash encryption, anyone holding the device can read NVS:
- **`nvs` setup:** this exposes the Tang keys directly.
- **`nvs` + `require_password`:** it exposes only the encrypted record. The password still protects that record, though only as well as its strength holds up against offline guessing at the configured PBKDF2 cost.

The component does not require flash encryption, because enabling it burns eFuses irreversibly and is not a first-class ESPHome feature. Instead:
- The documentation explains how to enable flash encryption and NVS encryption through `sdkconfig_options`, and recommends both for the plain `nvs` setup.
- If keys are stored in plaintext while flash encryption is off, the component logs a warning at boot and when it stores them.
- The detailed `/status` reports `flash_encryption: false`.

Even with flash encryption, the plain `nvs` setup does not protect against someone who takes the device and simply powers it up: it serves the keys again. The captive portal and the fallback access point should be off on such a device, so that it cannot be pointed at another network.

**`/wipe` is not a forensic erase.** NVS marks old entries as erased but only overwrites them when the page is reused. A plaintext record can linger in flash after a wipe. The component overwrites the record with zeros before erasing it, which helps but does not guarantee the old copy is gone.

## Configuration

```yaml
web_server_base:            # pulled in automatically; the port is set here or via web_server
  port: 80

tang_server:
  id: tang
  key_storage: nvs                # ram | nvs (required)
  require_password: true          # nvs only, default false; the password goes to /activate
  pbkdf2_iterations: 20000        # with require_password only, default 20000 (about 2 s per /activate)
  admin_token: !secret tang_admin_token   # optional; when set, protects all management endpoints

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

**Neither the keys nor the key password appear in YAML.** Keys only ever arrive through `/provision`, so the build needs no key material and no extra Python packages.

**`admin_token`** is optional. Setting it is the switch: there is no separate boolean, so protection can never be turned on without a token to check. When it is set, it protects every management endpoint:
- `/provision`, `/activate`, `/deactivate` and `/wipe`;
- the detailed part of `/status`.

`/adv` and `/rec` stay open either way, because Clevis cannot send a token.

When it is not set, all management endpoints are open to anyone who can reach the device, and the full `/status` is public. Anyone on the network could then:
- deactivate the server;
- wipe stored keys;
- provision their own keys onto an `unprovisioned` device.

The component logs a warning at boot when no token is configured. The detailed `/status` reports `"admin_token": false`. Leaving it out only makes sense on a network where everyone who can reach the device is trusted.

The token is compared in constant time. The token sits in the firmware, which is acceptable because it only guards management actions. It is **not** used to encrypt the keys: a flash dump reveals the token, but not password-protected keys.

**`max_active_time` and `idle_timeout`** can be combined, and whichever expires first deactivates the server. The idle timer starts when the server becomes active and restarts on every successful `/rec`. In the plain `nvs` setup, a deactivated server stays `locked` until `/activate` or the next reboot, and the reboot activates it again.

The timers run in the component's `loop()`, which also fires `on_deactivate` when one expires. They compare `millis()` values with unsigned subtraction (`millis() - since >= timeout`), so they keep working when the 32-bit counter wraps after about 49 days.

**`auth_backoff`** counts failures across the whole device, not per client, with one counter per secret:
- **The token:** a missing or wrong Bearer token, when `admin_token` is set.
- **The key password:** a wrong password on `/activate`.

After each failure, the next attempt that checks the same secret is refused with 429 for an exponentially growing time (1 s, 2 s, 4 s, …), even if it carries the right secret. After `max_failures` failures in a row, the refusal lasts `lockout`. 429 carries `Retry-After` with the seconds left. A success resets that secret's counter.

The counters are separate so that a success with one secret cannot reset the failures of the other. With one counter, someone who has the token could reset it with any valid request between password guesses, and never reach the lockout.

Only requests that check a secret are refused: the management endpoints when `admin_token` is set, `/status` when it carries a token, and `/activate` with `require_password`. `/adv`, `/rec` and the public `/status` keep working. Refused requests do not count as failures, but they do count in the `auth_failure` counter and fire `on_auth_failure`.

Because the counters are global, an attacker can also lock out the legitimate admin. On a LAN device that is the better trade-off than allowing unlimited guessing. `on_auth_failure` makes such attempts visible. The PBKDF2 cost adds its own delay to each password guess.

## HTTP endpoints

All endpoints are at the root, so the Clevis URL is `http://<device>`. The paths do not collide with `web_server`'s UI. When `admin_token` is set, management endpoints take `Authorization: Bearer <admin_token>`. In the table below, "token" means "Bearer token if `admin_token` is set, open otherwise".

| Method and path | Storage | Auth | Purpose |
|---|---|---|---|
| `GET /adv`, `/adv/`, `/adv/<thp>` | all | none | Signed advertisement, as tangd. `/adv/<thp>` returns 404 for a thumbprint that is not a signing key's. |
| `POST /rec/<thp>` | all | none | Key exchange, as tangd. |
| `POST /provision` | all | token | Body `{"keys": [...]}`. Checks the keys and loads them into RAM. The state becomes `active` with `ram`, `pending` with `nvs`. |
| `POST /activate` | `nvs` | token | The body is `{"password": "..."}` with `require_password`, empty otherwise. From `pending`: stores the keys (encrypted with the password if one is required). From `locked`: loads (and decrypts) the stored keys. The state becomes `active`. |
| `POST /deactivate` | all | token | Wipes the keys from RAM. The state becomes `locked` if keys are stored, `unprovisioned` otherwise. |
| `POST /wipe` | all | token | Wipes the keys from RAM and erases the stored record. The state becomes `unprovisioned`. |
| `GET /status` | all | optional | See below. |

`/reboot` is removed; ESPHome's `restart` button and action replace it.

### Thumbprints

Like tangd, `/adv/<thp>` and `/rec/<thp>` accept a key's RFC 7638 thumbprint in any hash tangd supports: S1, S224, S256, S384 and S512 (`TANG_THP_ALGS` in today's `helpers.h`). Clevis uses jose's default, S1. Only S1 would be enough for Clevis, but checking all of them keeps the device interchangeable with tangd. `/status` reports S1 and S256 for each key.

### Request handling

Some of these notes come from an earlier ESPHome port (cherjr/esp32-tang, branch `fix/esphome-tang-runtime`) that ran into them. All were checked against the ESP-IDF web server (`web_server_idf`) of ESPHome 2026.8.0, the version the flake pins.
- **Bodies arrive in `handleBody()`.** For a POST whose `Content-Type` is anything but form data (for example `application/json`, or the `application/jwk+json` Clevis sends), `web_server_base` reads the body from the socket itself, before `handleRequest()` runs. It passes the body to `handleBody()` in chunks. Reading the socket again in `handleRequest()` gets nothing. The handler therefore collects the chunks per request and processes the complete body in `handleRequest()`. The httpd task serves one request at a time, so a single buffer is enough. It remembers which request it belongs to and is wiped at the end of every `handleRequest()`. A request whose body could not be read to the end never reaches `handleRequest()`; the next request resets its partial body. `isRequestHandlerTrivial()` returns `false`, which ESPHome 2026.8.0 does not check but the Arduino-style API expects.
- **Form-encoded bodies never reach the handler.** With `Content-Type: application/x-www-form-urlencoded`, or none at all, the server reads the body into its own form parser and never calls `handleBody()`; above 1024 bytes it answers 400 before the component sees the request. `curl -d` sends exactly that header. A non-empty body that did not come through `handleBody()` is therefore refused with 415. Clients send JSON with `curl --json`, or `-H 'Content-Type: application/json'`.
- **`Content-Length` is required.** The server answers a POST without it with 411 before the component sees it. A bare `curl -X POST` sends no `Content-Length`; requests without a body use `curl -X POST -d ''` or `curl --json ''`.
- **Body size limit.** A body larger than 4096 bytes is refused with 413 before it is buffered. Two P-521 keys with their private parts fit well below that limit. A chunk that arrives out of order or does not add up to `Content-Length` gives 400.
- **Sending responses.** `AsyncWebServerRequest::send()` only knows 200, 204, 400, 401, 404, 409 and 422 and turns every other code into 500. The component therefore sends responses with `httpd_resp_set_status`, `httpd_resp_set_type` and `httpd_resp_send`. `httpd_resp_set_status` needs the full status line, such as `"503 Service Unavailable"`, so the component keeps a table for every code it uses. `Retry-After` on 429 is set with `httpd_resp_set_hdr`.
- **Only Tang paths.** `canHandle()` accepts only the component's own paths, so `web_server` keeps serving everything else. It reads the path with `url_to()`; `url()` is removed in ESPHome 2026.9.0.
- **No web server login.** The handler is registered with `add_handler_without_auth()`. `add_handler()` would put it behind `web_server`'s `auth:` when that is configured, and Clevis cannot log in. `admin_token` is the component's own protection.
- **Starting the server.** `web_server_base` only listens once a consumer calls `init()`. `web_server` and `captive_portal` do so, but the component may be the only consumer, so its `setup()` calls `init()` itself. `init()` is reference-counted, so this is safe alongside the others.
- **Client IP.** The request type has no remote address. `last_client_ip` comes from `getpeername()` on `httpd_req_to_sockfd()`.
- **Two threads.** Handlers run in the httpd task, while timers, actions, buttons and entities run in ESPHome's main loop. A mutex guards the keys and the state. Everything that ESPHome expects on the main loop is handed over with `defer()`: firing triggers and publishing entity states. The key record is written through the NVS API, which is thread-safe, so the httpd task writes it directly (see [Stored key format](#stored-key-format)).
- **Stack size.** The httpd task has a 4352-byte stack (`HTTPD_DEFAULT_CONFIG()` plus 256 bytes), and ESPHome offers no option to change it. The old firmware ran its P-521 operations on an 8 KB stack. Large buffers stay off the stack, and the stack high-water mark is measured during `/adv` and `/rec`. If it does not fit, the crypto moves to a dedicated task with its own stack.

A `password` in the `/activate` body is required with `require_password` and rejected without it. A 400 for a mismatch makes a wrong setup obvious, instead of silently storing keys in a way the user did not expect.

### Deactivate and wipe

Both endpoints exist in every setup, so the same scripts work everywhere.
- **`ram`:** they do the same thing, because RAM holds the only copy. They differ only in the `reason` passed to `on_deactivate`: `manual` or `wipe`.
- **`nvs`:** `/deactivate` keeps the stored keys, so the device can be activated again. `/wipe` removes them, so it has to be provisioned again. In `pending`, nothing is stored yet, so both return the device to `unprovisioned`.

### Status codes

| Code | When |
|---|---|
| 200 | success |
| 400 | malformed body; invalid JWK; `d` not matching `x`/`y`; missing signing or exchange key; `/activate` with `password` missing under `require_password` or present without it |
| 401 | Bearer token missing or wrong, or wrong key password on `/activate` |
| 413 | request body larger than 4096 bytes |
| 404 | unknown path; `/activate` with `ram`; `/adv/<thp>` or `/rec/<thp>` for an unknown thumbprint |
| 405 | a component path with the wrong method, such as `POST /adv`; `Allow` names the right one |
| 409 | `/provision` while not `unprovisioned` (wipe first); `/activate` while already `active`; `/activate` while `unprovisioned` |
| 411 | POST without `Content-Length`; sent by `web_server_base`, not the component |
| 415 | a non-empty body sent as form data instead of JSON |
| 429 | auth backoff or lockout; `Retry-After` gives the seconds left |
| 503 | `/adv` or `/rec` while `unprovisioned`, `pending` or `locked`. Clevis treats this as a failure and falls back to the passphrase. |

Refusing `/provision` with 409 over stored keys means replacing keys always takes an explicit `/wipe` first. A stray provision cannot overwrite the keys that existing Clevis bindings depend on.

### `/status`

With `admin_token` set and no token in the request, `/status` returns the state only:

```json
{"state": "locked"}
```

With a valid token, or with no `admin_token` configured, it adds details. No private key material is ever included.

```json
{
  "state": "active",
  "key_storage": "nvs",
  "require_password": true,
  "flash_encryption": false,
  "admin_token": true,
  "keys": [
    {"thp": {"S1": "…", "S256": "…"}, "use": "sign", "crv": "P-521"},
    {"thp": {"S1": "…", "S256": "…"}, "use": "exchange", "crv": "P-521"}
  ],
  "active_since_s": 1234,
  "deactivates_in_s": 41966,
  "idle_deactivates_in_s": 512,
  "auth_failures": 0,
  "lockout_remaining_s": 0,
  "counters": {"activation": 1, "recovery": 3, "adv": 5, "auth_failure": 0}
}
```

What `keys` lists depends on the state:
- **`active` or `pending`:** the keys loaded in RAM.
- **`locked` without a password:** the stored keys, as they were when the keys were deactivated. `/status` does not read or check the record.
- **`locked` with `require_password`:** empty, because the thumbprints are only known after decryption.

`active_since_s` counts the seconds since the server became active. `deactivates_in_s` and `idle_deactivates_in_s` are the seconds left on each timer. All three are `null` while the server is not active, and the timers are `null` when they are not configured. `auth_failures` is the number of failures in a row, of both secrets together, and `lockout_remaining_s` is the longest wait left.

A wrong token on `/status` counts as an auth failure and returns 401; it does not fall back to the public view. Leave the header out entirely for the public view.

## Automations

### Triggers

| Trigger | Variables | Fires when |
|---|---|---|
| `on_activate` | `bool success` | every activate attempt that passed the token check (if any), with its result; every `ram` provision attempt; and the automatic activation at boot in the plain `nvs` setup |
| `on_deactivate` | `std::string reason` | keys are removed from RAM, from NVS, or both. `reason` is `manual`, `max_active_time`, `idle_timeout` or `wipe`. |
| `on_state_change` | `std::string state` | the state changes. `state` is `unprovisioned`, `pending`, `locked` or `active`. Also fires once at boot with the initial state. |
| `on_recovery` | `std::string thp`, `bool success` | every `/rec/<thp>` request that reached an active server |
| `on_adv` | `std::string thp` | every successful `/adv` request. `thp` is empty for `/adv` and `/adv/`. |
| `on_request` | `std::string path`, `std::string method`, `int status` | every request handled by the component, after the response is sent |
| `on_auth_failure` | `std::string path` | wrong or missing Bearer token (only with `admin_token` set), wrong key password, or a request refused by backoff or lockout |
| `on_rejected` | `std::string path`, `std::string reason` | `/adv` or `/rec` refused with 503. `reason` is `unprovisioned`, `pending` or `locked`. In practice, a client is waiting to be unlocked. |

There is no `on_wipe`; `on_deactivate` with `reason == "wipe"` covers it.

`on_deactivate` with reason `manual` covers HTTP, the action and the button alike. A `/deactivate` request on an `unprovisioned` or `locked` device succeeds but fires nothing, because there are no keys in RAM to remove. A `/deactivate` in `pending` does fire, because it drops the provisioned keys. A `/wipe` fires whenever there are keys anywhere: in RAM (`pending`, `active`), in NVS (`locked`), or both.

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

| Action | Storage | Notes |
|---|---|---|
| `tang_server.activate` | `nvs` | Same as `/activate`, from `pending` or `locked`. `password:` is templatable. It is required with `require_password` and rejected without it. It goes through the same backoff as HTTP. |
| `tang_server.deactivate` | all | Reason `manual`. |
| `tang_server.wipe` | all | Reason `wipe`. |

Actions never need `admin_token`: whoever can run them already controls the device through the ESPHome API. There is no provision action: keys come from off-device, so they come over HTTP.

To let Home Assistant unlock a `require_password` device after every boot, expose the action through `api: actions:`:

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

Then add an HA automation that calls `esphome.<device>_tang_activate` with the password from HA's secrets whenever the device comes online and reports `locked`.

### Conditions

`tang_server.is_active`, `tang_server.is_locked` and `tang_server.is_provisioned`. `is_provisioned` is true when the state is `pending`, `locked` or `active`.

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
    activate:                     # nvs only
      name: Tang activate
      password_id: tang_password  # with require_password only; read, then cleared
```

- `last_error` holds a short, safe message, never key material or the submitted password.
- `last_client_ip` is the IP of the last request the component handled.
- The activate button clears the text entity after each attempt, whatever the result, so the password does not stay in Home Assistant's state.

## Repository layout after the migration

```
components/tang_server/
  __init__.py          schema, triggers, actions, conditions
  binary_sensor.py
  sensor.py
  text_sensor.py
  button.py
  tang_server.h/.cpp   component: state machine, timers, backoff, entities
  http_handler.h/.cpp  AsyncWebHandler registered on web_server_base
  tang_crypto.h/.cpp   JWK parsing, adv signing, ECMR exchange (from helpers.h)
  key_store.h/.cpp     NVS record, PBKDF2 + AES-GCM encryption and decryption
  automation.h         trigger, action and condition classes
example/
  tang-ram.yaml
  tang-nvs.yaml
  tang-nvs-password.yaml
  secrets.yaml.example
tests/
  luks-clevis.nix
verify_tang.py
docs/esphome-component.md
```

`main/`, `CMakeLists.txt`, `Makefile`, `sdkconfig.defaults` and `dependencies.lock` are deleted. The flake's dev shell swaps the ESP-IDF toolchain for `esphome`, and gains a check that runs `esphome config` on all three example files.

## Tests

Both tests keep talking to a real device and keep replacing whatever it currently serves. Every setup accepts keys at runtime, so both tests generate fresh keys in all three setups.

### `verify_tang.py`

It gains:
- `--token` for the Bearer header;
- `--storage ram|nvs`;
- `--password` for a `require_password` device.

Each run starts with `/wipe`. For P-256 and P-521, it then:
1. generates fresh keys and provisions them;
2. checks the adv signature, the adv paths and the exchanges;
3. checks that a key whose `d` does not match `x`/`y` is rejected;
4. deactivates.

Checks for every setup:
- 503 on `/adv` and `/rec` while inactive;
- with `--token`: 401 without the token, and 401 with a wrong one;
- without `--token`: management endpoints work without a header, and the public `/status` shows details;
- 409 on a second provision without a wipe;
- `/wipe` leaves the device `unprovisioned`;
- `/status`: the public view shows only the state, and the detailed view never contains `d`.

Extra checks with `nvs`:
- after `/provision`, the device is `pending` and `/adv` returns 503;
- `/deactivate` from `pending` leaves the device `unprovisioned`;
- after the first `/activate`, `/deactivate` leaves the device `locked`;
- `/activate` from `locked` brings back the same thumbprints;
- 400 for a `password` on `/activate` that does not match `require_password`.

Extra checks with `nvs` + `require_password`:
- a wrong password returns 401 and leaves the device `locked`.

Two checks are opt-in, because they need time or a person:
- **`--check-lockout`:** backoff and lockout. Running it locks the device for the configured time.
- **`--check-reboot`:** asks you to power-cycle the device, then checks that it comes back `active` (plain `nvs`) or `locked` with the same keys after activation (`require_password`).

### `tests/luks-clevis.nix`

It keeps the same flow, driven by environment variables:
- `TANG_URL` (as today)
- `TANG_TOKEN`
- `TANG_PASSWORD`, only for a `require_password` device

The test wipes, provisions fresh keys and, with `nvs`, activates them (with `TANG_PASSWORD` if set). It checks that the initrd unlocks the root through the device, then deactivates and checks that the next boot falls back to the passphrase prompt, now via a 503 from the device.

## Implementation order

[esphome-implementation.md](esphome-implementation.md) breaks these steps into tasks, maps today's code to the new files, and lists what each step must show before the next one starts.

1. Component skeleton: `__init__.py` schema, the state machine, and the `web_server_base` handler with the Tang endpoints ported from `handlers.h` (`ram` only).
2. `verify_tang.py`: `--token` and the `ram` checks. Run it against the new firmware before continuing.
3. `nvs` storage without a password: the `pending` state, storing on the first `/activate`, activation at boot, `/wipe`, and the `nvs` checks.
4. `require_password`: PBKDF2 + AES-GCM in `key_store`, and the password checks.
5. Auth backoff, auto-deactivation, `/status` and the flash encryption warning.
6. Triggers, actions and conditions.
7. Entities and buttons.
8. Port `luks-clevis.nix`, update the flake and README (including the flash encryption guide), and delete the ESP-IDF build.
