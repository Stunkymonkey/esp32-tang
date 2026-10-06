# Design: ESPHome `tang_server` component

Status: implemented; see [Implementation history](#implementation-history) for how it was built and where it differs from the first draft.

This document describes the ESPHome external component that replaced the standalone ESP-IDF firmware. It covers configuration, HTTP endpoints, automations and entities, and the tests. The Tang protocol code (JWK parsing, `/adv` signing, `/rec` exchange) came over from the ESP-IDF firmware. What changed is everything around it: how keys get onto the device, whether they survive a reboot, when they are usable, and how Home Assistant sees and controls that.

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
  - **Cost:** on an ESP32, one PBKDF2 iteration takes about 100 µs, so the default of 20000 iterations makes an activation take about 2 s through the action or the button. Through `/activate` it takes about 3.4 s: the extra time only appears while an HTTP request waits for the activation task, for a reason not found yet. 100000 iterations took 10 s. The derivation yields every 1000 iterations, so the task watchdog does not trip at any count. The count is stored in the record, so changing `pbkdf2_iterations` only affects keys stored afterwards.

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

Unless NVS is encrypted, anyone holding the device can read it:
- **`nvs` setup:** this exposes the Tang keys directly.
- **`nvs` + `require_password`:** it exposes only the encrypted record. The password still protects that record, though only as well as its strength holds up against offline guessing at the configured PBKDF2 cost.

Flash encryption alone is not enough: ESP-IDF leaves the `nvs` partition out of it. NVS encryption is a separate option (`CONFIG_NVS_ENCRYPTION`). Its keys live in an `nvs_keys` partition, which flash encryption protects, so it needs flash encryption as well.

The component does not require either, because enabling flash encryption burns eFuses irreversibly and is not a first-class ESPHome feature. Instead:
- The README explains how to enable flash encryption and NVS encryption through `sdkconfig_options` and an extra partition, and recommends both for the plain `nvs` setup.
- If keys are stored in plaintext while NVS is not encrypted, the component logs a warning at boot and when it stores them.
- The detailed `/status` reports `flash_encryption` and `nvs_encryption`.

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

Like tangd, `/adv/<thp>` and `/rec/<thp>` accept a key's RFC 7638 thumbprint in any hash tangd supports: S1, S224, S256, S384 and S512 (`TANG_THP_ALGS` in `tang_crypto`). Clevis uses jose's default, S1. Only S1 would be enough for Clevis, but checking all of them keeps the device interchangeable with tangd. `/status` reports S1 and S256 for each key.

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
- **Stack size.** The httpd task has a 4352-byte stack (`HTTPD_DEFAULT_CONFIG()` plus 256 bytes), and ESPHome offers no option to change it. The old firmware ran its P-521 operations on an 8 KB stack. Large buffers stay off the stack, and the stack high-water mark is logged after every request. Activations, from `/activate` and from the action, run in their own task with an 8 KB stack: they hold PBKDF2, AES-GCM and the key-pair checks, the deepest path. `/activate` waits for that task; one activation runs at a time, and a second one gets 409. `/provision`, `/adv` and `/rec` stay on the httpd stack.

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
  "nvs_encryption": false,
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
| `on_activate` | `bool success` | every activate attempt that passed the token check (if any) and the backoff, with its result, including 400 and 409; every `ram` provision attempt; and the automatic activation at boot in the plain `nvs` setup |
| `on_deactivate` | `std::string reason` | keys are removed from RAM, from NVS, or both. `reason` is `manual`, `max_active_time`, `idle_timeout` or `wipe`. |
| `on_state_change` | `std::string state` | the state changes. `state` is `unprovisioned`, `pending`, `locked` or `active`. Also fires once at boot with the initial state, after the stored keys are loaded; the changes while loading them are not reported on their own. |
| `on_recovery` | `std::string thp`, `bool success` | every `/rec/<thp>` request that reached an active server |
| `on_adv` | `std::string thp` | every successful `/adv` request. `thp` is empty for `/adv` and `/adv/`. |
| `on_request` | `std::string path`, `std::string method`, `int status` | every request handled by the component, after the response is sent |
| `on_auth_failure` | `std::string path` | wrong or missing Bearer token (only with `admin_token` set), wrong key password, or a request refused by backoff or lockout |
| `on_rejected` | `std::string path`, `std::string reason` | `/adv` or `/rec` refused with 503. `reason` is `unprovisioned`, `pending` or `locked`. In practice, a client is waiting to be unlocked. |

There is no `on_wipe`; `on_deactivate` with `reason == "wipe"` covers it.

Every trigger runs on the main loop, whichever task the event happened in: the component hands it over with `defer()`, so the events of one request may arrive a loop iteration later. `path` is the request path; for the action, `on_auth_failure` gets `tang_server.activate` instead.

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
| `tang_server.activate` | `nvs` | Same as `/activate`, from `pending` or `locked`. `password:` is templatable. It is required with `require_password` and rejected without it; the build fails otherwise, and with `key_storage: ram`. It goes through the same backoff as HTTP. It returns at once: the activation runs in its own task, so PBKDF2 does not block the main loop. Its result shows in `on_activate`. |
| `tang_server.deactivate` | all | Reason `manual`. |
| `tang_server.wipe` | all | Reason `wipe`. |

Actions never need `admin_token`: whoever can run them already controls the device through the ESPHome API. There is no provision action: keys come from off-device, so they come over HTTP.

`tang_server.deactivate` and `tang_server.wipe` wait for the lock, so while an activation runs, they hold up the main loop until it is done: about 2 s at the default PBKDF2 cost.

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

- `last_error` holds a short, safe message, never key material or the submitted password. It is only published when it changes, so Home Assistant keeps the time it happened.
- `last_client_ip` is the IP of the last request the component handled, read from the request's socket.
- The activate button reads the text entity and clears it right away on every press, whatever the result, so the password does not stay in Home Assistant's state. It wipes the entity's own copy before publishing it empty. The text entity must not have `restore_value: true`, which would save the password in flash. Like `tang_server.activate`, it activates in the background; the result shows in `on_activate` and the entities. `password_id` is required with `require_password` and rejected without it, and the button needs `key_storage: nvs`; the build fails otherwise.
- Entities show the latest state, not every change: they are published on the main loop, and changes within one loop iteration are published once. For example, `pending → active → locked` within a few milliseconds shows as `pending → locked`. The triggers report every change.

## Repository layout

```
components/tang_server/
  __init__.py          schema, triggers, actions, conditions
  binary_sensor.py
  sensor.py
  text_sensor.py
  button.py
  tang_server.h/.cpp   component: state machine, timers, backoff, activation task, entities
  http_handler.h/.cpp  AsyncWebHandler registered on web_server_base
  tang_crypto.h/.cpp   JWK parsing, adv signing, ECMR exchange
  key_store.h/.cpp     NVS record, PBKDF2 + AES-GCM encryption and decryption
  automation.h         trigger, action and condition classes
  tang_button.h        button classes
example/
  tang-ram.yaml
  tang-nvs.yaml
  tang-nvs-password.yaml
  secrets.yaml.example
tests/
  luks-clevis.nix      NixOS VM test: LUKS root unlocked by Clevis through the device
  tang-test.yaml       test firmware: short timers, every trigger and entity
  tang_api.py          drives tang-test.yaml through the ESPHome API
verify_tang.py
docs/esphome-component.md
```

The standalone ESP-IDF build (`main/`, `CMakeLists.txt`, `Makefile`, `sdkconfig.defaults`, `dependencies.lock`) is gone. The flake's dev shell has ESPHome, and its `checks.examples` runs `esphome config` on the three examples and `tests/tang-test.yaml`.

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

It is driven by environment variables:
- `TANG_URL`
- `TANG_TOKEN`, the device's `admin_token` if one is set
- `TANG_PASSWORD`, only for a `require_password` device

The test wipes, provisions fresh keys and, with `nvs`, activates them (with `TANG_PASSWORD` if set). It checks that the initrd unlocks the root through the device, then deactivates and checks that the next boot falls back to the passphrase prompt, now via a 503 from the device.

## Implementation history

The component was built in eight steps, each checked on an ESP32 (ESP-IDF 5.5.2, ESPHome 2026.8.0) with `verify_tang.py` before the next one started:

1. Component skeleton: `__init__.py` schema, the state machine, and the `web_server_base` handler with the Tang endpoints ported from the ESP-IDF firmware's `handlers.h` (`ram` only).
2. `verify_tang.py`: `--token` and the `ram` checks.
3. `nvs` storage without a password: the `pending` state, storing on the first `/activate`, activation at boot, `/wipe`, and the `nvs` checks.
4. `require_password`: PBKDF2 + AES-GCM in `key_store`, and the password checks.
5. Auth backoff, auto-deactivation, `/status` and the flash encryption warning.
6. Triggers, actions and conditions.
7. Entities and buttons.
8. Port `luks-clevis.nix`, update the flake and README (including the flash encryption guide), and delete the ESP-IDF build.

### Measurements

On an ESP32 at 240 MHz:
- **httpd stack:** the httpd task has 4352 bytes. The deepest request is a rejected `/provision`, which leaves about 820 bytes unused. Activations run in their own task with 8 KB.
- **PBKDF2:** about 100 µs per iteration: 2 s at the default 20000 iterations through the action or the button, about 3.4 s through `/activate` (see the verification notes below), 10 s at 100000.
- **Timers:** `idle_timeout: 20s` fired after 20.5 s and `max_active_time: 60s` after 60.4 s.
- **Stored record:** 697 bytes in plaintext for two P-521 keys, 764 bytes encrypted.

### Differences from the original design

Where the implementation differs from this design as it was first agreed, or from the plan that went with it, the difference is listed here with the reason. Where the design changed, the sections above already describe the result; this list says what it said before.

#### Build environment

- **ESPHome does not build through PlatformIO, and not with its own ESP-IDF.**
  - **Plan:** ESPHome builds with ESP-IDF 5.5.5, downloaded through PlatformIO into `~/.platformio`. Step 8 drops `esp-idf-full` and `nixpkgs-esp-dev`.
  - **Done:** ESPHome 2026.8 calls `idf.py` itself. The toolchain it downloads into `~/.cache/esphome/idf` cannot run on NixOS, so it builds with `esp-idf-full` 5.5.2 from the dev shell (`IDF_PATH`). The shell's `esphome` is a wrapper: it takes the environment of ESPHome's Nix wrapper (which also brings `esptool`), puts ESP-IDF's Python first on `PATH` and runs the unwrapped script. Without this, `idf.py` runs with a Python that lacks ESP-IDF's packages.
  - **Consequence:** the dev shell keeps `esp-idf-full`, and the flake keeps its second nixpkgs input, because `esp-idf-full` does not evaluate on a current nixpkgs. The README describes the build environment.
- **The dev shell leaks a `PYTHONPATH`.** A shell entered before the wrapper existed still carries ESPHome's Python 3.14 packages, and `verify-tang` (Python 3.13) then fails to import `cryptography`. Re-entering the shell fixes it.

#### Step 1

- **SHA-384/512 are requested from ESPHome** (`esp32.require_mbedtls_sha512()`). Not in the plan. ESPHome turns them off on ESP-IDF 6 unless a component asks, and ES512 (P-521) and the S384/S512 thumbprints need them.
- **One body buffer instead of a map keyed by the request pointer.** The httpd task serves one request at a time, so a map is not needed. A request whose body cannot be read to the end never reaches `handleRequest()`; the next request resets its partial body. Design updated.
- **405 for a component path with the wrong method**, with `Allow`. The design had no status for it; without it, such requests fell through to other handlers or got no answer. Design updated.
- **401 carries `WWW-Authenticate: Bearer`.** Not in the design.
- **No CORS header.** The component sends its own responses, so it does not get the `Access-Control-Allow-Origin: *` that `web_server_base` adds to responses sent through `send()`. Pages on other origins cannot read its answers.
- **The parser is stricter than the ESP-IDF firmware's `handlers.h`** beyond the planned whole-payload rejection: `kty` must be `EC`. Thumbprints are computed once per key at load instead of on every request.
- **The URL buffer (513 bytes) is resolved in a separate, non-inlined function**, so it is off the httpd stack while the crypto runs.
- **The stack high-water mark is logged after every operation**, not only after `/adv` and `/rec`. The deepest path turned out to be `/provision`.

#### Step 2

- **The `/status` details checks have nothing to check yet.** `/status` returns only the state until step 5. The checks pass now and become meaningful with the detailed view.
- **Each suite ends with `/deactivate` and then `/wipe`.** In step 2, P-256 ended with `/deactivate` and P-521 with `/wipe`; step 3 changed both to do both, so the `nvs` suites start clean.

#### Step 3

- **The ESP-IDF NVS API instead of ESPHome's preferences.**
  - **Plan:** `global_preferences->make_preference<>()` with a fixed hash, a fixed-size struct, `sync()` after the first `/activate` and after `/wipe`, and writes handed to the main loop with `defer()`.
  - **Done:** one NVS blob, key `keys`, in the namespace `tang_server`, written with `nvs_set_blob()` and `nvs_commit()` from the httpd task, and erased with `nvs_erase_key()`.
  - **Why:** preferences keep each write in a heap buffer until the next sync and free it without wiping, and comparing with the stored value reads it into another unwiped buffer. They cannot erase a record, and they may only be used from the main loop. NVS is thread-safe, so `/activate` answers only once the record is committed.
  - Design updated: [Stored key format](#stored-key-format) and the "Two threads" note.
- **The record has a variable size**, not a fixed-size struct: magic `TANG`, format version, payload.
- **The payload is written from the parsed keys** (`kty`, `crv`, `kid`, `key_ops`, `d`, `x`, `y`), not copied from the `/provision` body. It is still the JSON `/provision` accepts, so one parser checks both. This keeps the record small and free of anything else the client sent.
- **The reboot check was a reset**, through the serial adapter's EN line and later the EN button, not a power cycle. Both clear RAM and keep NVS.

#### Step 4

- **The default PBKDF2 iteration count is 20000, not 100000.** This is the fallback the plan named: 100000 iterations took 10 s per `/activate` on an ESP32 (about 100 µs each), 20000 take 2 s. The maximum is 10000000. Design updated.
- **PBKDF2 is its own loop over mbedTLS's HMAC**, verified against Python's `hashlib`. `mbedtls_pkcs5_pbkdf2_hmac_ext()` runs all iterations in one call and cannot yield; the loop yields every 1000 iterations.
- **The encrypted record starts with the magic number and has format version `2`.** The design had format version `1` at offset 0 and additional data over bytes 0–32. Now both formats share the 5-byte header, the version tells them apart, and the additional data is bytes 0–36. Design updated.
- **The GCM context is on the heap.** It is about 800 bytes, which the httpd stack does not have to spare.
- **`/activate` answers 409 for `active` and `unprovisioned` before it checks the password.** Before, a request without a password on an `unprovisioned` device got 400; the state is the more basic answer.
- **A record that does not match the configuration is ignored at boot**: plaintext with `require_password`, or encrypted without it. The device boots `unprovisioned` with `last_error` set, and the record stays. The design did not cover this case. Design updated.
- **The DRBG is seeded in `setup()`.** Its first use, gathering entropy, was the deepest call on the httpd stack.
- **`verify_tang.py --password` implies `--storage nvs`.**

#### Step 5

- **One backoff counter per secret**, the token and the key password, instead of one for the whole device. With one counter, someone holding the token could reset it with any valid request between password guesses. Design updated.
- **Backoff applies only to requests that check a secret.** The design said "every protected endpoint". Without `admin_token`, the management endpoints check nothing, so they are not refused; the public `/status`, `/adv` and `/rec` never are. Design updated.
- **Refusals are not failures**, so waiting is always enough to get through. They still count in the `auth_failure` counter, and in step 6 they fire `on_auth_failure`, as the design says.
- **`/status` reports the timers as `null`** while the server is not active or a timer is not configured. The design did not say. Design updated.
- **While `locked` without a password, `/status` lists the stored keys as they were when deactivated.** Reading and checking the record on every `/status` would run the key-pair check on the httpd stack. Design updated.
- **`loop()` uses `try_lock()`** and skips a round while `/activate` holds the lock, as planned in the risk table. Without timers, `loop()` is disabled.
- **The warnings are in `dump_config()`**, so they show at boot and whenever a log client connects. The plaintext warning also shows when keys are stored.
- **The test YAML is `tests/tang-test.yaml`.** It reads the examples' secrets through a `tests/secrets.yaml` symlink, which is git-ignored.
- **`verify_tang.py` waits out the backoff** after each failure it causes on purpose, and before it starts, so a lockout left by an earlier run does not fail the next one.

#### Step 6

- **Activations run in their own task**, from HTTP and from the action. The plan's fallback for the stack, a crypto task, applied to `/activate` only: the triggers added two call frames to its path, and the low point fell to 604 bytes. `/activate` now waits for the task, so the httpd stack holds no PBKDF2, AES-GCM or key check; the low point is 840 bytes again. `/provision`, `/adv` and `/rec` stay on the httpd stack. Design updated.
- **`tang_server.activate` returns at once.** Running PBKDF2 on the main loop would block it for 2 s, or 10 s at 100000 iterations, close to the loop watchdog. Its result shows in `on_activate`. Design updated.
- **One activation at a time.** A second `/activate` gets 409 while one runs; a second action logs a warning. Not in the design. Design updated.
- **The password checks of `tang_server.activate` run at build time**, in its code generation, because an action's schema cannot see the component's configuration. Design updated.
- **`on_activate` fires for 400 and 409 as well**: every attempt that passed the token check and the backoff, as the design says, including those that fail before the keys are touched. The design now says so explicitly.
- **`on_state_change` at boot fires once, with the state after loading the stored keys.** The changes while loading are not reported on their own. Design updated.
- **`on_auth_failure` from the action has the path `tang_server.activate`.** The design did not say. Design updated.
- **`tests/tang-short-timers.yaml` became `tests/tang-test.yaml`**, with a log line for every trigger and API actions for the actions and conditions. `tests/tang_api.py` calls those actions through the ESPHome API, as Home Assistant would.

#### Step 7

- **Checked through the ESPHome native API, not in Home Assistant.** No Home Assistant instance was at hand. `tests/tang_api.py` uses `aioesphomeapi`, the library Home Assistant's ESPHome integration is built on, to list the entities, watch their states, press the buttons and set the password text.
- **Entities show the latest state, not every change.** Publishing goes through one named `defer()`, so changes within one loop iteration are published once, and a state that lasts only milliseconds can be skipped. The triggers still report every change. Design updated.
- **The counters are atomics, and `last_error` has its own mutex**, so the main loop can publish them while an activation holds the lock for seconds.
- **The activate button clears the text right away on the press**, not after the attempt: the activation runs in the background, and the password is copied before. It also wipes the text entity's own copy of the string. Design updated.
- **The `password_id` check runs at build time**, like the action's password check. Design updated.
- **`last_error` was not exercised in this step's run**, because nothing in it fails in a way that sets it. Step 4 showed a boot error in the log and `dump_config()`; the entity uses the same value.
- **The examples gained entities**: the active binary sensor, the state and last error text sensors, and the buttons. `tang-nvs-password.yaml` also has the API action and the password text for unlocking from Home Assistant.
- **`tests/tang_api.py` has subcommands now**: `run`, `entities`, `watch`, `press` and `text`.

#### Verification after step 7

- **The warnings and `/status` look at NVS encryption**, not only at flash encryption. ESP-IDF leaves the `nvs` partition out of flash encryption, so the plain `nvs` setup's keys stay readable unless `CONFIG_NVS_ENCRYPTION` is on too. The warning used to say nothing once flash encryption was on. `/status` gains `nvs_encryption`. Design updated.
- **The activation task runs at priority 5, pinned to core 0 on dual-core chips.** At priority 1, PBKDF2 at 20000 iterations took 4.4 s instead of step 4's 2.0 s. At priority 5 it takes 2.0 s from the action, but still about 3.4 s from `/activate`. The step 4 firmware, flashed again, still took 2.0 s on the same board, and the current code with `/activate` back in the httpd task took 2.0 s too. So the extra time only appears while an HTTP request waits for the task; neither core affinity nor polling instead of blocking removed it. Moving PBKDF2 back to the httpd task would leave about 600 bytes of stack, so it stays in the task. Design updated.
- **OTA updates rolled back on the test board.** It browned out when booting new firmware, so the bootloader rolled back to the previous one, and its USB adapter dropped off at most boots. That is a power problem, not the component's; the timing experiments above were redone over USB.
- **`restore_value: true` on the password text would save the password in flash.** The example and the design now warn against it.

#### Step 8

- **`tests/luks-clevis.nix` sends empty POSTs with `curl --json ''`**, not `-d ''`, and every body with `--json`. It reads `key_storage` from the detailed `/status` to decide whether to activate, so it needs no variable for it.
- **The flake check also validates `tests/tang-test.yaml`**, besides the three examples. It runs ESPHome's own wrapper, which needs no ESP-IDF for validation.
- **`admin_token` and the action's `password` are marked `cv.sensitive()`**, so `esphome config` redacts them after ESPHome 2026.12 drops its name heuristic.
- **The flash encryption guide in the README is untested on hardware.** Enabling flash encryption burns eFuses irreversibly; it was written from the ESP-IDF 5.5 sources and documentation.
- **The implementation plan was deleted**, as planned; its deviations and measurements moved here.
