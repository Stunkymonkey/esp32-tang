# Implementation plan: ESPHome `tang_server` component

Status: steps 1 to 4 are done; step 5 is next.

This is the working plan for building the component described in [esphome-component.md](esphome-component.md). The design says *what* the component does. This file says *how to get there from today's `main/`*: the toolchain, what code carries over and what changes in it, and what each step has to show before the next one starts. Where the work differs from the plan, [Deviations from the plan](#deviations-from-the-plan) records how and why; step 8 moves that section into the design. This file is deleted in step 8, together with `main/`.

## Toolchain

- **ESPHome 2026.8.0**, from the flake input `nixpkgs-unstable`, is in the default dev shell. It brings mbedTLS 3.6 and ArduinoJson 7.4.3.
- **ESPHome builds with `esp-idf-full` from `nixpkgs-esp-dev` (ESP-IDF 5.5.2).** ESPHome 2026.8 calls `idf.py` directly rather than going through PlatformIO. Without `IDF_PATH` it downloads ESP-IDF 5.5.5 and a prebuilt toolchain into `~/.cache/esphome/idf`, and that toolchain cannot run on NixOS. With `IDF_PATH` set, as in the dev shell, it uses that ESP-IDF instead. It runs `idf.py` with the first `python` on `PATH`, but its Nix wrapper puts its own Python first, and that Python lacks ESP-IDF's packages. So the dev shell's `esphome` is a small wrapper: it calls the unwrapped script with ESP-IDF's Python first on `PATH`.
- **The ESP-IDF build stays until step 8.** `main/` is the working reference: when the new firmware misbehaves, the old one can be flashed and run through `verify_tang.py` to compare. `esp-idf-full` no longer evaluates on a current nixpkgs, which is why ESPHome comes from a second nixpkgs input.
- **Building:** `esphome compile example/tang-ram.yaml`, and `esphome run example/tang-ram.yaml --device /dev/ttyUSB0` to flash and follow the log. Both need the dev shell.
- **The examples load the component from the tree:**

  ```yaml
  external_components:
    - source:
        type: local
        path: ../components
  ```

- **Git:** `.esphome/` (build output) and `example/secrets.yaml` are ignored. `secrets.yaml.example` is committed.

## What carries over

Most of `helpers.h` and the protocol half of `handlers.h` move into `tang_crypto` almost unchanged. Everything Arduino- or WebServer-specific goes away.

| Today | After | Changes |
|---|---|---|
| `helpers.h`: `init_rng`, `get_rng_context`, `cleanup_rng` | `tang_crypto` | The DRBG is used from the httpd task and the main loop, so it is only touched under the component's mutex. |
| `helpers.h`: `ScopedWipe` | `tang_crypto.h` | Works on `std::string` and `std::vector<uint8_t>` instead of Arduino `String`. |
| `helpers.h`: `base64_url_encode`, `base64_url_decode` | `tang_crypto` | `std::string` instead of `String`. Still mbedTLS base64. |
| `helpers.h`: `TANG_THP_ALGS`, `jwk_canonical_ec`, `jwk_thumbprint` | `tang_crypto` | `std::string` only. |
| `helpers.h`: `compute_ecdh_shared_secret`, `sign_data`, `ec_keypair_matches` | `tang_crypto` | `ESP_LOGx` instead of `DEBUG_PRINTF`. |
| `helpers.h`: `generate_ec_keypair`, `compute_ec_public_key`, `print_hex` | dropped | Unused, P-256 only, and on-device key generation is out of scope. |
| `TangServer.h`: `TangKey`, `KeyUsage`; `handlers.h`: `key_matches_id` | `tang_crypto.h` | `kid` stays. |
| `handlers.h`: `handleAdv` | `tang_crypto`: build the signed advertisement | Returns a status and a body instead of calling `server_http.send`, so it has no HTTP dependency. |
| `handlers.h`: `handleRec` | `tang_crypto`: ECMR exchange | Same: input is the thumbprint and the body, output a status and a body. |
| `handlers.h`: parsing loop of `handleProvision` | `tang_crypto`: parse a `{"keys": [...]}` payload | One parser for `/provision` and the stored record. **Behaviour change:** today a bad key is skipped and the rest are kept; the design rejects the whole payload with 400 and requires one signing and one exchange key. |
| `handlers.h`: `handleDeactivate`, `deactivate_server` | `tang_server`: deactivate and wipe | Take a reason and drive the state machine. |
| `TangServer.h`: Wi-Fi, AP fallback, `NUKE`, `setup`/`loop`; `handlers.h`: `handleReboot`, `handleNotFound`; `main.cpp` | dropped | ESPHome's `wifi`, `captive_portal` and `restart` replace them. |

### ArduinoJson 6 → 7

ESPHome brings ArduinoJson 7, so every JSON call changes:
- `DynamicJsonDocument doc(n)` becomes `JsonDocument doc`; documents grow as needed.
- `createNestedArray("k")` becomes `doc["k"].to<JsonArray>()`, and `createNestedObject()` becomes `arr.add<JsonObject>()`.
- `String x = doc["x"]` becomes `doc["x"] | ""` or `doc["x"].as<std::string>()`.
- **Zero-copy parsing is gone.** Today `/provision` parses its body in place, so `d` lives only in the body buffer that `ScopedWipe` clears. With ArduinoJson 7 the document copies every string into its own memory, so every document that can hold a private key uses the wiping allocator from [Secrets in RAM](esphome-component.md#secrets-in-ram).

## Code structure

- **`tang_crypto` knows nothing about HTTP or ESPHome entities.** It takes bytes and keys and returns results. That keeps it the same code for HTTP and for the `tang_server.activate` action.
- **`key_store` knows nothing about HTTP either.** It turns a payload into a record and back, with or without a password.
- **`http_handler` only does HTTP:** matching paths, collecting bodies, checking the token and backoff, and turning results into responses. It calls into `TangServer`.
- **`TangServer` owns the state.** It holds the keys, the state machine, the timers, the counters and the entities. Every public method that touches keys or state takes the mutex. Methods called from the httpd task hand triggers, entity updates and preference writes to the main loop with `defer()`.

## Steps

The numbers match [Implementation order](esphome-component.md#implementation-order). Each step ends with a commit, and with a run of `verify_tang.py` against a real device once step 2 has added the checks it needs.

### 1. Skeleton, `ram` only

- `components/tang_server/__init__.py`: the full config schema from the design, so the examples validate from the start. Only `key_storage: ram` is accepted for now; `nvs`, `require_password` and the timers fail validation with "not implemented yet". `DEPENDENCIES = ["network"]`, `AUTO_LOAD = ["web_server_base", "json"]`.
- `tang_crypto.h/.cpp`: the port from the table above, with the wiping JSON allocator.
- `http_handler.h/.cpp`: `canHandle()` for `/adv`, `/adv/`, `/adv/<thp>`, `/rec/<thp>`, `/provision`, `/deactivate`, `/wipe`, `/status`; body collection in `handleBody()` with the 4096-byte limit; the status line table; 415 for form bodies. Registered with `add_handler_without_auth()`, after `init()`.
- `tang_server.h/.cpp`: the states `unprovisioned` and `active`, `admin_token` with a constant-time compare, a minimal `/status` (`state` only).
- `example/tang-ram.yaml` and `secrets.yaml.example`.

**Done when:**
- `esphome config` and `esphome compile` pass for `tang-ram.yaml`;
- today's `verify_tang.py` passes against the device unchanged. It already sends JSON with `Content-Type` and gives empty POSTs a `Content-Length: 0`, and its mismatched-key check expects the 400 the new parser returns;
- `clevis encrypt tang` and `clevis decrypt` work against the device;
- the httpd stack high-water mark during a P-521 `/adv` and `/rec` is logged and leaves room. If not, move the crypto to its own task before going on.

  Measured on an ESP32 (ESP-IDF 5.5.2, log level `DEBUG`): at least 816 of the 4352 bytes stay unused. The low point is the `d`/`x`/`y` check of a rejected `/provision`, not P-521 `/adv` or `/rec`. That is enough for now; step 4 measures again, since PBKDF2 and AES-GCM run on the same stack.

### 2. `verify_tang.py` for `ram`

- `--token`, sent as `Authorization: Bearer`.
- Keeps sending every POST through `requests` with `json=` or no body, so `Content-Type` and `Content-Length` stay right.
- Starts with `/wipe` instead of `/deactivate`.
- The `ram` checks from [verify_tang.py](esphome-component.md#verify_tangpy): 503 while inactive, 401 without or with a wrong token, 409 on a second provision, `/wipe` leaving `unprovisioned`, the public `/status`.

**Done when:** it passes against the step 1 firmware, with and without `admin_token`.

### 3. `nvs` storage without a password

- `key_store.h/.cpp`: the record with magic number and format version and a plaintext payload, written with the ESP-IDF NVS API in its own namespace and committed right away, overwritten with zeros before it is erased. Not ESPHome's preferences: see [Stored key format](esphome-component.md#stored-key-format).
- The `pending` and `locked` states, `/activate`, activation at boot, the boot checks of a stored record and `last_error`.
- `example/tang-nvs.yaml`; `verify_tang.py --storage nvs` with its checks.

**Done when:** the `nvs` checks pass, and `--check-reboot` brings the device back `active` with the same thumbprints.

Done on an ESP32, with the reboot done as a reset through the serial adapter's EN line. In step 4, an encrypted record booted by the plain `nvs` firmware left the device `unprovisioned` with `last_error` set, and the record stayed: the `require_password` firmware then unlocked it.

### 4. `require_password`

- PBKDF2-HMAC-SHA256 and AES-256-GCM in `key_store`, with the header as additional data.
- 400 for a `password` that does not match `require_password`, 401 for a wrong one.
- `example/tang-nvs-password.yaml`; `verify_tang.py --password`.

**Done when:** the password checks pass, and the time of one `/activate` at the default 100000 iterations is measured. If it trips the task watchdog or takes much more than a few seconds, the default iterations come down and the design is updated with the measured number.

Done on an ESP32. PBKDF2 has its own loop over mbedTLS's HMAC, because `mbedtls_pkcs5_pbkdf2_hmac_ext()` cannot yield; it yields every 1000 iterations and never tripped the watchdog. 100000 iterations took 10 s, so the default is now 20000 (2 s). The DRBG is now seeded in `setup()`: its first use was the deepest call on the httpd stack. The low point is now `/activate` from `locked` (decrypt, then the `d`/`x`/`y` check), with 728 bytes unused. Steps 5 to 7 add to the request path, so they watch this number; the fallback is still a crypto task.

### 5. Backoff, auto-deactivation, `/status`, flash encryption

- `auth_backoff` with 429 and `Retry-After`.
- `max_active_time` and `idle_timeout` in `loop()`, with wrap-safe `millis()` arithmetic.
- The detailed `/status`, including `flash_encryption` from `esp_flash_encryption_enabled()`.
- The boot and store warnings for plaintext keys without flash encryption, and for a missing `admin_token`.

**Done when:** `verify_tang.py --check-lockout` passes, and the timers are checked with short values in a test YAML.

### 6. Triggers, actions, conditions

- `automation.h` and the codegen in `__init__.py` for every trigger, action and condition in [Automations](esphome-component.md#automations).
- All triggers fire on the main loop.

**Done when:** a test YAML that logs every trigger shows each one firing for the matching `verify_tang.py` run, and `tang_server.activate` unlocks a `require_password` device through the API.

### 7. Entities and buttons

- `binary_sensor.py`, `sensor.py`, `text_sensor.py`, `button.py` and their C++ counterparts.
- The activate button reads and then clears the password text entity.

**Done when:** all entities show up in Home Assistant and follow a `verify_tang.py` run.

### 8. Clean-up

- `tests/luks-clevis.nix`: `TANG_TOKEN` and `TANG_PASSWORD`; `/wipe` before provisioning; `curl --json` for `/provision`; `-d ''` for empty POSTs. Today's bare `curl -X POST .../deactivate` sends no `Content-Length` and gets 411 from ESPHome.
- `flake.nix`: remove the `idf.py`/`make` tooling and its shell hook from the shell, and add a check that runs `esphome config` on the three examples. `esp-idf-full` stays, because ESPHome builds with it (see [Toolchain](#toolchain)). Moving to one current `nixpkgs` needs an ESP-IDF that evaluates there, either a fixed `nixpkgs-esp-dev` or an FHS environment for ESPHome's own download.
- README: ESPHome setup, `curl --json` in every example, the flash encryption guide.
- Move [Deviations from the plan](#deviations-from-the-plan) into [esphome-component.md](esphome-component.md) as a section on how the implementation differs from the original design, so the reasons outlive this file.
- Delete `main/`, `CMakeLists.txt`, `Makefile`, `sdkconfig*`, `dependencies.lock`, `.envrc`'s ESP-IDF exports, and this file.

## Deviations from the plan

Where the work differs from this plan or from the design as it stood before the step, the difference is listed here with the reason. Where the design changed, [esphome-component.md](esphome-component.md) is updated too; this list says what it said before. The measured results stay with each step above.

### Build environment

- **ESPHome does not build through PlatformIO, and not with its own ESP-IDF.**
  - **Plan:** ESPHome builds with ESP-IDF 5.5.5, downloaded through PlatformIO into `~/.platformio`. Step 8 drops `esp-idf-full` and `nixpkgs-esp-dev`.
  - **Done:** ESPHome 2026.8 calls `idf.py` itself. The toolchain it downloads into `~/.cache/esphome/idf` cannot run on NixOS, so it builds with `esp-idf-full` 5.5.2 from the dev shell (`IDF_PATH`). The shell's `esphome` is a wrapper: it takes the environment of ESPHome's Nix wrapper (which also brings `esptool`), puts ESP-IDF's Python first on `PATH` and runs the unwrapped script. Without this, `idf.py` runs with a Python that lacks ESP-IDF's packages.
  - **Consequence:** step 8 keeps `esp-idf-full`. [Toolchain](#toolchain), step 8 and the risk table are updated.
- **The dev shell leaks a `PYTHONPATH`.** A shell entered before the wrapper existed still carries ESPHome's Python 3.14 packages, and `verify-tang` (Python 3.13) then fails to import `cryptography`. Re-entering the shell fixes it.

### Step 1

- **SHA-384/512 are requested from ESPHome** (`esp32.require_mbedtls_sha512()`). Not in the plan. ESPHome turns them off on ESP-IDF 6 unless a component asks, and ES512 (P-521) and the S384/S512 thumbprints need them.
- **One body buffer instead of a map keyed by the request pointer.** The httpd task serves one request at a time, so a map is not needed. A request whose body cannot be read to the end never reaches `handleRequest()`; the next request resets its partial body. Design updated.
- **405 for a component path with the wrong method**, with `Allow`. The design had no status for it; without it, such requests fell through to other handlers or got no answer. Design updated.
- **401 carries `WWW-Authenticate: Bearer`.** Not in the design.
- **No CORS header.** The component sends its own responses, so it does not get the `Access-Control-Allow-Origin: *` that `web_server_base` adds to responses sent through `send()`. Pages on other origins cannot read its answers.
- **The parser is stricter than today's `handlers.h`** beyond the planned whole-payload rejection: `kty` must be `EC`. Thumbprints are computed once per key at load instead of on every request.
- **The URL buffer (513 bytes) is resolved in a separate, non-inlined function**, so it is off the httpd stack while the crypto runs.
- **The stack high-water mark is logged after every operation**, not only after `/adv` and `/rec`. The deepest path turned out to be `/provision`.

### Step 2

- **The `/status` details checks have nothing to check yet.** `/status` returns only the state until step 5. The checks pass now and become meaningful with the detailed view.
- **Each suite ends with `/deactivate` and then `/wipe`.** In step 2, P-256 ended with `/deactivate` and P-521 with `/wipe`; step 3 changed both to do both, so the `nvs` suites start clean.

### Step 3

- **The ESP-IDF NVS API instead of ESPHome's preferences.**
  - **Plan:** `global_preferences->make_preference<>()` with a fixed hash, a fixed-size struct, `sync()` after the first `/activate` and after `/wipe`, and writes handed to the main loop with `defer()`.
  - **Done:** one NVS blob, key `keys`, in the namespace `tang_server`, written with `nvs_set_blob()` and `nvs_commit()` from the httpd task, and erased with `nvs_erase_key()`.
  - **Why:** preferences keep each write in a heap buffer until the next sync and free it without wiping, and comparing with the stored value reads it into another unwiped buffer. They cannot erase a record, and they may only be used from the main loop. NVS is thread-safe, so `/activate` answers only once the record is committed.
  - Design updated: [Stored key format](esphome-component.md#stored-key-format) and the "Two threads" note.
- **The record has a variable size**, not a fixed-size struct: magic `TANG`, format version, payload.
- **The payload is written from the parsed keys** (`kty`, `crv`, `kid`, `key_ops`, `d`, `x`, `y`), not copied from the `/provision` body. It is still the JSON `/provision` accepts, so one parser checks both. This keeps the record small and free of anything else the client sent.
- **The reboot check was a reset**, through the serial adapter's EN line and later the EN button, not a power cycle. Both clear RAM and keep NVS.

### Step 4

- **The default PBKDF2 iteration count is 20000, not 100000.** This is the fallback the plan named: 100000 iterations took 10 s per `/activate` on an ESP32 (about 100 µs each), 20000 take 2 s. The maximum is 10000000. Design updated.
- **PBKDF2 is its own loop over mbedTLS's HMAC**, verified against Python's `hashlib`. `mbedtls_pkcs5_pbkdf2_hmac_ext()` runs all iterations in one call and cannot yield; the loop yields every 1000 iterations.
- **The encrypted record starts with the magic number and has format version `2`.** The design had format version `1` at offset 0 and additional data over bytes 0–32. Now both formats share the 5-byte header, the version tells them apart, and the additional data is bytes 0–36. Design updated.
- **The GCM context is on the heap.** It is about 800 bytes, which the httpd stack does not have to spare.
- **`/activate` answers 409 for `active` and `unprovisioned` before it checks the password.** Before, a request without a password on an `unprovisioned` device got 400; the state is the more basic answer.
- **A record that does not match the configuration is ignored at boot**: plaintext with `require_password`, or encrypted without it. The device boots `unprovisioned` with `last_error` set, and the record stays. The design did not cover this case. Design updated.
- **The DRBG is seeded in `setup()`.** Its first use, gathering entropy, was the deepest call on the httpd stack.
- **`verify_tang.py --password` implies `--storage nvs`.**

## Risks to check early

| Risk | Where it shows | Fallback |
|---|---|---|
| P-521 crypto overflows the 4352-byte httpd stack | step 1, stack high-water mark | a dedicated crypto task with its own stack, fed by a queue |
| PBKDF2 at 100000 iterations is too slow or trips the watchdog | step 4, timing: 10 s, no watchdog | done: default 20000 (2 s); yields every 1000 iterations |
| Long `/activate` holds the mutex for seconds | step 5, timers in `loop()` | `loop()` uses `try_lock()` and skips a round; a blocking lock would stall the main loop |
| ESPHome expects a newer ESP-IDF than `esp-idf-full` provides (5.5.5 vs 5.5.2 today) | any compile after a bump | bump `nixpkgs-esp-dev`, or build in an FHS environment with ESPHome's own ESP-IDF |
| ESPHome changes the web server API again | any update of `nixpkgs-unstable` | the flake pins it; re-check [Request handling](esphome-component.md#request-handling) before bumping |
