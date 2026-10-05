# Implementation plan: ESPHome `tang_server` component

Status: ready to start with step 1.

This is the working plan for building the component described in [esphome-component.md](esphome-component.md). The design says *what* the component does. This file says *how to get there from today's `main/`*: the toolchain, what code carries over and what changes in it, and what each step has to show before the next one starts. It is deleted in step 8, together with `main/`.

## Toolchain

- **ESPHome 2026.8.0**, from the flake input `nixpkgs-unstable`, is in the default dev shell. It builds with ESP-IDF 5.5.5, mbedTLS 3.6 and ArduinoJson 7.4.3.
- **The ESP-IDF build stays until step 8.** `main/` is the working reference: when the new firmware misbehaves, the old one can be flashed and run through `verify_tang.py` to compare. `esp-idf-full` no longer evaluates on a current nixpkgs, which is why ESPHome comes from a second nixpkgs input. Step 8 drops `nixpkgs-esp-dev`, points `nixpkgs` at a current revision and removes `nixpkgs-unstable`.
- **Building:** `esphome compile example/tang-ram.yaml`, and `esphome run example/tang-ram.yaml --device /dev/ttyUSB0` to flash and follow the log. The first compile downloads ESP-IDF and its toolchain through PlatformIO into `~/.platformio`. This part is not pinned by the flake.
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

### 2. `verify_tang.py` for `ram`

- `--token`, sent as `Authorization: Bearer`.
- Keeps sending every POST through `requests` with `json=` or no body, so `Content-Type` and `Content-Length` stay right.
- Starts with `/wipe` instead of `/deactivate`.
- The `ram` checks from [verify_tang.py](esphome-component.md#verify_tangpy): 503 while inactive, 401 without or with a wrong token, 409 on a second provision, `/wipe` leaving `unprovisioned`, the public `/status`.

**Done when:** it passes against the step 1 firmware, with and without `admin_token`.

### 3. `nvs` storage without a password

- `key_store.h/.cpp`: the record with magic number and format version, plaintext payload, `global_preferences->make_preference<>()` with a fixed hash, `sync()` right after the first `/activate` and after `/wipe`, overwriting with zeros before erasing.
- The `pending` and `locked` states, `/activate`, activation at boot, the boot checks of a stored record and `last_error`.
- `example/tang-nvs.yaml`; `verify_tang.py --storage nvs` with its checks.

**Done when:** the `nvs` checks pass, and `--check-reboot` brings the device back `active` with the same thumbprints.

### 4. `require_password`

- PBKDF2-HMAC-SHA256 and AES-256-GCM in `key_store`, with the header as additional data.
- 400 for a `password` that does not match `require_password`, 401 for a wrong one.
- `example/tang-nvs-password.yaml`; `verify_tang.py --password`.

**Done when:** the password checks pass, and the time of one `/activate` at the default 100000 iterations is measured. If it trips the task watchdog or takes much more than a few seconds, the default iterations come down and the design is updated with the measured number.

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
- `flake.nix`: drop `esp-idf-full`, `nixpkgs-esp-dev` and the ESP-IDF tooling from the shell; move to one current `nixpkgs`; add a check that runs `esphome config` on the three examples.
- README: ESPHome setup, `curl --json` in every example, the flash encryption guide.
- Delete `main/`, `CMakeLists.txt`, `Makefile`, `sdkconfig*`, `dependencies.lock`, `.envrc`'s ESP-IDF exports, and this file.

## Risks to check early

| Risk | Where it shows | Fallback |
|---|---|---|
| P-521 crypto overflows the 4352-byte httpd stack | step 1, stack high-water mark | a dedicated crypto task with its own stack, fed by a queue |
| PBKDF2 at 100000 iterations is too slow or trips the watchdog | step 4, timing | lower default; feed the watchdog between PBKDF2 rounds |
| ESPHome changes the web server API again | any update of `nixpkgs-unstable` | the flake pins it; re-check [Request handling](esphome-component.md#request-handling) before bumping |
