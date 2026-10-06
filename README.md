# ESP32 Tang Server

A [Tang](https://github.com/latchset/tang) server on an ESP32, as an [ESPHome](https://esphome.io) external component. Tang is the network service that [Clevis](https://github.com/latchset/clevis) uses to unlock LUKS-encrypted disks automatically while they are on the right network. With this component, a small ESP32 can be that service, managed from Home Assistant.

The design and the reasons behind it are in [docs/esphome-component.md](docs/esphome-component.md).

> **Developed with LLMs.** Large parts of this project, including the ESPHome component, its tests and its documentation, were written with the help of large language models (Anthropic's Claude) and tested on an ESP32. It is an experimental project that protects disk-encryption keys: read the code and the [design](docs/esphome-component.md) before you rely on it.

## Overview

- **Tang protocol:** `/adv` and `/rec` as tangd serves them, with P-256 and P-521 keys and every thumbprint hash tangd accepts. Clevis works against it unchanged.
- **Keys from off-device:** you create the keys with `jose` and upload them with `/provision`. The device never generates keys.
- **Three setups**, fixed in the YAML:

  | | `key_storage: ram` | `key_storage: nvs` | `nvs` + `require_password: true` |
  |---|---|---|---|
  | Keys after a power loss | gone, provision again | served again right away | stored encrypted; served after `/activate` with the password |
  | Stolen device | holds nothing | serves the keys wherever it is powered | stays locked |

- **Management:** `/provision`, `/activate`, `/deactivate`, `/wipe` and `/status`, protected by a Bearer token (`admin_token`), with backoff and lockout after failed attempts. Optional auto-deactivation after a time or when idle.
- **Home Assistant:** sensors for state and counters, buttons, triggers for every event, and actions such as `tang_server.activate`, so Home Assistant can unlock the device after a reboot.

**Plain HTTP only.** ESPHome has no TLS server on ESP32, so the token, the key password and the private keys on `/provision` cross the network in cleartext. Use the device on a trusted LAN.

## Getting started

### Build environment

```bash
nix develop
```

The dev shell has ESPHome and the tools below. On NixOS, ESPHome cannot run the toolchain it would download, so it builds with the shell's ESP-IDF instead; the shell's `esphome` takes care of that. Without Nix, a normal ESPHome installation works.

### Configure and flash

```bash
cp example/secrets.yaml.example example/secrets.yaml   # then fill it in
esphome run example/tang-nvs-password.yaml --device /dev/ttyUSB0
```

Pick the example for your setup: [tang-ram.yaml](example/tang-ram.yaml), [tang-nvs.yaml](example/tang-nvs.yaml) or [tang-nvs-password.yaml](example/tang-nvs-password.yaml). Later updates can go over the air: `esphome run example/<setup>.yaml --device <esp-ip>`.

To use the component in your own configuration, load it from this repository:

```yaml
external_components:
  - source: github://Stunkymonkey/esp32-tang
    components: [tang_server]

tang_server:
  key_storage: nvs
  require_password: true
  admin_token: !secret tang_admin_token
```

If an update over the air does not seem to take effect, check the log for "OTA rollback detected" and "brownout": a board whose supply drops when Wi-Fi starts resets before the new firmware is confirmed, and the bootloader goes back to the old one. A better USB cable, port or power supply fixes it.

## Usage

The examples below set `T` to the `admin_token`. Every POST uses `curl --json`: the device needs `Content-Type: application/json` for a body and `Content-Length` even for an empty one.

```bash
T=<admin_token>
auth=(-H "Authorization: Bearer $T")
```

### Provision and activate

Create a signing and an exchange key, and back them up: they are the only way to rebuild the server if the device is lost.

```bash
jose jwk gen -i '{"alg":"ES512"}' -o sign.jwk
jose jwk gen -i '{"alg":"ECMR"}' -o exc.jwk
jq -s '{keys: .}' sign.jwk exc.jwk > keys.json

curl "${auth[@]}" --json @keys.json http://<esp-ip>/provision
```

With `ram`, the server is now active. With `nvs`, the keys wait in RAM until the first `/activate` stores them:

```bash
curl "${auth[@]}" --json '' http://<esp-ip>/activate                        # nvs
curl "${auth[@]}" --json '{"password": "..."}' http://<esp-ip>/activate     # nvs + require_password
```

The first `/activate` with a password decides it; there is no confirmation. With `require_password`, every boot needs `/activate` with the password again.

### Bind a disk with Clevis

```bash
clevis luks bind -d /dev/sdX tang '{"url": "http://<esp-ip>"}'
```

### Manage

```bash
curl "${auth[@]}" http://<esp-ip>/status                    # details; without the token only the state
curl "${auth[@]}" --json '' http://<esp-ip>/deactivate      # drop the keys from RAM; stored keys stay
curl "${auth[@]}" --json '' http://<esp-ip>/wipe            # drop them from RAM and storage
```

Replacing keys always takes a `/wipe` first; `/provision` refuses while keys are on the device. All endpoints and status codes are described in [the design](docs/esphome-component.md#http-endpoints).

### Home Assistant

The examples expose the state, the last error and buttons to deactivate and wipe. [tang-nvs-password.yaml](example/tang-nvs-password.yaml) also has:
- an API action `tang_activate`, for a Home Assistant automation that unlocks the device with the password from Home Assistant's secrets when it comes online and reports `locked`;
- a password text and an activate button for unlocking by hand. The text is cleared on every press.

All entities, triggers, actions and conditions are listed in [the design](docs/esphome-component.md#automations).

## Flash encryption

Without it, anyone who holds the device can read its flash. With plain `nvs` storage, that exposes the Tang keys; with `require_password`, only the encrypted record, which then has to withstand offline password guessing. The component warns at boot while keys are stored in plaintext in unencrypted NVS, and `/status` reports `flash_encryption` and `nvs_encryption`.

Flash encryption alone does not cover the keys: ESP-IDF leaves the `nvs` partition out of it. NVS encryption is a separate option, and its keys go into an extra `nvs_keys` partition that flash encryption protects. Both are needed:

```yaml
esp32:
  board: esp32dev
  framework:
    type: esp-idf
    sdkconfig_options:
      CONFIG_SECURE_FLASH_ENC_ENABLED: y
      CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT: y
      CONFIG_NVS_ENCRYPTION: y
      # The bootloader grows with flash encryption; make room for it.
      CONFIG_PARTITION_TABLE_OFFSET: "0xB000"
  partitions:
    - name: nvs_keys
      type: data
      subtype: nvs_keys
      size: 0x1000
```

**Read this before you flash it.** This configuration builds, but it has not been tried on a device, because enabling flash encryption burns eFuses and cannot be undone. See ESP-IDF's [flash encryption](https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/security/flash-encryption.html) and [NVS encryption](https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/api-reference/storage/nvs_encryption.html) guides.
- **Flash it over USB.** The partition table changes, which an update over the air cannot do. The first boot encrypts the flash in place; do not cut the power while it does.
- **NVS starts empty**, including Wi-Fi settings from the captive portal and the stored Tang keys. Provision and activate again.
- **Afterwards, update over the air.** A plain USB flash of an encrypted device does not boot.
- **Development mode** still allows re-flashing with `esptool --encrypt`. Once everything works, switch to `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE`, which closes that door for good.

Even with encryption, a device with plain `nvs` storage serves its keys to whoever powers it up. Turn off the captive portal and the fallback access point on such a device, so that it cannot be pointed at another network.

## Debugging

- **Logs:** `esphome logs example/<setup>.yaml` follows the device log over the network, or `--device /dev/ttyUSB0` over USB, which also shows crashes and the boot. At the default `DEBUG` level, the component logs every request with its status, every state change, and why a request was refused. It never logs keys, the token or the password.
- **State:** `curl "${auth[@]}" http://<esp-ip>/status` shows the state, the keys' thumbprints, the timers, the backoff and the counters.
- **Events:** [tests/tang-test.yaml](tests/tang-test.yaml) logs every trigger and has every entity; `tests/tang_api.py` watches them through the ESPHome API (see [Verification](#verification)).
- **Updates that do not stick:** see the brownout note under [Configure and flash](#configure-and-flash).

### Web UI, temporarily

ESPHome's web UI shows the entities and the log in a browser, and has the deactivate, wipe and activate buttons. It is useful while setting up or debugging a device, but leave it out of a device in use:
- it is plain HTTP, so its login travels in cleartext, and that login is enough to wipe the keys;
- once a browser has the login, any web page it opens could send requests to the device, including a press on the wipe button;
- everything it shows is also available through Home Assistant, over the encrypted ESPHome API.

To enable it for a while, add this to the device's YAML and `web_password` to `secrets.yaml`:

```yaml
web_server:
  port: 80
  local: true            # serve the page from the device, not from the internet
  auth:
    username: admin
    password: !secret web_password
```

The UI's login does not apply to the Tang endpoints, which Clevis must reach without one; they keep checking `admin_token`. Remove the block and flash again when you are done.

## Verification

Both checks below talk to a real ESP32 on your network and **replace the keys on it**: they wipe the device, provision their own test keys, and leave it wiped or deactivated. Provision your own keys again afterwards.

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
1. It wipes the device, provisions fresh keys and, with `key_storage: nvs`, activates them.
2. It checks that the initrd unlocks the root through the ESP32.
3. It then deactivates the device and checks that the next boot falls back to the passphrase prompt, as the device now answers 503.

This exercises the real Clevis client, including the blinded exchange it performs.

The VM reaches the ESP32 through QEMU's user-mode network, which the Nix sandbox blocks. The test is therefore exposed as a package rather than a flake check, and has to be run through its driver on a Linux host with KVM:

```bash
nix build .#luks-clevis-test.driver
TANG_URL=http://<esp-ip> TANG_TOKEN=<admin_token> TANG_PASSWORD=<password> ./result/bin/nixos-test-driver
```

Leave out `TANG_TOKEN` if the device has no `admin_token`, and `TANG_PASSWORD` unless it has `require_password`.

The driver writes VM disk images into the current directory, so run it from a scratch directory. To step through the test interactively, build `.#luks-clevis-test.driverInteractive` instead, then call `test_script()` or drive `machine` from the Python prompt.


### Without a device: `nix flake check` and CI

`nix flake check` runs two checks that need no device:
- `examples`: `esphome config` on the three examples and `tests/tang-test.yaml`, with dummy secrets;
- `host-tests`: [tests/host/run.sh](tests/host/run.sh) builds `tang_crypto` and `key_store` for Linux, with AddressSanitizer and UndefinedBehaviorSanitizer, and checks them against Python's `cryptography` and `hashlib`: `/adv` signatures, `/rec` exchanges, thumbprints, key parsing, PBKDF2 and the stored record's format, decrypted independently.

GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs `nix flake check` and builds the firmware for every example and the test configuration, on every pull request and on `main`. The checks against a device above stay manual: run them before merging changes to the component.

## Useful Links

- [Tang server (reference implementation)](https://github.com/latchset/tang)
- [Clevis](https://github.com/latchset/clevis)
- [ESPHome external components](https://esphome.io/components/external_components/)
