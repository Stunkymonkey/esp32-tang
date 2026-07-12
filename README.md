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
A python script `verify_tang.py` is included in this repository to demonstrate the full flow: generating keys, provisioning the device, and performing a test exchange.

## Useful Links

- [Tang Server (reference implementation)](https://github.com/latchset/tang)
