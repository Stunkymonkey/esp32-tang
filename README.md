# ESP32 Tang Server

An experimental implementation of a **Tang server** running directly on an **ESP32** device.
The server is written in **C++**, using **mbedTLS** and the **ESP-IDF** framework.

## Overview

The goal of this project is to implement the core Tang functionality — **advertisement** and **activation** — directly on the ESP32, demonstrating that a small embedded system can operate as a self-contained cryptographic service.

In future iterations, this implementation will be **integrated into ESPHome**, enabling seamless use with **Home Assistant**. This will allow ESP-based devices to provide secure key exchange mechanisms within **IoT** or **home automation** environments.
Because HTTPS/SSL will be handled by ESPHome, it is **not** a primary focus of this standalone implementation.

A distributed deployment with multiple ESP32 Tang servers could further enhance security by requiring responses from several devices for key recovery, reducing single points of failure.

## Usage

### Activate the server

```bash
curl http://<esp-ip>/pub > server_pub.jwk
echo -n "change-me" | jose jwe enc -I- -k server_pub.jwk -o request.jwe -i '{"protected":{"enc":"A128GCM"}}'
curl -X POST -H "Content-Type: application/json" -d @request.jwe http://<esp-ip>/activate
```

### Test the server

```bash
curl http://<esp-ip>/adv
```

## Useful Links

- [Tang Server (reference implementation)](https://github.com/latchset/tang)
