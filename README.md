# ESP32 Tang Server

an experimental tang server on the ESP32 device.
The server is implemented in C++ and uses mbedTLS and the ESP-IDF framework.

The goal is to implemented a tang server, and migrate this to the esphome framework.

## Usage

### activate server

```bash
curl http://<esp-ip>/pub > server_pub.jwk
echo -n "change-me" | jose jwe enc -I- -k server_pub.jwk -o request.jwe -i '{"protected":{"enc":"A128GCM"}}'
curl -X POST -H "Content-Type: application/json" -d @request.jwe http://<esp-ip>/activate
```
### test server

```bash
curl http://<esp-ip>/adv
```
