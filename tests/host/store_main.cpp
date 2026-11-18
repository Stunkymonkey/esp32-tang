// Host driver for key_store, called by test_store.py:
//
//   store_host pbkdf2 <password> <salt-hex> <iterations>   derived key, hex
//   store_host store <payload> [<password> <iterations>]   the record, hex
//   store_host load <record-hex> [<password>]              LoadResult, payload
//
// NVS is the in-memory stand-in from stubs/nvs.h.
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "key_store.h"
#include "nvs.h"

using namespace esphome::tang_server;

static std::vector<uint8_t> unhex(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
    bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  return bytes;
}

static std::string hex(const uint8_t *data, size_t len) {
  std::string out;
  char byte[3];
  for (size_t i = 0; i < len; i++) {
    snprintf(byte, sizeof(byte), "%02x", data[i]);
    out += byte;
  }
  return out;
}

int main(int argc, char **argv) {
  if (argc < 3)
    return 2;
  std::string command = argv[1];
  std::string error;
  KeyStore store;
  store.open();

  if (command == "pbkdf2" && argc > 4) {
    std::vector<uint8_t> salt = unhex(argv[3]);
    uint8_t key[32];
    if (pbkdf2_sha256(argv[2], salt.data(), salt.size(), std::stoul(argv[4]), key) != 0)
      return 1;
    std::cout << hex(key, sizeof(key)) << "\n";
    return 0;
  }

  if (command == "store") {
    std::string password = argc > 3 ? argv[3] : "";
    uint32_t iterations = argc > 4 ? std::stoul(argv[4]) : 0;
    if (!store.store(argv[2], error, argc > 3 ? &password : nullptr, iterations)) {
      std::cout << "error: " << error << "\n";
      return 1;
    }
    const auto &record = fake_nvs()["keys"];
    std::cout << hex(record.data(), record.size()) << "\n";
    return 0;
  }

  if (command == "load") {
    fake_nvs()["keys"] = unhex(argv[2]);
    std::string password = argc > 3 ? argv[3] : "";
    std::vector<uint8_t> payload;
    KeyStore::LoadResult result = store.load(payload, error, argc > 3 ? &password : nullptr);
    std::cout << static_cast<int>(result) << "\n" << std::string(payload.begin(), payload.end()) << "\n";
    return 0;
  }
  return 2;
}
