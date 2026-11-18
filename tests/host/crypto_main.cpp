// Host driver for tang_crypto, called by test_crypto.py:
//
//   crypto_host <keys.json> parse                   thumbprints (S1, S256) per key
//   crypto_host <keys.json> roundtrip               serialize_keys() and back
//   crypto_host <keys.json> adv [thp]               build_adv()
//   crypto_host <keys.json> rec <thp> <body.json>   exchange()
//
// Prints the status on the first line, then the rest of the result. A
// payload that parse_keys() rejects prints 400 and the error for any command.
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "tang_crypto.h"

using namespace esphome::tang_server;

static std::string slurp(const char *path) {
  std::ifstream file(path);
  std::stringstream content;
  content << file.rdbuf();
  return content.str();
}

int main(int argc, char **argv) {
  if (argc < 3)
    return 2;
  std::string keys_json = slurp(argv[1]);
  std::string command = argv[2];
  std::vector<TangKey> keys;
  std::string error;
  if (!parse_keys(keys_json.data(), keys_json.size(), keys, error)) {
    std::cout << 400 << "\n" << error << "\n";
    return 0;
  }

  if (command == "parse") {
    std::cout << 200 << "\n";
    for (const auto &key : keys)
      std::cout << key.thp_by_alg("S1") << " " << key.thp_by_alg("S256") << "\n";
    return 0;
  }

  if (command == "roundtrip") {
    std::string json = serialize_keys(keys);
    std::vector<TangKey> again;
    bool ok = parse_keys(json.data(), json.size(), again, error) && again.size() == keys.size();
    for (size_t i = 0; ok && i < keys.size(); i++) {
      ok = again[i].thp == keys[i].thp && again[i].kid == keys[i].kid && again[i].usage == keys[i].usage &&
           memcmp(again[i].private_key, keys[i].private_key, keys[i].key_len) == 0;
    }
    std::cout << (ok ? 200 : 500) << "\n" << json.size() << "\n";
    return 0;
  }

  Result result{0, "", ""};
  if (command == "adv") {
    result = build_adv(keys, argc > 3 ? argv[3] : "");
  } else if (command == "rec" && argc > 4) {
    std::string body = slurp(argv[4]);
    result = exchange(keys, argv[3], body.data(), body.size());
  } else {
    return 2;
  }
  std::cout << result.status << "\n" << result.content_type << "\n" << result.body << "\n";
  return 0;
}
