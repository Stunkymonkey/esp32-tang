#!/usr/bin/env bash
# Builds tang_crypto and key_store for the host, with AddressSanitizer and
# UndefinedBehaviorSanitizer, and checks them with test_crypto.py and
# test_store.py.
#
# Needs a C++20 compiler, mbedTLS 3.6 (headers and libmbedcrypto where the
# compiler finds them), Python 3 with cryptography and requests, and
# ArduinoJson 7.4.3's single header:
#
#   ARDUINOJSON=/path/to/ArduinoJson-v7.4.3.h tests/host/run.sh
#
# The flake runs it as checks.host-tests, with all of these pinned.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
component=$here/../../components/tang_server
out=${OUT_DIR:-$(mktemp -d)}
mkdir -p "$out/include"
cp "${ARDUINOJSON:?set ARDUINOJSON to ArduinoJson 7.4.3\'s single header}" "$out/include/ArduinoJson.h"

flags=(-std=gnu++20 -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=all
       -I"$here/stubs" -I"$out/include" -I"$component")
"${CXX:-c++}" "${flags[@]}" "$component/tang_crypto.cpp" "$here/crypto_main.cpp" \
  -lmbedcrypto -o "$out/crypto_host"
"${CXX:-c++}" "${flags[@]}" "$component/key_store.cpp" "$component/tang_crypto.cpp" "$here/store_main.cpp" \
  -lmbedcrypto -o "$out/store_host"

CRYPTO_HOST=$out/crypto_host python3 "$here/test_crypto.py"
STORE_HOST=$out/store_host python3 "$here/test_store.py"
