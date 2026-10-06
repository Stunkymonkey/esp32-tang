#pragma once
// Host stand-in for the hardware RNG, which key_store uses for salt and nonce.
#include <cstdio>
#include <cstdlib>
inline void esp_fill_random(void *buf, size_t len) {
  FILE *f = fopen("/dev/urandom", "rb");
  if (f == nullptr || fread(buf, 1, len, f) != len)
    abort();
  fclose(f);
}
