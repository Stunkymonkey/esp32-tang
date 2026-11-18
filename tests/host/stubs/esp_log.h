#pragma once
// Host stand-in: key_store times PBKDF2 with esp_log_timestamp().
#include <chrono>
#include <cstdint>
inline uint32_t esp_log_timestamp() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
