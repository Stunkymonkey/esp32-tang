#pragma once
// Host stand-in for ESP-IDF's NVS: one namespace, kept in memory.
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "esp_err.h"

typedef uint32_t nvs_handle_t;
typedef enum { NVS_READONLY, NVS_READWRITE } nvs_open_mode_t;
#define ESP_ERR_NVS_NOT_FOUND 0x1102
#define ESP_ERR_NVS_INVALID_LENGTH 0x110c

inline std::map<std::string, std::vector<uint8_t>> &fake_nvs() {
  static std::map<std::string, std::vector<uint8_t>> blobs;
  return blobs;
}
inline esp_err_t nvs_open(const char *, nvs_open_mode_t, nvs_handle_t *handle) {
  *handle = 1;
  return ESP_OK;
}
inline esp_err_t nvs_get_blob(nvs_handle_t, const char *key, void *out, size_t *len) {
  auto it = fake_nvs().find(key);
  if (it == fake_nvs().end())
    return ESP_ERR_NVS_NOT_FOUND;
  if (out != nullptr) {
    if (*len < it->second.size())
      return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(out, it->second.data(), it->second.size());
  }
  *len = it->second.size();
  return ESP_OK;
}
inline esp_err_t nvs_set_blob(nvs_handle_t, const char *key, const void *data, size_t len) {
  auto *p = static_cast<const uint8_t *>(data);
  fake_nvs()[key] = std::vector<uint8_t>(p, p + len);
  return ESP_OK;
}
inline esp_err_t nvs_erase_key(nvs_handle_t, const char *key) {
  return fake_nvs().erase(key) ? ESP_OK : ESP_ERR_NVS_NOT_FOUND;
}
inline esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }
