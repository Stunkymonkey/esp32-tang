#include "key_store.h"

#include <cstring>

#include <esp_err.h>

#include "esphome/core/log.h"

#include "tang_crypto.h"

namespace esphome::tang_server {

static const char *const TAG = "tang_server.store";

static const char *const NVS_NAMESPACE = "tang_server";
static const char *const NVS_KEY = "keys";

// Record: magic (4) | format version (1) | payload
static constexpr uint8_t MAGIC[4] = {'T', 'A', 'N', 'G'};
static constexpr uint8_t FORMAT_PLAINTEXT = 1;
static constexpr size_t HEADER_SIZE = sizeof(MAGIC) + 1;

bool KeyStore::open() {
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &this->handle_);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
    return false;
  }
  this->open_ = true;
  return true;
}

bool KeyStore::exists() {
  size_t len = 0;
  return this->open_ && nvs_get_blob(this->handle_, NVS_KEY, nullptr, &len) == ESP_OK;
}

KeyStore::LoadResult KeyStore::load(std::vector<uint8_t> &payload, std::string &error) {
  if (!this->open_) {
    error = "NVS is not available";
    return LoadResult::ERROR;
  }

  size_t len = 0;
  esp_err_t err = nvs_get_blob(this->handle_, NVS_KEY, nullptr, &len);
  if (err == ESP_ERR_NVS_NOT_FOUND)
    return LoadResult::ABSENT;
  if (err != ESP_OK) {
    error = std::string("Cannot read the stored keys: ") + esp_err_to_name(err);
    return LoadResult::ERROR;
  }

  std::vector<uint8_t> record(len);
  ScopedWipe<std::vector<uint8_t>> wipe_record{record};
  err = nvs_get_blob(this->handle_, NVS_KEY, record.data(), &len);
  if (err != ESP_OK) {
    error = std::string("Cannot read the stored keys: ") + esp_err_to_name(err);
    return LoadResult::ERROR;
  }
  if (len < HEADER_SIZE || memcmp(record.data(), MAGIC, sizeof(MAGIC)) != 0) {
    error = "The stored keys are not a tang_server record";
    return LoadResult::ERROR;
  }
  if (record[sizeof(MAGIC)] != FORMAT_PLAINTEXT) {
    error = "The stored keys have an unknown format version";
    return LoadResult::ERROR;
  }

  wipe(payload);
  payload.reserve(len - HEADER_SIZE);
  payload.assign(record.begin() + HEADER_SIZE, record.end());
  return LoadResult::OK;
}

bool KeyStore::store(const std::string &payload, std::string &error) {
  if (!this->open_) {
    error = "NVS is not available";
    return false;
  }

  std::vector<uint8_t> record;
  record.reserve(HEADER_SIZE + payload.size());
  ScopedWipe<std::vector<uint8_t>> wipe_record{record};
  record.insert(record.end(), MAGIC, MAGIC + sizeof(MAGIC));
  record.push_back(FORMAT_PLAINTEXT);
  record.insert(record.end(), payload.begin(), payload.end());

  esp_err_t err = nvs_set_blob(this->handle_, NVS_KEY, record.data(), record.size());
  if (err == ESP_OK)
    err = nvs_commit(this->handle_);
  if (err != ESP_OK) {
    error = std::string("Cannot store the keys: ") + esp_err_to_name(err);
    return false;
  }
  ESP_LOGI(TAG, "Keys stored (%zu bytes)", record.size());
  return true;
}

bool KeyStore::erase(std::string &error) {
  if (!this->open_) {
    error = "NVS is not available";
    return false;
  }

  size_t len = 0;
  esp_err_t err = nvs_get_blob(this->handle_, NVS_KEY, nullptr, &len);
  if (err == ESP_ERR_NVS_NOT_FOUND)
    return true;

  // NVS only marks old entries as erased, so this does not guarantee the
  // old copy is gone from flash, but it makes it more likely.
  if (err == ESP_OK && len > 0) {
    std::vector<uint8_t> zeros(len, 0);
    nvs_set_blob(this->handle_, NVS_KEY, zeros.data(), zeros.size());
  }
  err = nvs_erase_key(this->handle_, NVS_KEY);
  if (err == ESP_OK)
    err = nvs_commit(this->handle_);
  if (err != ESP_OK) {
    error = std::string("Cannot erase the stored keys: ") + esp_err_to_name(err);
    return false;
  }
  ESP_LOGI(TAG, "Stored keys erased");
  return true;
}

}  // namespace esphome::tang_server
