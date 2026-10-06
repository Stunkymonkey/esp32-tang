#include "key_store.h"

#include <cinttypes>
#include <cstring>
#include <memory>

#include <esp_err.h>
#include <esp_log.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

#include "esphome/core/log.h"

#include "tang_crypto.h"

namespace esphome::tang_server {

static const char *const TAG = "tang_server.store";

static const char *const NVS_NAMESPACE = "tang_server";
static const char *const NVS_KEY = "keys";

// Every record: magic (4) | format version (1) | ...
static constexpr uint8_t MAGIC[4] = {'T', 'A', 'N', 'G'};
static constexpr size_t HEADER_SIZE = sizeof(MAGIC) + 1;
// ... | the {"keys": [...]} JSON
static constexpr uint8_t FORMAT_PLAINTEXT = 1;
// ... | PBKDF2 iterations (4, big-endian) | salt (16) | GCM nonce (12) |
//     ciphertext (n) | GCM tag (16). Bytes 0-36 are the additional data.
static constexpr uint8_t FORMAT_PASSWORD = 2;
static constexpr size_t SALT_SIZE = 16;
static constexpr size_t NONCE_SIZE = 12;
static constexpr size_t TAG_SIZE = 16;
static constexpr size_t KEY_SIZE = 32;
static constexpr size_t ENCRYPTED_HEADER_SIZE = HEADER_SIZE + 4 + SALT_SIZE + NONCE_SIZE;
// A record cannot make /activate run for hours.
static constexpr uint32_t MAX_ITERATIONS = 10000000;

int pbkdf2_sha256(const std::string &password, const uint8_t *salt, size_t salt_len, uint32_t iterations,
                  uint8_t out[32]) {
  // One output block: T1 = U1 ^ U2 ^ ... ^ Uc, U1 = HMAC(P, S || INT(1)),
  // Ui = HMAC(P, Ui-1). Same result as mbedtls_pkcs5_pbkdf2_hmac_ext(),
  // which cannot yield in between.
  static constexpr uint8_t BLOCK_INDEX[4] = {0, 0, 0, 1};
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  uint8_t u[32];

  const auto *pw = reinterpret_cast<const unsigned char *>(password.data());
  int ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  if (ret == 0)
    ret = mbedtls_md_hmac_starts(&ctx, pw, password.size());
  if (ret == 0)
    ret = mbedtls_md_hmac_update(&ctx, salt, salt_len);
  if (ret == 0)
    ret = mbedtls_md_hmac_update(&ctx, BLOCK_INDEX, sizeof(BLOCK_INDEX));
  if (ret == 0)
    ret = mbedtls_md_hmac_finish(&ctx, u);
  if (ret == 0)
    memcpy(out, u, sizeof(u));

  for (uint32_t i = 1; ret == 0 && i < iterations; i++) {
    ret = mbedtls_md_hmac_reset(&ctx);
    if (ret == 0)
      ret = mbedtls_md_hmac_update(&ctx, u, sizeof(u));
    if (ret == 0)
      ret = mbedtls_md_hmac_finish(&ctx, u);
    for (size_t j = 0; j < sizeof(u); j++)
      out[j] ^= u[j];
    if (i % 1000 == 0)
      vTaskDelay(1);
  }

  // Frees and wipes the HMAC pads, which are derived from the password.
  mbedtls_md_free(&ctx);
  mbedtls_platform_zeroize(u, sizeof(u));
  if (ret != 0)
    mbedtls_platform_zeroize(out, 32);
  return ret;
}

namespace {

/// The AES key for a record. Logs how long it took, which is the cost of
/// every /activate with a password.
bool derive_key(const std::string &password, const uint8_t *salt, uint32_t iterations, uint8_t key[KEY_SIZE],
                std::string &error) {
  uint32_t start = esp_log_timestamp();
  int ret = pbkdf2_sha256(password, salt, SALT_SIZE, iterations, key);
  if (ret != 0) {
    error = "Key derivation failed";
    ESP_LOGE(TAG, "PBKDF2 failed: -0x%04x", -ret);
    return false;
  }
  ESP_LOGI(TAG, "PBKDF2 with %" PRIu32 " iterations took %" PRIu32 " ms", iterations, esp_log_timestamp() - start);
  return true;
}

/// AES-256-GCM in place of `output`. The context is about 800 bytes, too
/// much for the httpd task's stack.
int gcm(bool encrypt, const uint8_t key[KEY_SIZE], const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
        const uint8_t *input, size_t len, uint8_t *output, uint8_t *tag) {
  auto ctx = std::make_unique<mbedtls_gcm_context>();
  mbedtls_gcm_init(ctx.get());
  int ret = mbedtls_gcm_setkey(ctx.get(), MBEDTLS_CIPHER_ID_AES, key, KEY_SIZE * 8);
  if (ret == 0) {
    if (encrypt) {
      ret = mbedtls_gcm_crypt_and_tag(ctx.get(), MBEDTLS_GCM_ENCRYPT, len, nonce, NONCE_SIZE, aad, aad_len, input,
                                      output, TAG_SIZE, tag);
    } else {
      ret = mbedtls_gcm_auth_decrypt(ctx.get(), len, nonce, NONCE_SIZE, aad, aad_len, tag, TAG_SIZE, input, output);
    }
  }
  // Wipes the expanded key.
  mbedtls_gcm_free(ctx.get());
  return ret;
}

}  // namespace

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

KeyStore::LoadResult KeyStore::load(std::vector<uint8_t> &payload, std::string &error, const std::string *password) {
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

  wipe(payload);
  switch (record[sizeof(MAGIC)]) {
    case FORMAT_PLAINTEXT:
      if (password != nullptr) {
        error = "The stored keys are not encrypted";
        return LoadResult::NOT_ENCRYPTED;
      }
      payload.reserve(len - HEADER_SIZE);
      payload.assign(record.begin() + HEADER_SIZE, record.end());
      return LoadResult::OK;
    case FORMAT_PASSWORD:
      break;
    default:
      error = "The stored keys have an unknown format version";
      return LoadResult::ERROR;
  }

  if (password == nullptr) {
    error = "The stored keys are encrypted";
    return LoadResult::NEEDS_PASSWORD;
  }
  if (len < ENCRYPTED_HEADER_SIZE + TAG_SIZE) {
    error = "The stored keys are truncated";
    return LoadResult::ERROR;
  }

  const uint8_t *p = record.data() + HEADER_SIZE;
  uint32_t iterations = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
  const uint8_t *salt = p + 4;
  const uint8_t *nonce = salt + SALT_SIZE;
  const uint8_t *ciphertext = record.data() + ENCRYPTED_HEADER_SIZE;
  size_t ciphertext_len = len - ENCRYPTED_HEADER_SIZE - TAG_SIZE;
  const uint8_t *tag = ciphertext + ciphertext_len;
  if (iterations == 0 || iterations > MAX_ITERATIONS) {
    error = "The stored keys have an invalid PBKDF2 iteration count";
    return LoadResult::ERROR;
  }

  uint8_t key[KEY_SIZE];
  if (!derive_key(*password, salt, iterations, key, error))
    return LoadResult::ERROR;

  // Sized once, so it never reallocates and leaves an unwiped copy.
  payload.resize(ciphertext_len);
  int ret = gcm(false, key, nonce, record.data(), ENCRYPTED_HEADER_SIZE, ciphertext, ciphertext_len,
                payload.data(), const_cast<uint8_t *>(tag));
  mbedtls_platform_zeroize(key, sizeof(key));
  if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
    wipe(payload);
    error = "Wrong password";
    return LoadResult::WRONG_PASSWORD;
  }
  if (ret != 0) {
    wipe(payload);
    error = "Decryption failed";
    ESP_LOGE(TAG, "AES-GCM decryption failed: -0x%04x", -ret);
    return LoadResult::ERROR;
  }
  return LoadResult::OK;
}

bool KeyStore::store(const std::string &payload, std::string &error, const std::string *password,
                     uint32_t iterations) {
  if (!this->open_) {
    error = "NVS is not available";
    return false;
  }

  std::vector<uint8_t> record;
  ScopedWipe<std::vector<uint8_t>> wipe_record{record};
  if (password == nullptr) {
    record.reserve(HEADER_SIZE + payload.size());
    record.insert(record.end(), MAGIC, MAGIC + sizeof(MAGIC));
    record.push_back(FORMAT_PLAINTEXT);
    record.insert(record.end(), payload.begin(), payload.end());
    return this->write_(record, error);
  }

  // Header, then room for the ciphertext and the tag.
  record.resize(ENCRYPTED_HEADER_SIZE + payload.size() + TAG_SIZE);
  uint8_t *p = record.data();
  memcpy(p, MAGIC, sizeof(MAGIC));
  p[sizeof(MAGIC)] = FORMAT_PASSWORD;
  p += HEADER_SIZE;
  p[0] = iterations >> 24;
  p[1] = iterations >> 16;
  p[2] = iterations >> 8;
  p[3] = iterations;
  uint8_t *salt = p + 4;
  uint8_t *nonce = salt + SALT_SIZE;
  // The hardware RNG; with Wi-Fi running, it is a true random source.
  esp_fill_random(salt, SALT_SIZE);
  esp_fill_random(nonce, NONCE_SIZE);
  uint8_t *ciphertext = record.data() + ENCRYPTED_HEADER_SIZE;
  uint8_t *tag = ciphertext + payload.size();

  uint8_t key[KEY_SIZE];
  if (!derive_key(*password, salt, iterations, key, error))
    return false;
  int ret = gcm(true, key, nonce, record.data(), ENCRYPTED_HEADER_SIZE,
                reinterpret_cast<const uint8_t *>(payload.data()), payload.size(), ciphertext, tag);
  mbedtls_platform_zeroize(key, sizeof(key));
  if (ret != 0) {
    error = "Encryption failed";
    ESP_LOGE(TAG, "AES-GCM encryption failed: -0x%04x", -ret);
    return false;
  }
  return this->write_(record, error);
}

bool KeyStore::write_(const std::vector<uint8_t> &record, std::string &error) {
  esp_err_t err = nvs_set_blob(this->handle_, NVS_KEY, record.data(), record.size());
  if (err == ESP_OK)
    err = nvs_commit(this->handle_);
  if (err != ESP_OK) {
    error = std::string("Cannot store the keys: ") + esp_err_to_name(err);
    return false;
  }
  ESP_LOGI(TAG, "Keys stored (%zu bytes, %s)", record.size(),
           record[sizeof(MAGIC)] == FORMAT_PASSWORD ? "encrypted" : "plaintext");
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
