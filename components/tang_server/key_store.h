#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nvs.h>

namespace esphome::tang_server {

/// The stored key record in NVS, in its own namespace next to ESPHome's
/// preferences. Knows nothing about HTTP; it turns a payload into a record
/// and back, with or without a password.
///
/// Uses the NVS API directly rather than ESPHome's preferences: they keep a
/// copy of every write in a heap buffer that is freed without wiping, cannot
/// erase a record, and may only be used from the main loop. NVS is
/// thread-safe and reads and writes the caller's buffers directly.
class KeyStore {
 public:
  enum class LoadResult : uint8_t {
    OK,
    ABSENT,
    ERROR,
    /// The record is encrypted and no password was given.
    NEEDS_PASSWORD,
    /// A password was given, but the record is plaintext.
    NOT_ENCRYPTED,
    /// The GCM tag check failed: a wrong password or a corrupt record.
    WRONG_PASSWORD,
  };

  /// Opens the namespace. NVS itself is initialized by ESPHome at boot.
  bool open();

  bool exists();

  /// Reads the record, checks it and decrypts it if `password` is given.
  /// `payload` gets the `{"keys": [...]}` JSON; the caller wipes it.
  LoadResult load(std::vector<uint8_t> &payload, std::string &error, const std::string *password = nullptr);

  /// Writes and commits the record: plaintext without a password, else
  /// encrypted with a key derived from it with `iterations` PBKDF2 rounds.
  bool store(const std::string &payload, std::string &error, const std::string *password = nullptr,
             uint32_t iterations = 0);

  /// Overwrites the record with zeros, then erases it.
  bool erase(std::string &error);

 protected:
  bool write_(const std::vector<uint8_t> &record, std::string &error);

  nvs_handle_t handle_{0};
  bool open_{false};
};

/// PBKDF2-HMAC-SHA256 with a 32-byte output. Yields every 1000 iterations,
/// so a high count does not starve the idle task and trip the watchdog.
/// @return 0 on success, or an mbedTLS error.
int pbkdf2_sha256(const std::string &password, const uint8_t *salt, size_t salt_len, uint32_t iterations,
                  uint8_t out[32]);

}  // namespace esphome::tang_server
