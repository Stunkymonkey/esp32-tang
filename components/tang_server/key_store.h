#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nvs.h>

namespace esphome::tang_server {

/// The stored key record in NVS, in its own namespace next to ESPHome's
/// preferences. Knows nothing about HTTP; it turns a payload into a record
/// and back.
///
/// Uses the NVS API directly rather than ESPHome's preferences: they keep a
/// copy of every write in a heap buffer that is freed without wiping, cannot
/// erase a record, and may only be used from the main loop. NVS is
/// thread-safe and reads and writes the caller's buffers directly.
class KeyStore {
 public:
  enum class LoadResult : uint8_t { OK, ABSENT, ERROR };

  /// Opens the namespace. NVS itself is initialized by ESPHome at boot.
  bool open();

  bool exists();

  /// Reads the record and checks its magic number and format version.
  /// `payload` gets the `{"keys": [...]}` JSON; the caller wipes it.
  LoadResult load(std::vector<uint8_t> &payload, std::string &error);

  /// Writes and commits the record with a plaintext payload.
  bool store(const std::string &payload, std::string &error);

  /// Overwrites the record with zeros, then erases it.
  bool erase(std::string &error);

 protected:
  nvs_handle_t handle_{0};
  bool open_{false};
};

}  // namespace esphome::tang_server
