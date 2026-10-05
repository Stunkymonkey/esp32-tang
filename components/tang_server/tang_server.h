#pragma once

#include <string>
#include <vector>

#include "esphome/components/web_server_base/web_server_base.h"
#include "esphome/core/component.h"
#include "esphome/core/helpers.h"
#include "esphome/core/optional.h"

#include "http_handler.h"
#include "key_store.h"
#include "tang_crypto.h"

namespace esphome::tang_server {

enum class KeyStorage : uint8_t { RAM, NVS };

enum class State : uint8_t { UNPROVISIONED, PENDING, LOCKED, ACTIVE };

const char *state_to_string(State state);

/// Which secret a request checks, for the auth backoff.
enum class Secret : uint8_t { TOKEN, PASSWORD };

/// Public facts about a key, for /status: never the private part.
struct KeyInfo {
  std::string thp_s1;
  std::string thp_s256;
  KeyUsage usage;
  const char *crv;
};

/// Owns the keys and the state machine. The HTTP handler calls the public
/// methods from the httpd task, so every method that touches keys or state
/// takes the mutex.
class TangServer : public Component {
 public:
  explicit TangServer(web_server_base::WebServerBase *base) : base_(base), handler_(this) {}

  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override;

  void set_key_storage(KeyStorage key_storage) { this->key_storage_ = key_storage; }
  void set_require_password(bool require_password) { this->require_password_ = require_password; }
  void set_pbkdf2_iterations(uint32_t iterations) { this->pbkdf2_iterations_ = iterations; }
  void set_admin_token(const char *admin_token) { this->admin_token_ = admin_token; }
  void set_max_active_time(uint32_t ms) { this->max_active_ms_ = ms; }
  void set_idle_timeout(uint32_t ms) { this->idle_timeout_ms_ = ms; }
  void set_auth_backoff(uint8_t max_failures, uint32_t lockout_ms) {
    this->max_failures_ = max_failures;
    this->lockout_ms_ = lockout_ms;
  }

  KeyStorage get_key_storage() const { return this->key_storage_; }
  bool get_require_password() const { return this->require_password_; }
  bool has_admin_token() const { return this->admin_token_ != nullptr; }
  /// Constant-time check of an `Authorization` header against `admin_token`.
  bool check_token(const optional<std::string> &authorization) const;

  /// Auth backoff. Failures of each secret are counted on their own, so a
  /// success with one cannot reset the failures of the other.
  /// @return milliseconds until a request that checks these secrets may try
  /// again, 0 if it may now. Counts the refusal.
  uint32_t auth_blocked_ms(bool token, bool password);
  void auth_result(Secret secret, bool ok);

  // HTTP operations, called from the httpd task.
  Result adv(const std::string &thp);
  Result rec(const std::string &thp, const std::vector<uint8_t> &body);
  Result provision(const std::vector<uint8_t> &body);
  Result activate(const std::vector<uint8_t> &body);
  Result deactivate();
  Result wipe();
  Result status(bool detailed);

 protected:
  /// Loads stored keys at boot and, without require_password, activates them.
  void load_at_boot_();

  // Callers hold the mutex.
  /// Reads, decrypts if `password` is given, and checks the stored record
  /// into keys_.
  KeyStore::LoadResult load_stored_keys_(std::string &error, const std::string *password);
  /// Drops the keys from RAM.
  void clear_keys_();
  /// Short, safe message for the log and the last_error sensor; never key
  /// material.
  void set_last_error_(const std::string &error);
  void set_state_(State state);
  Result inactive_result_() const;
  /// Drops the keys from RAM and moves to locked or unprovisioned.
  void deactivate_(const char *reason);
  std::vector<KeyInfo> key_info_() const;
  bool stores_plaintext_without_flash_encryption_() const;

  struct Backoff {
    uint8_t failures{0};
    uint32_t last_failure_ms{0};
  };
  /// Callers hold auth_lock_.
  uint32_t blocked_ms_(const Backoff &backoff, uint32_t now) const;

  web_server_base::WebServerBase *base_;
  HttpHandler handler_;
  KeyStorage key_storage_{KeyStorage::RAM};
  bool require_password_{false};
  uint32_t pbkdf2_iterations_{20000};
  const char *admin_token_{nullptr};
  uint32_t max_active_ms_{0};
  uint32_t idle_timeout_ms_{0};
  uint8_t max_failures_{5};
  uint32_t lockout_ms_{5 * 60 * 1000};

  Mutex lock_;
  State state_{State::UNPROVISIONED};
  std::vector<TangKey> keys_;
  KeyStore store_;
  std::string last_error_;
  /// The stored keys while locked without a password, for /status.
  std::vector<KeyInfo> stored_info_;
  uint32_t active_since_ms_{0};
  uint32_t last_recovery_ms_{0};
  uint32_t activation_count_{0};
  uint32_t recovery_count_{0};
  uint32_t adv_count_{0};

  // Separate from lock_, which /activate holds for seconds while PBKDF2 runs.
  mutable Mutex auth_lock_;
  Backoff token_backoff_;
  Backoff password_backoff_;
  uint32_t auth_failure_count_{0};
};

}  // namespace esphome::tang_server
