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

/// Owns the keys and the state machine. The HTTP handler calls the public
/// methods from the httpd task, so every method that touches keys or state
/// takes the mutex.
class TangServer : public Component {
 public:
  explicit TangServer(web_server_base::WebServerBase *base) : base_(base), handler_(this) {}

  void setup() override;
  void dump_config() override;
  float get_setup_priority() const override;

  void set_key_storage(KeyStorage key_storage) { this->key_storage_ = key_storage; }
  void set_admin_token(const char *admin_token) { this->admin_token_ = admin_token; }

  KeyStorage get_key_storage() const { return this->key_storage_; }
  bool has_admin_token() const { return this->admin_token_ != nullptr; }
  /// Constant-time check of an `Authorization` header against `admin_token`.
  bool check_token(const optional<std::string> &authorization) const;

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
  /// Reads and checks the stored record into keys_.
  bool load_stored_keys_(std::string &error);
  /// Drops the keys from RAM.
  void clear_keys_();
  /// Short, safe message for the log and the last_error sensor; never key
  /// material.
  void set_last_error_(const std::string &error);
  void set_state_(State state);
  Result inactive_result_() const;

  web_server_base::WebServerBase *base_;
  HttpHandler handler_;
  KeyStorage key_storage_{KeyStorage::RAM};
  const char *admin_token_{nullptr};

  Mutex lock_;
  State state_{State::UNPROVISIONED};
  std::vector<TangKey> keys_;
  KeyStore store_;
  std::string last_error_;
};

}  // namespace esphome::tang_server
