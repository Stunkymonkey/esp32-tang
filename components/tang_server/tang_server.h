#pragma once

#include <atomic>
#include <string>
#include <utility>
#include <vector>

#include "esphome/components/web_server_base/web_server_base.h"
#ifdef USE_BINARY_SENSOR
#include "esphome/components/binary_sensor/binary_sensor.h"
#endif
#ifdef USE_SENSOR
#include "esphome/components/sensor/sensor.h"
#endif
#ifdef USE_TEXT_SENSOR
#include "esphome/components/text_sensor/text_sensor.h"
#endif
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
  /// Safe from any task; for conditions.
  State get_state() const { return this->state_; }
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
  Result status(bool detailed);

  // HTTP operations that the actions use too; callable from any task.
  Result deactivate();
  Result wipe();

  /// tang_server.activate: runs the activation in its own task, so PBKDF2
  /// neither blocks the main loop nor needs the small httpd stack. `password`
  /// is copied; nullptr means none was given.
  void activate_in_background(const std::string *password);

  // Events from the HTTP handler, for the triggers.
  void notify_request(const std::string &path, const char *method, int status, const std::string &client_ip);
  void notify_auth_failure(const std::string &path);

  // Entities. They are published on the main loop.
#ifdef USE_BINARY_SENSOR
  void set_active_binary_sensor(binary_sensor::BinarySensor *s) { this->active_binary_sensor_ = s; }
#endif
#ifdef USE_SENSOR
  void set_activation_count_sensor(sensor::Sensor *s) { this->activation_count_sensor_ = s; }
  void set_recovery_count_sensor(sensor::Sensor *s) { this->recovery_count_sensor_ = s; }
  void set_adv_count_sensor(sensor::Sensor *s) { this->adv_count_sensor_ = s; }
  void set_auth_failure_count_sensor(sensor::Sensor *s) { this->auth_failure_count_sensor_ = s; }
#endif
#ifdef USE_TEXT_SENSOR
  void set_state_text_sensor(text_sensor::TextSensor *s) { this->state_text_sensor_ = s; }
  void set_last_path_text_sensor(text_sensor::TextSensor *s) { this->last_path_text_sensor_ = s; }
  void set_last_error_text_sensor(text_sensor::TextSensor *s) { this->last_error_text_sensor_ = s; }
  void set_last_client_ip_text_sensor(text_sensor::TextSensor *s) { this->last_client_ip_text_sensor_ = s; }
#endif

  // Triggers. The callbacks run on the main loop.
  template<typename F> void add_on_activate_callback(F &&f) { this->activate_callback_.add(std::forward<F>(f)); }
  template<typename F> void add_on_deactivate_callback(F &&f) { this->deactivate_callback_.add(std::forward<F>(f)); }
  template<typename F> void add_on_state_change_callback(F &&f) { this->state_callback_.add(std::forward<F>(f)); }
  template<typename F> void add_on_recovery_callback(F &&f) { this->recovery_callback_.add(std::forward<F>(f)); }
  template<typename F> void add_on_adv_callback(F &&f) { this->adv_callback_.add(std::forward<F>(f)); }
  template<typename F> void add_on_request_callback(F &&f) { this->request_callback_.add(std::forward<F>(f)); }
  template<typename F> void add_on_auth_failure_callback(F &&f) {
    this->auth_failure_callback_.add(std::forward<F>(f));
  }
  template<typename F> void add_on_rejected_callback(F &&f) { this->rejected_callback_.add(std::forward<F>(f)); }

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
  /// Publishes the state, counters and last error. Coalesced: several calls
  /// before the next loop iteration publish once.
  void schedule_publish_();
  void publish_();
  void set_state_(State state);
  Result inactive_result_(const std::string &path);
  /// Every activation attempt, from HTTP or the action. Fires on_activate
  /// with the result.
  Result activate_(const std::string &password, bool has_password, const char *source);
  Result activate_locked_(const std::string &password, bool has_password, const char *source);
  struct ActivateJob;
  /// Starts the activation task for `job`, copying `password` into it.
  bool start_activation_(ActivateJob *job, const std::string *password);
  /// Runs one activation in the activation task and waits for its result.
  Result run_activation_(const std::string &password, bool has_password, const char *source);
  static void activate_task_(void *arg);

  /// Runs the callbacks on the main loop, with copies of the arguments.
  template<typename... Ts, typename... As> void fire_(CallbackManager<void(Ts...)> &callbacks, As &&...args) {
    this->defer([&callbacks, args...]() { callbacks.call(args...); });
  }
  /// Drops the keys from RAM and moves to locked or unprovisioned.
  void deactivate_(const char *reason);
  std::vector<KeyInfo> key_info_() const;
  bool stores_plaintext_keys_in_plaintext_nvs_() const;

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
  std::atomic<State> state_{State::UNPROVISIONED};
  std::atomic<bool> activation_running_{false};
  bool setup_done_{false};
  std::vector<TangKey> keys_;
  KeyStore store_;
  // Guarded by info_lock_, not lock_, so the main loop can read it while an
  // activation holds lock_.
  std::string last_error_;
  mutable Mutex info_lock_;
  /// The stored keys while locked without a password, for /status.
  std::vector<KeyInfo> stored_info_;
  uint32_t active_since_ms_{0};
  uint32_t last_recovery_ms_{0};
  // Atomic, so the main loop reads them without the lock.
  std::atomic<uint32_t> activation_count_{0};
  std::atomic<uint32_t> recovery_count_{0};
  std::atomic<uint32_t> adv_count_{0};

  // Separate from lock_, which /activate holds for seconds while PBKDF2 runs.
  mutable Mutex auth_lock_;
  Backoff token_backoff_;
  Backoff password_backoff_;
  std::atomic<uint32_t> auth_failure_count_{0};

#ifdef USE_BINARY_SENSOR
  binary_sensor::BinarySensor *active_binary_sensor_{nullptr};
#endif
#ifdef USE_SENSOR
  sensor::Sensor *activation_count_sensor_{nullptr};
  sensor::Sensor *recovery_count_sensor_{nullptr};
  sensor::Sensor *adv_count_sensor_{nullptr};
  sensor::Sensor *auth_failure_count_sensor_{nullptr};
#endif
#ifdef USE_TEXT_SENSOR
  text_sensor::TextSensor *state_text_sensor_{nullptr};
  text_sensor::TextSensor *last_path_text_sensor_{nullptr};
  text_sensor::TextSensor *last_error_text_sensor_{nullptr};
  text_sensor::TextSensor *last_client_ip_text_sensor_{nullptr};
#endif

  CallbackManager<void(bool)> activate_callback_;
  CallbackManager<void(const std::string &)> deactivate_callback_;
  CallbackManager<void(const std::string &)> state_callback_;
  CallbackManager<void(const std::string &, bool)> recovery_callback_;
  CallbackManager<void(const std::string &)> adv_callback_;
  CallbackManager<void(const std::string &, const std::string &, int)> request_callback_;
  CallbackManager<void(const std::string &)> auth_failure_callback_;
  CallbackManager<void(const std::string &, const std::string &)> rejected_callback_;
};

}  // namespace esphome::tang_server
