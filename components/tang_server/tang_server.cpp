#include "tang_server.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <strings.h>

#include <esp_flash_encrypt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include "esphome/core/hal.h"
#include "esphome/core/log.h"

namespace esphome::tang_server {

static const char *const TAG = "tang_server";

const char *state_to_string(State state) {
  switch (state) {
    case State::UNPROVISIONED:
      return "unprovisioned";
    case State::PENDING:
      return "pending";
    case State::LOCKED:
      return "locked";
    case State::ACTIVE:
      return "active";
  }
  return "unknown";
}

void TangServer::setup() {
  {
    // Seeding gathers entropy, the deepest call in the crypto code. Done
    // here on the main loop's stack rather than on the first request in the
    // httpd task, whose stack is small.
    LockGuard guard(this->lock_);
    if (init_rng() != 0)
      this->set_last_error_("Cannot seed the random number generator");
  }
  if (this->key_storage_ == KeyStorage::NVS)
    this->load_at_boot_();

  // web_server_base only listens once a consumer calls init(), and this
  // component may be the only one. init() is reference-counted.
  this->base_->init();
  // Not add_handler(): web_server's auth would lock out Clevis, which cannot
  // log in. admin_token is the component's own protection.
  this->base_->add_handler_without_auth(&this->handler_);

  // loop() only runs the auto-deactivation timers.
  if (this->max_active_ms_ == 0 && this->idle_timeout_ms_ == 0)
    this->disable_loop();

  // on_state_change fires once at boot with the initial state; the changes
  // while loading the stored keys are not reported on their own.
  this->setup_done_ = true;
  this->fire_(this->state_callback_, std::string(state_to_string(this->state_)));
}

void TangServer::loop() {
  // /activate holds the lock for seconds while PBKDF2 runs. Skip a round
  // rather than stall the main loop; the timers are checked again soon.
  if (!this->lock_.try_lock())
    return;
  if (this->state_ == State::ACTIVE) {
    // Unsigned subtraction keeps working when millis() wraps after 49 days.
    uint32_t now = millis();
    if (this->max_active_ms_ != 0 && now - this->active_since_ms_ >= this->max_active_ms_) {
      this->deactivate_("max_active_time");
    } else if (this->idle_timeout_ms_ != 0 && now - this->last_recovery_ms_ >= this->idle_timeout_ms_) {
      this->deactivate_("idle_timeout");
    }
  }
  this->lock_.unlock();
}

void TangServer::dump_config() {
  ESP_LOGCONFIG(TAG,
                "Tang server:\n"
                "  Key storage: %s\n"
                "  Require password: %s\n"
                "  Admin token: %s\n"
                "  State: %s",
                this->key_storage_ == KeyStorage::RAM ? "ram" : "nvs", YESNO(this->require_password_),
                YESNO(this->has_admin_token()), state_to_string(this->state_));
  if (this->require_password_)
    ESP_LOGCONFIG(TAG, "  PBKDF2 iterations: %" PRIu32, this->pbkdf2_iterations_);
  if (this->max_active_ms_ != 0)
    ESP_LOGCONFIG(TAG, "  Max active time: %" PRIu32 " s", this->max_active_ms_ / 1000);
  if (this->idle_timeout_ms_ != 0)
    ESP_LOGCONFIG(TAG, "  Idle timeout: %" PRIu32 " s", this->idle_timeout_ms_ / 1000);
  ESP_LOGCONFIG(TAG,
                "  Auth backoff: %u failures, then %" PRIu32 " s lockout\n"
                "  Flash encryption: %s",
                this->max_failures_, this->lockout_ms_ / 1000, YESNO(esp_flash_encryption_enabled()));
  if (!this->last_error_.empty())
    ESP_LOGCONFIG(TAG, "  Last error: %s", this->last_error_.c_str());

  if (!this->has_admin_token())
    ESP_LOGW(TAG, "No admin_token: anyone on the network can provision, deactivate and wipe");
  if (this->stores_plaintext_without_flash_encryption_())
    ESP_LOGW(TAG, "Keys are stored in plaintext and flash encryption is off: anyone holding the device can read "
                  "them. See the flash encryption guide in the README.");
}

bool TangServer::stores_plaintext_without_flash_encryption_() const {
  return this->key_storage_ == KeyStorage::NVS && !this->require_password_ && !esp_flash_encryption_enabled();
}

void TangServer::load_at_boot_() {
  // No other task touches the state yet, but the helpers expect the lock.
  LockGuard guard(this->lock_);
  if (!this->store_.open()) {
    this->set_last_error_("NVS is not available");
    return;
  }
  if (!this->store_.exists()) {
    ESP_LOGI(TAG, "No stored keys");
    return;
  }

  // A record that fails the checks is left in NVS, so a firmware downgrade
  // or a config change does not destroy it; /wipe or the next store
  // replaces it.
  std::string error;
  KeyStore::LoadResult result = this->load_stored_keys_(error, nullptr);
  if (this->require_password_) {
    // An encrypted record can only be checked with the password, on
    // /activate.
    if (result == KeyStore::LoadResult::NEEDS_PASSWORD) {
      ESP_LOGI(TAG, "Stored keys are encrypted; waiting for /activate");
      this->set_state_(State::LOCKED);
      return;
    }
    this->clear_keys_();
    if (result == KeyStore::LoadResult::OK)
      error = "they are not encrypted, but require_password is set. Wipe and provision again";
    this->set_last_error_("Stored keys ignored: " + error);
    return;
  }

  // Without require_password, stored keys activate themselves, like tangd
  // after a reboot.
  if (result == KeyStore::LoadResult::NEEDS_PASSWORD)
    error = "they are encrypted, but require_password is not set";
  if (result != KeyStore::LoadResult::OK) {
    this->set_last_error_("Stored keys ignored: " + error);
    this->fire_(this->activate_callback_, false);
    return;
  }
  ESP_LOGI(TAG, "Activated %zu stored keys", this->keys_.size());
  this->set_state_(State::ACTIVE);
  this->fire_(this->activate_callback_, true);
}

KeyStore::LoadResult TangServer::load_stored_keys_(std::string &error, const std::string *password) {
  std::vector<uint8_t> payload;
  ScopedWipe<std::vector<uint8_t>> wipe_payload{payload};
  KeyStore::LoadResult result = this->store_.load(payload, error, password);
  if (result == KeyStore::LoadResult::ABSENT)
    error = "No stored keys";
  if (result != KeyStore::LoadResult::OK)
    return result;
  if (!parse_keys(reinterpret_cast<const char *>(payload.data()), payload.size(), this->keys_, error))
    return KeyStore::LoadResult::ERROR;
  return KeyStore::LoadResult::OK;
}

// After Wi-Fi, like web_server: httpd needs the network stack.
float TangServer::get_setup_priority() const { return setup_priority::WIFI - 1.0f; }

bool TangServer::check_token(const optional<std::string> &authorization) const {
  if (this->admin_token_ == nullptr)
    return true;
  if (!authorization.has_value())
    return false;

  static constexpr const char *PREFIX = "Bearer ";
  static constexpr size_t PREFIX_LEN = 7;
  const std::string &header = authorization.value();
  if (header.size() < PREFIX_LEN || strncasecmp(header.c_str(), PREFIX, PREFIX_LEN) != 0)
    return false;

  // Runs over the whole expected token whatever the given one is, so the
  // time taken does not depend on where they first differ.
  const char *given = header.c_str() + PREFIX_LEN;
  size_t given_len = header.size() - PREFIX_LEN;
  size_t expected_len = strlen(this->admin_token_);
  uint8_t diff = given_len != expected_len;
  for (size_t i = 0; i < expected_len; i++) {
    char c = i < given_len ? given[i] : 0;
    diff |= static_cast<uint8_t>(c ^ this->admin_token_[i]);
  }
  return diff == 0;
}

Result TangServer::inactive_result_(const std::string &path) {
  // Clevis treats this as a failure and falls back to the passphrase. In
  // practice, a client is waiting to be unlocked: on_rejected says so.
  std::string state = state_to_string(this->state_);
  this->fire_(this->rejected_callback_, path, state);
  return {503, "text/plain", "Server not active (" + state + ")"};
}

Result TangServer::adv(const std::string &thp) {
  LockGuard guard(this->lock_);
  if (this->state_ != State::ACTIVE)
    return this->inactive_result_(thp.empty() ? std::string("/adv") : "/adv/" + thp);
  Result result = build_adv(this->keys_, thp);
  if (result.status == 200) {
    this->adv_count_++;
    this->fire_(this->adv_callback_, thp);
  }
  return result;
}

Result TangServer::rec(const std::string &thp, const std::vector<uint8_t> &body) {
  LockGuard guard(this->lock_);
  if (this->state_ != State::ACTIVE)
    return this->inactive_result_("/rec/" + thp);
  Result result = exchange(this->keys_, thp, reinterpret_cast<const char *>(body.data()), body.size());
  if (result.status == 200) {
    this->recovery_count_++;
    // Only a successful recovery restarts the idle timer.
    this->last_recovery_ms_ = millis();
  }
  this->fire_(this->recovery_callback_, thp, result.status == 200);
  return result;
}

Result TangServer::provision(const std::vector<uint8_t> &body) {
  LockGuard guard(this->lock_);
  // With ram, provisioning is how the server becomes active, so every
  // attempt counts as an activation attempt.
  const bool ram = this->key_storage_ == KeyStorage::RAM;
  // Replacing keys always takes an explicit /wipe first, so a stray
  // provision cannot overwrite the keys existing bindings depend on.
  if (this->state_ != State::UNPROVISIONED) {
    if (ram)
      this->fire_(this->activate_callback_, false);
    return Result::text(409, "Already provisioned. Wipe first.");
  }

  std::string error;
  if (!parse_keys(reinterpret_cast<const char *>(body.data()), body.size(), this->keys_, error)) {
    ESP_LOGW(TAG, "Provision rejected: %s", error.c_str());
    if (ram)
      this->fire_(this->activate_callback_, false);
    return {400, "text/plain", error};
  }

  ESP_LOGI(TAG, "Provisioned %zu keys", this->keys_.size());
  if (ram) {
    // Nothing to store, so provisioning activates directly.
    this->set_state_(State::ACTIVE);
    this->fire_(this->activate_callback_, true);
    return Result::text(200, "Provisioned and active.");
  }
  // Provisioning never writes to flash; the first /activate stores the keys.
  this->set_state_(State::PENDING);
  return Result::text(200, "Provisioned. POST /activate to store the keys and serve them.");
}

Result TangServer::activate(const std::vector<uint8_t> &body) {
  // {"password": "..."} with require_password, else no body.
  std::string password;
  ScopedWipe<std::string> wipe_password{password};
  bool has_password = false;
  if (!body.empty()) {
    JsonDocument doc(WipingAllocator::instance());
    bool valid = !deserializeJson(doc, reinterpret_cast<const char *>(body.data()), body.size()) &&
                 doc.is<JsonObject>();
    JsonVariantConst value = doc["password"];
    has_password = valid && !value.isNull();
    if (!valid || (has_password && !value.is<const char *>())) {
      this->fire_(this->activate_callback_, false);
      return Result::text(400, valid ? "The password must be a string" : "Invalid JSON");
    }
    if (has_password) {
      const char *p = value.as<const char *>();
      password.reserve(strlen(p));
      password = p;
    }
  }
  // The activation runs in its own task with a bigger stack; the httpd task
  // waits for it.
  return this->run_activation_(password, has_password, "/activate");
}

Result TangServer::activate_(const std::string &password, bool has_password, const char *source) {
  LockGuard guard(this->lock_);
  Result result = this->activate_locked_(password, has_password, source);
  this->fire_(this->activate_callback_, result.status == 200);
  return result;
}

Result TangServer::activate_locked_(const std::string &password, bool has_password, const char *source) {
  // A password mismatch is refused, so a wrong setup shows up instead of
  // storing keys in a way the user did not expect.
  // Nothing to activate comes first, so the password is not sent for nothing.
  if (this->state_ == State::ACTIVE)
    return Result::text(409, "Already active.");
  if (this->state_ == State::UNPROVISIONED)
    return Result::text(409, "No keys to activate. Provision first.");
  if (has_password && !this->require_password_)
    return Result::text(400, "This device has no require_password; send no password");
  if (this->require_password_ && password.empty())
    return Result::text(400, "This device has require_password; send {\"password\": \"...\"}");
  const std::string *key_password = this->require_password_ ? &password : nullptr;

  std::string error;
  switch (this->state_) {
    case State::ACTIVE:
    case State::UNPROVISIONED:
      break;  // answered above
    case State::PENDING: {
      std::string payload = serialize_keys(this->keys_);
      ScopedWipe<std::string> wipe_payload{payload};
      // The first activation decides the password. There is no confirmation:
      // a mistyped one locks the stored keys away until /wipe.
      if (!this->store_.store(payload, error, key_password, this->pbkdf2_iterations_)) {
        this->set_last_error_(error);
        return {500, "text/plain", error};
      }
      if (this->stores_plaintext_without_flash_encryption_())
        ESP_LOGW(TAG, "Keys stored in plaintext while flash encryption is off");
      ESP_LOGI(TAG, "Activated: keys stored");
      this->set_state_(State::ACTIVE);
      return Result::text(200, "Keys stored and active.");
    }
    case State::LOCKED:
      switch (this->load_stored_keys_(error, key_password)) {
        case KeyStore::LoadResult::OK:
          this->auth_result(Secret::PASSWORD, true);
          break;
        case KeyStore::LoadResult::WRONG_PASSWORD:
          // A corrupt record looks the same; the tag check cannot tell.
          ESP_LOGW(TAG, "%s: wrong password", source);
          this->auth_result(Secret::PASSWORD, false);
          this->fire_(this->auth_failure_callback_, std::string(source));
          return Result::text(401, "Wrong password");
        default:
          this->set_last_error_("Cannot activate: " + error);
          return {500, "text/plain", error};
      }
      ESP_LOGI(TAG, "Activated: %zu stored keys loaded", this->keys_.size());
      this->set_state_(State::ACTIVE);
      return Result::text(200, "Activated.");
  }
  return Result::text(500, "Unknown state");
}

Result TangServer::deactivate() {
  LockGuard guard(this->lock_);
  this->deactivate_("manual");
  return Result::text(200, "Deactivated.");
}

void TangServer::deactivate_(const char *reason) {
  if (this->state_ != State::ACTIVE && this->state_ != State::PENDING)
    return;  // no keys in RAM, nothing to report
  ESP_LOGI(TAG, "Deactivating (%s)", reason);
  this->fire_(this->deactivate_callback_, std::string(reason));
  // Stored keys stay and can be activated again. Keys that were never
  // stored (ram, or pending) are gone.
  bool stored = this->state_ == State::ACTIVE && this->key_storage_ == KeyStorage::NVS;
  if (stored && !this->require_password_)
    this->stored_info_ = this->key_info_();
  this->clear_keys_();
  this->set_state_(stored ? State::LOCKED : State::UNPROVISIONED);
}

Result TangServer::wipe() {
  LockGuard guard(this->lock_);
  // Reported whenever there are keys anywhere: in RAM, in NVS, or both.
  bool had_keys = this->state_ == State::ACTIVE || this->state_ == State::PENDING ||
                  (this->key_storage_ == KeyStorage::NVS && this->store_.exists());
  if (had_keys) {
    ESP_LOGI(TAG, "Wiping");
    this->fire_(this->deactivate_callback_, std::string("wipe"));
  }
  this->clear_keys_();
  this->stored_info_.clear();
  if (this->key_storage_ == KeyStorage::NVS) {
    std::string error;
    if (!this->store_.erase(error)) {
      this->set_last_error_(error);
      this->set_state_(this->store_.exists() ? State::LOCKED : State::UNPROVISIONED);
      return {500, "text/plain", error};
    }
  }
  this->set_state_(State::UNPROVISIONED);
  return Result::text(200, "Wiped.");
}

Result TangServer::status(bool detailed) {
  LockGuard guard(this->lock_);
  JsonDocument doc;
  doc["state"] = state_to_string(this->state_);
  if (detailed) {
    // Public facts only: no private key material, whatever the state.
    doc["key_storage"] = this->key_storage_ == KeyStorage::RAM ? "ram" : "nvs";
    doc["require_password"] = this->require_password_;
    doc["flash_encryption"] = esp_flash_encryption_enabled();
    doc["admin_token"] = this->has_admin_token();

    // Keys in RAM while active or pending, the stored ones while locked
    // without a password. With a password, the thumbprints are only known
    // after decryption.
    const bool in_ram = this->state_ == State::ACTIVE || this->state_ == State::PENDING;
    JsonArray keys = doc["keys"].to<JsonArray>();
    for (const auto &info : in_ram ? this->key_info_() : this->stored_info_) {
      JsonObject k = keys.add<JsonObject>();
      k["thp"]["S1"] = info.thp_s1;
      k["thp"]["S256"] = info.thp_s256;
      k["use"] = info.usage == KeyUsage::SIGN ? "sign" : "exchange";
      k["crv"] = info.crv;
    }

    uint32_t now = millis();
    if (this->state_ == State::ACTIVE) {
      uint32_t active = now - this->active_since_ms_;
      uint32_t idle = now - this->last_recovery_ms_;
      doc["active_since_s"] = active / 1000;
      if (this->max_active_ms_ != 0) {
        doc["deactivates_in_s"] = (this->max_active_ms_ - std::min(active, this->max_active_ms_)) / 1000;
      } else {
        doc["deactivates_in_s"] = nullptr;
      }
      if (this->idle_timeout_ms_ != 0) {
        doc["idle_deactivates_in_s"] = (this->idle_timeout_ms_ - std::min(idle, this->idle_timeout_ms_)) / 1000;
      } else {
        doc["idle_deactivates_in_s"] = nullptr;
      }
    } else {
      doc["active_since_s"] = nullptr;
      doc["deactivates_in_s"] = nullptr;
      doc["idle_deactivates_in_s"] = nullptr;
    }

    uint32_t auth_failure_count;
    {
      LockGuard auth_guard(this->auth_lock_);
      doc["auth_failures"] = this->token_backoff_.failures + this->password_backoff_.failures;
      uint32_t blocked =
          std::max(this->blocked_ms_(this->token_backoff_, now), this->blocked_ms_(this->password_backoff_, now));
      doc["lockout_remaining_s"] = (blocked + 999) / 1000;
      auth_failure_count = this->auth_failure_count_;
    }

    JsonObject counters = doc["counters"].to<JsonObject>();
    counters["activation"] = this->activation_count_;
    counters["recovery"] = this->recovery_count_;
    counters["adv"] = this->adv_count_;
    counters["auth_failure"] = auth_failure_count;
  }

  Result result{200, "application/json", {}};
  serializeJson(doc, result.body);
  return result;
}

std::vector<KeyInfo> TangServer::key_info_() const {
  std::vector<KeyInfo> info;
  info.reserve(this->keys_.size());
  for (const auto &key : this->keys_)
    info.push_back({key.thp_by_alg("S1"), key.thp_by_alg("S256"), key.usage, key.crv()});
  return info;
}

uint32_t TangServer::blocked_ms_(const Backoff &backoff, uint32_t now) const {
  if (backoff.failures == 0)
    return 0;
  // 1 s, 2 s, 4 s, ... after each failure, then the lockout once
  // max_failures failures in a row are reached.
  uint32_t wait = this->lockout_ms_;
  if (backoff.failures < this->max_failures_)
    wait = std::min<uint32_t>(this->lockout_ms_, uint32_t{1000} << std::min(backoff.failures - 1, 20));
  uint32_t elapsed = now - backoff.last_failure_ms;
  return elapsed >= wait ? 0 : wait - elapsed;
}

uint32_t TangServer::auth_blocked_ms(bool token, bool password) {
  LockGuard guard(this->auth_lock_);
  uint32_t now = millis();
  uint32_t blocked = 0;
  if (token)
    blocked = std::max(blocked, this->blocked_ms_(this->token_backoff_, now));
  if (password)
    blocked = std::max(blocked, this->blocked_ms_(this->password_backoff_, now));
  if (blocked != 0)
    this->auth_failure_count_++;
  return blocked;
}

void TangServer::auth_result(Secret secret, bool ok) {
  LockGuard guard(this->auth_lock_);
  Backoff &backoff = secret == Secret::TOKEN ? this->token_backoff_ : this->password_backoff_;
  if (ok) {
    backoff.failures = 0;
    return;
  }
  if (backoff.failures < UINT8_MAX)
    backoff.failures++;
  backoff.last_failure_ms = millis();
  this->auth_failure_count_++;
  uint32_t wait = this->blocked_ms_(backoff, backoff.last_failure_ms);
  ESP_LOGW(TAG, "Wrong %s (%u in a row): next attempt in %" PRIu32 " s",
           secret == Secret::TOKEN ? "token" : "password", backoff.failures, (wait + 999) / 1000);
}

void TangServer::clear_keys_() {
  if (this->keys_.empty())
    return;
  // ~TangKey() wipes each private key as the vector releases it.
  std::vector<TangKey>().swap(this->keys_);
  ESP_LOGI(TAG, "Keys cleared from RAM");
}

void TangServer::set_last_error_(const std::string &error) {
  ESP_LOGW(TAG, "%s", error.c_str());
  this->last_error_ = error;
}

void TangServer::set_state_(State state) {
  if (state == this->state_)
    return;
  ESP_LOGI(TAG, "State: %s -> %s", state_to_string(this->state_), state_to_string(state));
  this->state_ = state;
  if (this->setup_done_)
    this->fire_(this->state_callback_, std::string(state_to_string(state)));
  if (state == State::ACTIVE) {
    // Every way of becoming active counts as one activation and starts
    // both timers.
    this->activation_count_++;
    this->active_since_ms_ = millis();
    this->last_recovery_ms_ = this->active_since_ms_;
  }
}

}  // namespace esphome::tang_server

namespace esphome::tang_server {

void TangServer::notify_request(const std::string &path, const char *method, int status) {
  this->fire_(this->request_callback_, path, std::string(method), status);
}

void TangServer::notify_auth_failure(const std::string &path) { this->fire_(this->auth_failure_callback_, path); }

/// One activation, run in its own task. With `done` set, the caller waits
/// on it and takes `result`; without, the task frees the job.
struct TangServer::ActivateJob {
  TangServer *server;
  std::string password;
  bool has_password;
  const char *source;
  /// The action goes through the backoff here; /activate already did.
  bool check_backoff;
  SemaphoreHandle_t done{nullptr};
  Result result{500, "text/plain", "Activation did not run"};
};

bool TangServer::start_activation_(ActivateJob *job, const std::string *password) {
  if (password != nullptr) {
    // Sized once, so the copy never reallocates and leaves one behind.
    job->password.reserve(password->size());
    job->password = *password;
  }
  // 8 KB, about twice what the httpd task has: PBKDF2, AES-GCM and the key
  // checks run here. Same priority as the main loop, which keeps running.
  if (xTaskCreate(&TangServer::activate_task_, "tang_activate", 8192, job, 1, nullptr) == pdPASS)
    return true;
  ESP_LOGE(TAG, "%s: cannot start the activation task", job->source);
  tang_server::wipe(job->password);
  this->activation_running_ = false;
  return false;
}

Result TangServer::run_activation_(const std::string &password, bool has_password, const char *source) {
  if (this->activation_running_.exchange(true))
    return Result::text(409, "An activation is already running.");
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  auto *job = new ActivateJob{this, {}, has_password, source, false, xSemaphoreCreateBinary()};
  Result result = Result::text(500, "Cannot start the activation");
  if (job->done != nullptr && this->start_activation_(job, &password)) {
    xSemaphoreTake(job->done, portMAX_DELAY);
    result = std::move(job->result);
  } else if (job->done == nullptr) {
    this->activation_running_ = false;
  }
  if (job->done != nullptr)
    vSemaphoreDelete(job->done);
  delete job;  // NOLINT(cppcoreguidelines-owning-memory)
  return result;
}

void TangServer::activate_in_background(const std::string *password) {
  static const char *const SOURCE = "tang_server.activate";
  if (this->activation_running_.exchange(true)) {
    ESP_LOGW(TAG, "%s: an activation is already running", SOURCE);
    return;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  auto *job = new ActivateJob{this, {}, password != nullptr, SOURCE, true};
  if (!this->start_activation_(job, password))
    delete job;  // NOLINT(cppcoreguidelines-owning-memory)
}

void TangServer::activate_task_(void *arg) {
  auto *job = static_cast<ActivateJob *>(arg);
  TangServer *server = job->server;
  {
    ScopedWipe<std::string> wipe_password{job->password};
    uint32_t blocked_ms =
        job->check_backoff && server->require_password_ ? server->auth_blocked_ms(false, true) : 0;
    if (blocked_ms != 0) {
      ESP_LOGW(TAG, "%s: refused by auth backoff for %" PRIu32 " s", job->source, (blocked_ms + 999) / 1000);
      server->notify_auth_failure(job->source);
    } else {
      job->result = server->activate_(job->password, job->has_password, job->source);
      if (job->done == nullptr) {
        // No one waits for the result, so log it.
        ESP_LOGI(TAG, "%s -> %d: %s", job->source, job->result.status, job->result.body.c_str());
      }
    }
  }
  server->activation_running_ = false;
  if (job->done != nullptr) {
    // The waiting caller frees the job.
    xSemaphoreGive(job->done);
  } else {
    delete job;  // NOLINT(cppcoreguidelines-owning-memory)
  }
  vTaskDelete(nullptr);
}

}  // namespace esphome::tang_server
