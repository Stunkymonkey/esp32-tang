#include "tang_server.h"

#include <cinttypes>
#include <cstring>
#include <strings.h>

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
  if (!this->last_error_.empty())
    ESP_LOGCONFIG(TAG, "  Last error: %s", this->last_error_.c_str());
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
    return;
  }
  ESP_LOGI(TAG, "Activated %zu stored keys", this->keys_.size());
  this->set_state_(State::ACTIVE);
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

Result TangServer::inactive_result_() const {
  // Clevis treats this as a failure and falls back to the passphrase.
  std::string body = "Server not active (";
  body += state_to_string(this->state_);
  body += ")";
  return {503, "text/plain", body};
}

Result TangServer::adv(const std::string &thp) {
  LockGuard guard(this->lock_);
  if (this->state_ != State::ACTIVE)
    return this->inactive_result_();
  return build_adv(this->keys_, thp);
}

Result TangServer::rec(const std::string &thp, const std::vector<uint8_t> &body) {
  LockGuard guard(this->lock_);
  if (this->state_ != State::ACTIVE)
    return this->inactive_result_();
  return exchange(this->keys_, thp, reinterpret_cast<const char *>(body.data()), body.size());
}

Result TangServer::provision(const std::vector<uint8_t> &body) {
  LockGuard guard(this->lock_);
  // Replacing keys always takes an explicit /wipe first, so a stray
  // provision cannot overwrite the keys existing bindings depend on.
  if (this->state_ != State::UNPROVISIONED)
    return Result::text(409, "Already provisioned. Wipe first.");

  std::string error;
  if (!parse_keys(reinterpret_cast<const char *>(body.data()), body.size(), this->keys_, error)) {
    ESP_LOGW(TAG, "Provision rejected: %s", error.c_str());
    return {400, "text/plain", error};
  }

  ESP_LOGI(TAG, "Provisioned %zu keys", this->keys_.size());
  if (this->key_storage_ == KeyStorage::RAM) {
    // Nothing to store, so provisioning activates directly.
    this->set_state_(State::ACTIVE);
    return Result::text(200, "Provisioned and active.");
  }
  // Provisioning never writes to flash; the first /activate stores the keys.
  this->set_state_(State::PENDING);
  return Result::text(200, "Provisioned. POST /activate to store the keys and serve them.");
}

Result TangServer::activate(const std::vector<uint8_t> &body) {
  LockGuard guard(this->lock_);

  // {"password": "..."} with require_password, else no body. A mismatch is
  // refused, so a wrong setup shows up instead of storing keys in a way the
  // user did not expect.
  std::string password;
  ScopedWipe<std::string> wipe_password{password};
  bool has_password = false;
  if (!body.empty()) {
    JsonDocument doc(WipingAllocator::instance());
    if (deserializeJson(doc, reinterpret_cast<const char *>(body.data()), body.size()) || !doc.is<JsonObject>())
      return Result::text(400, "Invalid JSON");
    JsonVariantConst value = doc["password"];
    has_password = !value.isNull();
    if (has_password) {
      if (!value.is<const char *>())
        return Result::text(400, "The password must be a string");
      const char *p = value.as<const char *>();
      password.reserve(strlen(p));
      password = p;
    }
  }
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
      ESP_LOGI(TAG, "Activated: keys stored");
      this->set_state_(State::ACTIVE);
      return Result::text(200, "Keys stored and active.");
    }
    case State::LOCKED:
      switch (this->load_stored_keys_(error, key_password)) {
        case KeyStore::LoadResult::OK:
          break;
        case KeyStore::LoadResult::WRONG_PASSWORD:
          // A corrupt record looks the same; the tag check cannot tell.
          ESP_LOGW(TAG, "/activate: wrong password");
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
  this->clear_keys_();
  // Stored keys stay and can be activated again. Keys that were never
  // stored (ram, or pending) are gone.
  if (this->state_ == State::ACTIVE && this->key_storage_ == KeyStorage::NVS) {
    this->set_state_(State::LOCKED);
  } else if (this->state_ != State::LOCKED) {
    this->set_state_(State::UNPROVISIONED);
  }
  return Result::text(200, "Deactivated.");
}

Result TangServer::wipe() {
  LockGuard guard(this->lock_);
  this->clear_keys_();
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

Result TangServer::status(bool /*detailed*/) {
  LockGuard guard(this->lock_);
  // The detailed view comes with the rest of /status.
  std::string body = R"({"state":")";
  body += state_to_string(this->state_);
  body += R"("})";
  return {200, "application/json", body};
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
}

}  // namespace esphome::tang_server
