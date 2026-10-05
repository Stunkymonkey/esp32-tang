#include "tang_server.h"

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
                "  Admin token: %s\n"
                "  State: %s",
                this->key_storage_ == KeyStorage::RAM ? "ram" : "nvs", YESNO(this->has_admin_token()),
                state_to_string(this->state_));
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
  this->set_state_(State::ACTIVE);
  return Result::text(200, "Provisioned and active.");
}

Result TangServer::deactivate() {
  LockGuard guard(this->lock_);
  // With ram storage, RAM holds the only copy, so this is the same as /wipe.
  this->clear_keys_();
  this->set_state_(State::UNPROVISIONED);
  return Result::text(200, "Deactivated.");
}

Result TangServer::wipe() {
  LockGuard guard(this->lock_);
  this->clear_keys_();
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

void TangServer::set_state_(State state) {
  if (state == this->state_)
    return;
  ESP_LOGI(TAG, "State: %s -> %s", state_to_string(this->state_), state_to_string(state));
  this->state_ = state;
}

}  // namespace esphome::tang_server
