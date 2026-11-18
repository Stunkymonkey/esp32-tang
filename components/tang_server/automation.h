#pragma once

#include <string>

#include "esphome/core/automation.h"
#include "esphome/core/helpers.h"

#include "tang_server.h"

namespace esphome::tang_server {

// Triggers. The component fires them on the main loop, whichever task the
// event happened in.

class ActivateTrigger : public Trigger<bool> {
 public:
  explicit ActivateTrigger(TangServer *parent) {
    parent->add_on_activate_callback([this](bool success) { this->trigger(success); });
  }
};

class DeactivateTrigger : public Trigger<std::string> {
 public:
  explicit DeactivateTrigger(TangServer *parent) {
    parent->add_on_deactivate_callback([this](const std::string &reason) { this->trigger(reason); });
  }
};

class StateChangeTrigger : public Trigger<std::string> {
 public:
  explicit StateChangeTrigger(TangServer *parent) {
    parent->add_on_state_change_callback([this](const std::string &state) { this->trigger(state); });
  }
};

class RecoveryTrigger : public Trigger<std::string, bool> {
 public:
  explicit RecoveryTrigger(TangServer *parent) {
    parent->add_on_recovery_callback([this](const std::string &thp, bool success) { this->trigger(thp, success); });
  }
};

class AdvTrigger : public Trigger<std::string> {
 public:
  explicit AdvTrigger(TangServer *parent) {
    parent->add_on_adv_callback([this](const std::string &thp) { this->trigger(thp); });
  }
};

class RequestTrigger : public Trigger<std::string, std::string, int> {
 public:
  explicit RequestTrigger(TangServer *parent) {
    parent->add_on_request_callback([this](const std::string &path, const std::string &method, int status) {
      this->trigger(path, method, status);
    });
  }
};

class AuthFailureTrigger : public Trigger<std::string> {
 public:
  explicit AuthFailureTrigger(TangServer *parent) {
    parent->add_on_auth_failure_callback([this](const std::string &path) { this->trigger(path); });
  }
};

class RejectedTrigger : public Trigger<std::string, std::string> {
 public:
  explicit RejectedTrigger(TangServer *parent) {
    parent->add_on_rejected_callback(
        [this](const std::string &path, const std::string &reason) { this->trigger(path, reason); });
  }
};

// Actions. They need no admin_token: whoever can run them already controls
// the device through the ESPHome API.

template<typename... Ts> class ActivateAction : public Action<Ts...>, public Parented<TangServer> {
 public:
  explicit ActivateAction(TangServer *parent) : Parented<TangServer>(parent) {}
  TEMPLATABLE_VALUE(std::string, password)

  void play(const Ts &...x) override {
    if (!this->password_.has_value()) {
      this->parent_->activate_in_background(nullptr);
      return;
    }
    std::string password = this->password_.value(x...);
    ScopedWipe<std::string> wipe_password{password};
    this->parent_->activate_in_background(&password);
  }
};

template<typename... Ts> class DeactivateAction : public Action<Ts...>, public Parented<TangServer> {
 public:
  explicit DeactivateAction(TangServer *parent) : Parented<TangServer>(parent) {}
  void play(const Ts &...x) override { this->parent_->deactivate(); }
};

template<typename... Ts> class WipeAction : public Action<Ts...>, public Parented<TangServer> {
 public:
  explicit WipeAction(TangServer *parent) : Parented<TangServer>(parent) {}
  void play(const Ts &...x) override { this->parent_->wipe(); }
};

// Conditions.

template<typename... Ts> class IsActiveCondition : public Condition<Ts...>, public Parented<TangServer> {
 public:
  explicit IsActiveCondition(TangServer *parent) : Parented<TangServer>(parent) {}
  bool check(const Ts &...x) override { return this->parent_->get_state() == State::ACTIVE; }
};

template<typename... Ts> class IsLockedCondition : public Condition<Ts...>, public Parented<TangServer> {
 public:
  explicit IsLockedCondition(TangServer *parent) : Parented<TangServer>(parent) {}
  bool check(const Ts &...x) override { return this->parent_->get_state() == State::LOCKED; }
};

/// Keys anywhere: pending, locked or active.
template<typename... Ts> class IsProvisionedCondition : public Condition<Ts...>, public Parented<TangServer> {
 public:
  explicit IsProvisionedCondition(TangServer *parent) : Parented<TangServer>(parent) {}
  bool check(const Ts &...x) override { return this->parent_->get_state() != State::UNPROVISIONED; }
};

}  // namespace esphome::tang_server
