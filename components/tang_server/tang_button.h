#pragma once

#include "esphome/core/defines.h"
#ifdef USE_BUTTON

#include <string>

#include "esphome/components/button/button.h"
#include "esphome/core/helpers.h"
#ifdef USE_TEXT
#include "esphome/components/text/text.h"
#endif

#include "tang_server.h"

namespace esphome::tang_server {

// Buttons, pressed on the main loop. Like the actions, they need no
// admin_token.

class DeactivateButton : public button::Button, public Parented<TangServer> {
 protected:
  void press_action() override { this->parent_->deactivate(); }
};

class WipeButton : public button::Button, public Parented<TangServer> {
 protected:
  void press_action() override { this->parent_->wipe(); }
};

/// Activates in the background, like tang_server.activate. With
/// require_password, the password comes from a text entity, which is cleared
/// right away, so the password does not stay in Home Assistant's state.
class ActivateButton : public button::Button, public Parented<TangServer> {
 public:
#ifdef USE_TEXT
  void set_password_text(text::Text *text) { this->password_text_ = text; }
#endif

 protected:
  void press_action() override {
#ifdef USE_TEXT
    if (this->password_text_ != nullptr) {
      std::string password;
      ScopedWipe<std::string> wipe_password{password};
      password.reserve(this->password_text_->state.size());
      password = this->password_text_->state;
      // Wipe the entity's own copy, then publish it empty.
      wipe(this->password_text_->state);
      this->password_text_->make_call().set_value("").perform();
      this->parent_->activate_in_background(&password);
      return;
    }
#endif
    this->parent_->activate_in_background(nullptr);
  }

#ifdef USE_TEXT
  text::Text *password_text_{nullptr};
#endif
};

}  // namespace esphome::tang_server

#endif  // USE_BUTTON
