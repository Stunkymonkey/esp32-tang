#include "http_handler.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>

#include <esp_http_server.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "esphome/core/log.h"
#include "esphome/core/string_ref.h"

#include "tang_server.h"

namespace esphome::tang_server {

static const char *const TAG = "tang_server.http";

namespace {

using Route = HttpHandler::Route;
using Target = HttpHandler::Target;

/// Matches the component's paths. Like tangd ("^/+adv/*$", "^/+adv/+<thp>$"),
/// one trailing slash after the thumbprint is accepted. A path below /adv/ or
/// /rec/ that is not a single segment yields Route::NONE with `owned` set, so
/// it gets a 404 here rather than falling through to another handler.
Route match(StringRef url, std::string *thp, bool *owned) {
  static constexpr const char *ADV = "/adv/";
  static constexpr const char *REC = "/rec/";
  *owned = true;

  if (url == "/provision")
    return Route::PROVISION;
  if (url == "/activate")
    return Route::ACTIVATE;
  if (url == "/deactivate")
    return Route::DEACTIVATE;
  if (url == "/wipe")
    return Route::WIPE;
  if (url == "/status")
    return Route::STATUS;
  if (url == "/adv")
    return Route::ADV;

  Route route;
  if (strncmp(url.c_str(), ADV, 5) == 0) {
    route = Route::ADV;
  } else if (strncmp(url.c_str(), REC, 5) == 0) {
    route = Route::REC;
  } else {
    *owned = false;
    return Route::NONE;
  }

  const char *segment = url.c_str() + 5;
  size_t len = url.size() - 5;
  if (len > 0 && segment[len - 1] == '/')
    len--;
  if (memchr(segment, '/', len) != nullptr)
    return Route::NONE;
  // "/adv/" is the plain advertisement; "/rec/" has no key to exchange with.
  if (len == 0 && route == Route::REC)
    return Route::NONE;
  if (thp != nullptr)
    thp->assign(segment, len);
  return route;
}

const char *status_line(int code) {
  // httpd_resp_set_status() needs the full line, and the request's own
  // send() turns most codes into 500.
  switch (code) {
    case 200:
      return "200 OK";
    case 400:
      return "400 Bad Request";
    case 401:
      return "401 Unauthorized";
    case 404:
      return "404 Not Found";
    case 405:
      return "405 Method Not Allowed";
    case 409:
      return "409 Conflict";
    case 413:
      return "413 Content Too Large";
    case 415:
      return "415 Unsupported Media Type";
    case 429:
      return "429 Too Many Requests";
    case 503:
      return "503 Service Unavailable";
    default:
      return "500 Internal Server Error";
  }
}

/// Out of line, so the URL buffer is off the stack before any crypto runs
/// on the httpd task's small stack.
__attribute__((noinline)) Target resolve(AsyncWebServerRequest *request) {
  char url_buf[AsyncWebServerRequest::URL_BUF_SIZE];
  StringRef url = request->url_to(url_buf);
  Target target;
  bool owned;
  target.route = match(url, &target.thp, &owned);
  target.path.assign(url.c_str(), url.size());
  return target;
}

const char *method_name(http_method method) {
  return method == HTTP_GET ? "GET" : method == HTTP_POST ? "POST" : http_method_str(method);
}

}  // namespace

bool HttpHandler::canHandle(AsyncWebServerRequest *request) const {
  char url_buf[AsyncWebServerRequest::URL_BUF_SIZE];
  bool owned;
  match(request->url_to(url_buf), nullptr, &owned);
  return owned;
}

void HttpHandler::handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
  if (index == 0) {
    this->reset_body_();
    this->body_request_ = request;
    if (total > MAX_BODY_SIZE) {
      this->body_too_large_ = true;
    } else {
      // Reserved once, so the buffer never reallocates and leaves an unwiped
      // copy behind.
      this->body_.reserve(total);
    }
  }
  if (request != this->body_request_ || this->body_too_large_ || this->body_out_of_order_)
    return;
  if (index != this->body_.size() || this->body_.size() + len > total) {
    this->body_out_of_order_ = true;
    return;
  }
  this->body_.insert(this->body_.end(), data, data + len);
  this->body_complete_ = this->body_.size() == total;
}

void HttpHandler::handleRequest(AsyncWebServerRequest *request) {
  Target target = resolve(request);
  const char *method = method_name(request->method());
  int status = this->handle_(request, target);
  this->reset_body_();
  // After the response is sent, for on_request.
  this->server_->notify_request(target.path, method, status);
}

int HttpHandler::handle_(AsyncWebServerRequest *request, const Target &target) {
  Route route = target.route;
  const std::string &thp = target.thp;
  const char *path = target.path.c_str();
  http_method method = request->method();

  Result result = Result::text(404, "Not found");
  if (route == Route::NONE) {
    this->send_(request, result);
    ESP_LOGD(TAG, "%s %s -> %d", method_name(method), path, result.status);
    return result.status;
  }

  bool is_post = route != Route::ADV && route != Route::STATUS;
  if (method != (is_post ? HTTP_POST : HTTP_GET)) {
    httpd_resp_set_hdr(*request, "Allow", is_post ? "POST" : "GET");
    result = Result::text(405, "Method not allowed");
    this->send_(request, result);
    ESP_LOGD(TAG, "%s %s -> %d", method_name(method), path, result.status);
    return result.status;
  }

  if (is_post) {
    // web_server_base hands only non-form bodies to handleBody(). Form data
    // (curl -d, or no Content-Type) goes to its own parser and never arrives.
    bool collected = this->body_request_ == request;
    size_t content_length = request->contentLength();
    if (!collected)
      this->reset_body_();  // a partial body left by an earlier request

    const char *body_error = nullptr;
    if (collected && this->body_too_large_) {
      result = Result::text(413, "Body too large");
      body_error = "too large";
    } else if (content_length > 0 && !collected) {
      result = Result::text(415, "Send the body as JSON (Content-Type: application/json)");
      body_error = "not JSON";
    } else if (collected && (this->body_out_of_order_ || !this->body_complete_ ||
                             this->body_.size() != content_length)) {
      result = Result::text(400, "Incomplete body");
      body_error = "incomplete";
    }
    if (body_error != nullptr) {
      this->send_(request, result);
      ESP_LOGW(TAG, "%s %s -> %d: body %s", method_name(method), path, result.status, body_error);
      return result.status;
    }
  }

  bool management = route == Route::PROVISION || route == Route::ACTIVATE || route == Route::DEACTIVATE ||
                    route == Route::WIPE;
  auto authorization = request->get_header("Authorization");
  // Which secrets this request checks: the token on every management
  // endpoint, and on /status when one is sent; the key password on /activate.
  bool checks_token =
      this->server_->has_admin_token() && (management || (route == Route::STATUS && authorization.has_value()));
  bool checks_password = route == Route::ACTIVATE && this->server_->get_require_password();
  uint32_t blocked_ms = 0;
  bool token_ok = true;

  if (route == Route::ACTIVATE && this->server_->get_key_storage() == KeyStorage::RAM) {
    // Nothing is stored with ram, so there is nothing to activate.
    result = Result::text(404, "Not found: /activate needs key_storage: nvs");
  } else if ((checks_token || checks_password) &&
             (blocked_ms = this->server_->auth_blocked_ms(checks_token, checks_password)) != 0) {
    // Refused before any secret is looked at, so waiting is the only way on.
    snprintf(this->retry_after_, sizeof(this->retry_after_), "%" PRIu32, (blocked_ms + 999) / 1000);
    httpd_resp_set_hdr(*request, "Retry-After", this->retry_after_);
    result = Result::text(429, "Too many failed attempts. Retry later.");
    ESP_LOGW(TAG, "%s %s: refused by auth backoff for %s s", method_name(method), path, this->retry_after_);
    this->server_->notify_auth_failure(target.path);
  } else if (checks_token && !(token_ok = this->server_->check_token(authorization))) {
    // A wrong token on /status is an error, not a fallback to the public view.
    this->server_->auth_result(Secret::TOKEN, false);
    httpd_resp_set_hdr(*request, "WWW-Authenticate", "Bearer");
    result = Result::text(401, "Unauthorized");
    ESP_LOGW(TAG, "%s %s: missing or wrong token", method_name(method), path);
    this->server_->notify_auth_failure(target.path);
  } else {
    if (checks_token)
      this->server_->auth_result(Secret::TOKEN, true);
    switch (route) {
      case Route::ADV:
        result = this->server_->adv(thp);
        break;
      case Route::REC:
        result = this->server_->rec(thp, this->body_);
        break;
      case Route::PROVISION:
        result = this->server_->provision(this->body_);
        break;
      case Route::ACTIVATE:
        result = this->server_->activate(this->body_);
        break;
      case Route::DEACTIVATE:
        result = this->server_->deactivate();
        break;
      case Route::WIPE:
        result = this->server_->wipe();
        break;
      case Route::STATUS:
        // Detailed with a valid token, or when no admin_token is set.
        result = this->server_->status(!this->server_->has_admin_token() || (checks_token && token_ok));
        break;
      default:
        break;
    }
    this->log_stack_();
  }

  this->send_(request, result);
  ESP_LOGD(TAG, "%s %s -> %d", method_name(method), path, result.status);
  return result.status;
}

void HttpHandler::send_(AsyncWebServerRequest *request, const Result &result) {
  httpd_req_t *req = *request;
  httpd_resp_set_status(req, status_line(result.status));
  httpd_resp_set_type(req, result.content_type);
  httpd_resp_send(req, result.body.data(), result.body.size());
}

void HttpHandler::reset_body_() {
  wipe(this->body_);
  // Give the memory back; the next body reserves its own size.
  std::vector<uint8_t>().swap(this->body_);
  this->body_request_ = nullptr;
  this->body_complete_ = false;
  this->body_too_large_ = false;
  this->body_out_of_order_ = false;
}

void HttpHandler::log_stack_() {
  // ESP-IDF counts stack in bytes. Logged whenever a new low is reached, to
  // check that P-521 fits the httpd task's stack. The deepest paths are the
  // EC operations of /provision, /adv and /rec.
  uint32_t free_bytes = uxTaskGetStackHighWaterMark(nullptr);
  if (free_bytes < this->stack_high_water_) {
    this->stack_high_water_ = free_bytes;
    ESP_LOGI(TAG, "httpd stack: %" PRIu32 " bytes never used", free_bytes);
  }
}

}  // namespace esphome::tang_server
