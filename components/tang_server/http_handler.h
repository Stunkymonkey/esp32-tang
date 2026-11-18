#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "esphome/components/web_server_base/web_server_base.h"

#include "tang_crypto.h"

namespace esphome::tang_server {

class TangServer;

/// Serves the Tang and management endpoints on web_server_base. Only does
/// HTTP: matching paths, collecting bodies, checking the token and turning
/// results into responses. Runs in the httpd task.
class HttpHandler : public AsyncWebHandler {
 public:
  explicit HttpHandler(TangServer *server) : server_(server) {}

  bool canHandle(AsyncWebServerRequest *request) const override;
  void handleRequest(AsyncWebServerRequest *request) override;
  void handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) override;
  bool isRequestHandlerTrivial() const override { return false; }

  /// Bodies above this are refused with 413 before they are buffered.
  static constexpr size_t MAX_BODY_SIZE = 4096;

  enum class Route : uint8_t { NONE, ADV, REC, PROVISION, ACTIVATE, DEACTIVATE, WIPE, STATUS };
  struct Target {
    Route route;
    std::string path;
    std::string thp;
  };

 protected:
  /// Handles a matched request and sends the response. @return its status.
  int handle_(AsyncWebServerRequest *request, const Target &target);
  void send_(AsyncWebServerRequest *request, const Result &result);
  void reset_body_();
  void log_stack_();

  TangServer *server_;

  // httpd runs one request at a time, so one body buffer is enough. It is
  // tied to the request it was collected for, and wiped after every request.
  // A request whose body could not be read to the end never reaches
  // handleRequest(); its partial body is reset by the next one.
  std::vector<uint8_t> body_;
  const AsyncWebServerRequest *body_request_{nullptr};
  bool body_complete_{false};
  bool body_too_large_{false};
  bool body_out_of_order_{false};

  uint32_t stack_high_water_{UINT32_MAX};
  // Retry-After of the response being sent; httpd keeps the pointer.
  char retry_after_[12]{};
};

}  // namespace esphome::tang_server
