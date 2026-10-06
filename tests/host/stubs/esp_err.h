#pragma once
// Host stand-in for ESP-IDF's esp_err.h.
typedef int esp_err_t;
#define ESP_OK 0
inline const char *esp_err_to_name(esp_err_t) { return "esp_err"; }
