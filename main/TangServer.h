#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include <WiFi.h>
#include <WebServer.h>
#include <uri/UriBraces.h>
#include <ArduinoJson.h>
#include <vector>
#include <string>
#include "sdkconfig.h"

// --- Compile-time Configuration ---
// Comment out this line to disable all Serial output for a "release" build.
#define DEBUG_SERIAL 1

// --- Debug Macros ---
#if defined(DEBUG_SERIAL) && DEBUG_SERIAL > 0
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

// --- Wi-Fi Configuration ---
const char* wifi_ssid = CONFIG_WIFI_SSID;
const char* wifi_password = CONFIG_WIFI_PASSWORD;
enum WifiMode { TANG_WIFI_STA, TANG_WIFI_AP };
WifiMode current_wifi_mode = TANG_WIFI_STA;
unsigned long mode_switch_timestamp = 0;
const unsigned long WIFI_MODE_DURATION = 60000; // 60 seconds

// --- Server & Crypto Globals ---
WebServer server_http(80);

// --- Server State ---
bool is_active = false;

// --- Key Management ---
#include <mbedtls/ecp.h>

enum KeyUsage {
    TANG_USAGE_SIGN,
    TANG_USAGE_EXCHANGE
};

struct TangKey {
    String kid;
    KeyUsage usage; // SIGN or EXCHANGE
    mbedtls_ecp_group_id curve_id; // MBEDTLS_ECP_DP_SECP256R1 or MBEDTLS_ECP_DP_SECP521R1
    uint8_t private_key[66]; // Max size for P-521
    uint8_t public_key[132]; // Max size for P-521 (X || Y)
    size_t key_len; // Actual length of private key (32 or 66)
};

// Global in-memory storage for keys.
// These are LOST on reboot, which is the desired behavior.
std::vector<TangKey> active_keys;

// Forward declare functions
void startAPMode();
void startSTAMode();
void deactivate_server();

// Include helper and handler files
// Order matters: helpers first (crypto), then handlers (logic using inputs)
#include "helpers.h"
#include "handlers.h"

// --- Main Application Logic ---
void setup() {
    Serial.begin(115200);
    // Give some time for power to settle and serial to connect
    delay(2000); 
    DEBUG_PRINTLN("\n\nESP32 Tang Server Starting...");

    // Keys must be provided via /provision endpoint.
    // Future Improvement: Implement persistent storage (NVS or SPIFFS) to save keys across reboots.

    if (wifi_ssid != NULL) {
        startSTAMode();
    } else {
        DEBUG_PRINTLN("ERROR: wifi_ssid is NULL! Cannot start WiFi.");
    }

    // --- Setup Server Routes ---
    server_http.on("/adv", HTTP_GET, handleAdv);
    server_http.on(UriBraces("/rec/{}"), HTTP_POST, handleRec);

    server_http.on("/provision", HTTP_POST, handleProvision); // Load keys
    server_http.on("/deactivate", HTTP_POST, handleDeactivate); // Clear keys

    server_http.on("/reboot", HTTP_GET, handleReboot);
    server_http.onNotFound(handleNotFound);

    server_http.begin();
    DEBUG_PRINTLN("HTTP server listening on port 80.");
    
    if (active_keys.empty()) {
        DEBUG_PRINTLN("Server is INACTIVE. POST to /provision to load keys.");
    }
}

void loop() {
    // --- Check for Serial Commands ---
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();
        if (command.equalsIgnoreCase("NUKE")) {
            // NUKE command clears keys and reboots.
            // Since we don't have persistent keys, a reboot is sufficient to clear state.
            DEBUG_PRINTLN("NUKE command received. Restarting...");
            ESP.restart();
        }
    }

    // --- Wi-Fi Connection Management ---
    if (WiFi.status() != WL_CONNECTED) {
        if (millis() - mode_switch_timestamp > WIFI_MODE_DURATION) {
            if (current_wifi_mode == TANG_WIFI_STA) {
                startAPMode();
            } else {
                startSTAMode();
            }
        }
        if (current_wifi_mode == TANG_WIFI_STA) {
            // Print a dot every so often while trying to connect
            if ((millis() % 2000) < 50) DEBUG_PRINT(".");
        }
    }

    server_http.handleClient();
}

// --- WiFi Mode Management ---
void startAPMode() {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("Tang-Server-Setup", NULL);
    DEBUG_PRINTLN("\nStarting Access Point 'Tang-Server-Setup'.");
    DEBUG_PRINTF("AP IP address: %s\n", WiFi.softAPIP().toString().c_str());
    current_wifi_mode = TANG_WIFI_AP;
    mode_switch_timestamp = millis();
}

void startSTAMode() {
    WiFi.mode(WIFI_STA);
    if(strlen(wifi_ssid) > 0) {
        WiFi.begin(wifi_ssid, wifi_password);
        DEBUG_PRINTF("\nConnecting to SSID: %s ", wifi_ssid);
    } else {
        DEBUG_PRINTLN("\nNo WiFi SSID configured. Skipping connection attempt.");
    }
    current_wifi_mode = TANG_WIFI_STA;
    mode_switch_timestamp = millis();
}

#endif // TANG_SERVER_H
