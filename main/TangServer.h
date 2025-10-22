#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <EEPROM.h>
#include <base64.h>
#include "CertHelper.h"
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

// --- Initial Setup Configuration ---
const char* initial_tang_password = CONFIG_INITIAL_TANG_PASSWORD;

// --- Server & Crypto Globals ---
WebServer server_http(80);
WebServer server_https(443);

// --- Server State ---
bool is_active = false;
unsigned long activation_timestamp = 0;
const unsigned long KEY_LIFETIME_MS = 3600000; // 1 hour

// --- Key Storage ---
uint8_t tang_private_key[32]; // In-memory only when active
uint8_t tang_public_key[64];  // In-memory only when active
uint8_t admin_private_key[32]; // Persistent in EEPROM
uint8_t admin_public_key[64];  // Derived from private key

// --- EEPROM Configuration ---
const int EEPROM_SIZE = 4096;
const int EEPROM_MAGIC_ADDR = 0;
const int EEPROM_ADMIN_KEY_ADDR = 4;
const int EEPROM_TANG_KEY_ADDR = EEPROM_ADMIN_KEY_ADDR + 32;
const int GCM_TAG_SIZE = 16;
const int EEPROM_TANG_TAG_ADDR = EEPROM_TANG_KEY_ADDR + 32;
const int EEPROM_WIFI_SSID_ADDR = EEPROM_TANG_TAG_ADDR + GCM_TAG_SIZE;
const int EEPROM_WIFI_PASS_ADDR = EEPROM_WIFI_SSID_ADDR + 33;
const int EEPROM_CERT_ADDR = EEPROM_WIFI_PASS_ADDR + 65;
const int EEPROM_CERT_KEY_ADDR = EEPROM_CERT_ADDR + 2048;
const uint32_t EEPROM_MAGIC_VALUE = 0xCAFED00D;

// Forward declare functions
void startAPMode();
void startSTAMode();

// Include helper and handler files
#include "helpers.h"
#include "handlers.h"

// --- Main Application Logic ---

void setup() {
    Serial.begin(115200);
    DEBUG_PRINTLN("\n\nESP32 Tang Server Starting (Secure Version)...");

    EEPROM.begin(EEPROM_SIZE);
    uint32_t magic = 0;
    EEPROM.get(EEPROM_MAGIC_ADDR, magic);

    // Buffers to hold PEM data for the server
    char cert_buf[2048];
    char key_buf[2048];
    memset(cert_buf, 0, sizeof(cert_buf));
    memset(key_buf, 0, sizeof(key_buf));

    if (magic == EEPROM_MAGIC_VALUE) {
        DEBUG_PRINTLN("Found existing configuration in EEPROM.");
        // Load Admin Key
        for (int i = 0; i < 32; ++i) admin_private_key[i] = EEPROM.read(EEPROM_ADMIN_KEY_ADDR + i);
        compute_ec_public_key(admin_private_key, admin_public_key);
        DEBUG_PRINTLN("Loaded admin key.");

        // Load Wi-Fi credentials if they exist
        if (EEPROM.read(EEPROM_WIFI_SSID_ADDR) != 0xFF && EEPROM.read(EEPROM_WIFI_SSID_ADDR) != 0) {
            EEPROM.get(EEPROM_WIFI_SSID_ADDR, wifi_ssid);
            EEPROM.get(EEPROM_WIFI_PASS_ADDR, wifi_password);
            DEBUG_PRINTLN("Loaded Wi-Fi credentials from EEPROM.");
        }

        // Load SSL certificate and key PEM strings from EEPROM
        EEPROM.get(EEPROM_CERT_ADDR, cert_buf);
        EEPROM.get(EEPROM_CERT_KEY_ADDR, key_buf);
        // TODO: Implement HTTPS server with proper SSL library
        // server_https.setServerKeyAndCert_P(key_buf, cert_buf);
        DEBUG_PRINTLN("Loaded SSL certificate and key from EEPROM (HTTPS disabled for now).");

    } else {
        DEBUG_PRINTLN("First run or NUKE'd: generating and saving new keys and certificate...");

        // 1. Generate and save admin key
        generate_ec_keypair(admin_public_key, admin_private_key);
        for (int i = 0; i < 32; ++i) EEPROM.write(EEPROM_ADMIN_KEY_ADDR + i, admin_private_key[i]);

        // 2. Generate initial Tang key and encrypt it with the default password
        generate_ec_keypair(tang_public_key, tang_private_key);
        uint8_t encrypted_tang_key[32];
        uint8_t gcm_tag[GCM_TAG_SIZE];
        memcpy(encrypted_tang_key, tang_private_key, 32);
        crypt_local_data_gcm(encrypted_tang_key, 32, initial_tang_password, true, gcm_tag);
        for (int i = 0; i < 32; ++i) EEPROM.write(EEPROM_TANG_KEY_ADDR + i, encrypted_tang_key[i]);
        for (int i = 0; i < GCM_TAG_SIZE; ++i) EEPROM.write(EEPROM_TANG_TAG_ADDR + i, gcm_tag[i]);

        // 3. Generate and save self-signed certificate
        CertHelper::generate_cert("Tang-ESP32-Server", 3650, key_buf, 2048, cert_buf, 2048);
        for(int i=0; i < 2048; i++) EEPROM.write(EEPROM_CERT_ADDR + i, cert_buf[i]);
        for(int i=0; i < 2048; i++) EEPROM.write(EEPROM_CERT_KEY_ADDR + i, key_buf[i]);

        // TODO: Implement HTTPS server with proper SSL library
        // server_https.setServerKeyAndCert_P(key_buf, cert_buf);
        DEBUG_PRINTLN("Generated and saved new SSL certificate (HTTPS disabled for now).");

        // 4. Write magic number and commit
        EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC_VALUE);
        if (EEPROM.commit()) {
            DEBUG_PRINTLN("Initial configuration saved to EEPROM.");
        } else {
            DEBUG_PRINTLN("ERROR: Failed to save to EEPROM!");
        }
    }

    DEBUG_PRINTLN("Admin Public Key:");
    print_hex(admin_public_key, sizeof(admin_public_key));

    startSTAMode();

    // --- Setup Server Routes ---
    // HTTP routes (temporarily using HTTP instead of HTTPS)
    server_http.on("/adv", HTTP_GET, handleAdv);
    server_http.on("/rec", HTTP_POST, handleRec);
    server_http.on("/pub", HTTP_GET, handlePub);
    server_http.on("/activate", HTTP_POST, handleActivate);
    server_http.on("/deactivate", HTTP_GET, handleDeactivate); // Simple deactivate
    server_http.on("/deactivate", HTTP_POST, handleDeactivate); // Deactivate and set new password
    server_http.on("/reboot", HTTP_GET, handleReboot);
    server_http.onNotFound(handleNotFound);

    // TODO: Setup HTTPS server with proper SSL library
    // server_https.begin();
    server_http.begin();
    DEBUG_PRINTLN("HTTP server listening on port 80 (HTTPS temporarily disabled).");
    DEBUG_PRINTLN("HTTP redirect server listening on port 80.");
    if (!is_active) {
        DEBUG_PRINTLN("Server is INACTIVE. POST to /activate to enable Tang services.");
    }
}

void loop() {
    // --- Check for Serial Commands ---
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();
        if (command.equalsIgnoreCase("NUKE")) {
            DEBUG_PRINTLN("!!! NUKE command received! Wiping configuration...");
            // By writing a different value to the magic address, we force
            // the setup() function to re-initialize everything on next boot.
            EEPROM.put(EEPROM_MAGIC_ADDR, (uint32_t)0x00);
            if (EEPROM.commit()) {
                DEBUG_PRINTLN("Configuration wiped. Restarting device.");
            } else {
                DEBUG_PRINTLN("ERROR: Failed to wipe configuration!");
            }
            delay(1000);
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

    // --- Automatic Deactivation Timer ---
    if (is_active && (millis() - activation_timestamp > KEY_LIFETIME_MS)) {
        DEBUG_PRINTLN("Key lifetime expired. Deactivating server automatically.");
        deactivate_server();
    }

    server_http.handleClient();
    // TODO: Handle HTTPS client connections
    // server_https.handleClient();
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
