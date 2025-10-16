#ifndef HANDLERS_H
#define HANDLERS_H

// --- Tang Protocol Handlers ---

void handleAdv() {
    if (!is_active) {
        server_http.send(403, "text/plain", "Server not active");
        return;
    }
    DEBUG_PRINTLN("Received request for /adv");

    DynamicJsonDocument doc(512);
    JsonArray keys = doc.createNestedArray("keys");
    JsonObject key = keys.createNestedObject();
    key["kty"] = "EC";
    key["crv"] = "P-256";
    key["x"] = base64_url_encode(tang_public_key, 32);
    key["y"] = base64_url_encode(tang_public_key + 32, 32);
    JsonArray key_ops = key.createNestedArray("key_ops");
    key_ops.add("deriveKey");
    key["alg"] = "ECMR"; // Note: This implementation is incomplete

    String response;
    serializeJson(doc, response);
    server_http.send(200, "application/json", response);
    DEBUG_PRINTLN("Sent public key advertisement.");
}

void handleRec() {
    if (!is_active) {
        server_http.send(403, "text/plain", "Server not active");
        return;
    }
    // The ECMR operation is complex and not implemented here.
    server_http.send(501, "text/plain", "Not Implemented: ECMR key recovery is not supported.");
}


// --- Administration Handlers ---

void handlePub() {
    DEBUG_PRINTLN("Received request for /pub");
    DynamicJsonDocument doc(512);
    JsonObject key = doc.to<JsonObject>();
    key["kty"] = "EC";
    key["crv"] = "P-256";
    key["x"] = base64_url_encode(admin_public_key, 32);
    key["y"] = base64_url_encode(admin_public_key + 32, 32);
    key["alg"] = "ECDH-ES";

    String response;
    serializeJson(doc, response);
    server_http.send(200, "application/json", response);
}

void handleActivate() {
    if (is_active) {
        server_http.send(400, "text/plain", "Already active");
        return;
    }
    if (!server_http.hasArg("plain")) {
        server_http.send(400, "text/plain", "Bad Request: Missing body");
        return;
    }
    String body = server_http.arg("plain");

    DynamicJsonDocument reqDoc(1024);
    deserializeJson(reqDoc, body);

    // 1. ECDH to derive shared secret
    JsonObject epk = reqDoc["header"]["epk"];
    uint8_t eph_pub_key[64];
    base64_url_decode(epk["x"].as<String>(), eph_pub_key, 32);
    base64_url_decode(epk["y"].as<String>(), eph_pub_key + 32, 32);

    uint8_t shared_secret[32];
    if (!compute_ecdh_shared_secret(eph_pub_key, admin_private_key, shared_secret)) {
        server_http.send(500, "text/plain", "Activation ECDH failed");
        return;
    }

    // 2. Derive CEK using Concat KDF
    uint8_t cek[16];
    const char* enc_alg_id = "A128GCM";
    const char* protected_header_b64 = reqDoc["protected"];
    concat_kdf(cek, sizeof(cek), shared_secret, sizeof(shared_secret), enc_alg_id, strlen(enc_alg_id));

    // 3. Decrypt the password (JWE ciphertext)
    String iv_b64 = reqDoc["iv"];
    String ciphertext_b64 = reqDoc["ciphertext"];
    String tag_b64 = reqDoc["tag"];

    uint8_t iv_buf[12];
    uint8_t tag_buf[16];
    base64_url_decode(iv_b64, iv_buf, sizeof(iv_buf));
    base64_url_decode(tag_b64, tag_buf, sizeof(tag_buf));

    uint8_t password_buf[65] = {0}; // Max password length + null terminator
    int decoded_len = base64_url_decode(ciphertext_b64, password_buf, sizeof(password_buf));
    if (decoded_len < 0) {
        server_http.send(400, "text/plain", "Bad Request: Invalid ciphertext encoding");
        return;
    }

    if (!jwe_gcm_decrypt(password_buf, decoded_len, cek, sizeof(cek), iv_buf, sizeof(iv_buf), tag_buf, sizeof(tag_buf), (const uint8_t*)protected_header_b64, strlen(protected_header_b64))) {
        server_http.send(401, "text/plain", "JWE decryption failed: invalid message or tag");
        return;
    }

    // 4. Use decrypted password to decrypt the locally stored Tang key
    char* password_str = (char*)password_buf;
    DEBUG_PRINTF("Decrypted activation password: %s\n", password_str);

    uint8_t encrypted_tang_key[32];
    uint8_t gcm_tag[GCM_TAG_SIZE];
    for(int i=0; i<32; ++i) encrypted_tang_key[i] = EEPROM.read(EEPROM_TANG_KEY_ADDR + i);
    for(int i=0; i<GCM_TAG_SIZE; ++i) gcm_tag[i] = EEPROM.read(EEPROM_TANG_TAG_ADDR + i);

    if (crypt_local_data_gcm(encrypted_tang_key, 32, password_str, false, gcm_tag)) {
        memcpy(tang_private_key, encrypted_tang_key, 32);
        compute_ec_public_key(tang_private_key, tang_public_key);
        is_active = true;
        activation_timestamp = millis();
        DEBUG_PRINTLN("Server ACTIVATED.");
        server_http.send(200, "text/plain", "Server activated successfully");
    } else {
        DEBUG_PRINTLN("GCM tag check failed for local key! Invalid password.");
        server_http.send(401, "text/plain", "Activation failed: invalid password for stored key");
    }
}

void handleDeactivate() {
    if (server_http.method() == HTTP_GET) {
        deactivate_server();
        server_http.send(200, "text/plain", "Server deactivated");
        return;
    }

    if (server_http.method() == HTTP_POST) {
        if (!is_active) {
            server_http.send(400, "text/plain", "Already inactive");
            return;
        }
        String body = server_http.arg("plain");
        DynamicJsonDocument reqDoc(1024);
        deserializeJson(reqDoc, body);

        JsonObject epk = reqDoc["header"]["epk"];
        uint8_t eph_pub_key[64];
        base64_url_decode(epk["x"].as<String>(), eph_pub_key, 32);
        base64_url_decode(epk["y"].as<String>(), eph_pub_key + 32, 32);

        uint8_t shared_secret[32];
        if (!compute_ecdh_shared_secret(eph_pub_key, admin_private_key, shared_secret)) {
            server_http.send(500, "text/plain", "Deactivation ECDH failed");
            return;
        }

        uint8_t cek[16];
        const char* enc_alg_id = "A128GCM";
        const char* protected_header_b64 = reqDoc["protected"];
        concat_kdf(cek, sizeof(cek), shared_secret, sizeof(shared_secret), enc_alg_id, strlen(enc_alg_id));

        uint8_t iv_buf[12], tag_buf[16];
        base64_url_decode(reqDoc["iv"].as<String>(), iv_buf, sizeof(iv_buf));
        base64_url_decode(reqDoc["tag"].as<String>(), tag_buf, sizeof(tag_buf));

        uint8_t password_buf[65] = {0};
        int decoded_len = base64_url_decode(reqDoc["ciphertext"].as<String>(), password_buf, sizeof(password_buf));
        if (decoded_len < 0) {
            server_http.send(400, "text/plain", "Bad Request: Invalid ciphertext encoding");
            return;
        }

        if (!jwe_gcm_decrypt(password_buf, decoded_len, cek, sizeof(cek), iv_buf, sizeof(iv_buf), tag_buf, sizeof(tag_buf), (const uint8_t*)protected_header_b64, strlen(protected_header_b64))) {
            server_http.send(401, "text/plain", "JWE decryption failed for new password");
            return;
        }

        char* new_password_str = (char*)password_buf;
        DEBUG_PRINTF("Received new password for saving: %s\n", new_password_str);

        uint8_t key_to_save[32];
        uint8_t new_gcm_tag[GCM_TAG_SIZE];
        memcpy(key_to_save, tang_private_key, 32);
        crypt_local_data_gcm(key_to_save, 32, new_password_str, true, new_gcm_tag);

        for(int i=0; i<32; ++i) EEPROM.write(EEPROM_TANG_KEY_ADDR + i, key_to_save[i]);
        for(int i=0; i<GCM_TAG_SIZE; ++i) EEPROM.write(EEPROM_TANG_TAG_ADDR + i, new_gcm_tag[i]);
        EEPROM.commit();

        DEBUG_PRINTLN("New encrypted Tang key saved to EEPROM.");
        deactivate_server();
        server_http.send(200, "text/plain", "Key saved and server deactivated");
    }
}

void handleWifiConfig() {
    String body = server_http.arg("plain");
    DynamicJsonDocument doc(256);
    deserializeJson(doc, body);

    const char* new_ssid = doc["ssid"];
    const char* new_pass = doc["password"];

    if (!new_ssid) {
        server_http.send(400, "text/plain", "SSID is required");
        return;
    }

    DEBUG_PRINTLN("Received new Wi-Fi configuration.");
    DEBUG_PRINTF("SSID: %s\n", new_ssid);

    for (int i=0; i < 33; i++) EEPROM.write(EEPROM_WIFI_SSID_ADDR + i, 0);
    for (int i=0; i < strlen(new_ssid); i++) EEPROM.write(EEPROM_WIFI_SSID_ADDR + i, new_ssid[i]);

    for (int i=0; i < 65; i++) EEPROM.write(EEPROM_WIFI_PASS_ADDR + i, 0);
    if(new_pass) {
        for (int i=0; i < strlen(new_pass); i++) EEPROM.write(EEPROM_WIFI_PASS_ADDR + i, new_pass[i]);
    }

    EEPROM.commit();

    server_http.send(200, "text/plain", "Wi-Fi credentials saved. Restarting...");
    delay(1000);
    ESP.restart();
}

void handleReboot() {
    server_http.send(200, "text/plain", "Rebooting...");
    delay(1000);
    ESP.restart();
}

void handleNotFound() {
    server_http.send(404, "text/plain", "Not found");
}

void handleHttpRedirect() {
    String host = server_http.hasHeader("Host") ? server_http.header("Host") : WiFi.localIP().toString();
    String redirectUrl = "https://" + host + server_http.uri();
    server_http.sendHeader("Location", redirectUrl, true);
    server_http.send(308, "text/plain", "Redirecting to HTTPS"); // 308 Permanent Redirect
}

#endif // HANDLERS_H
