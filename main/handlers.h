#ifndef HANDLERS_H
#define HANDLERS_H

// --- Tang Protocol Handlers ---
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

/**
 * @brief Handles the /adv endpoint.
 * Returns a signed JWKSet containing the active keys.
 */
void handleAdv() {
    DEBUG_PRINTLN("Received request for /adv");

    if (active_keys.empty()) {
        server_http.send(503, "text/plain", "Server not active (no keys loaded)");
        return;
    }

    // 1. Identify the signing key
    const TangKey* signing_key = nullptr;
    for (const auto& key : active_keys) {
        if (key.usage == TANG_USAGE_SIGN) {
            signing_key = &key;
            break;
        }
    }

    if (!signing_key) {
        server_http.send(500, "text/plain", "Internal Error: No signing key available");
        return;
    }

    // 2. Construct the JWKSet Payload
    DynamicJsonDocument doc(4096); 
    JsonArray keys = doc.createNestedArray("keys");

    for (const auto& key : active_keys) {
        JsonObject k = keys.createNestedObject();
        k["kty"] = "EC";
        if (key.curve_id == MBEDTLS_ECP_DP_SECP521R1) {
            k["crv"] = "P-521";
            k["alg"] = (key.usage == TANG_USAGE_SIGN) ? "ES512" : "ECMR"; 
        } else {
            k["crv"] = "P-256";
            k["alg"] = (key.usage == TANG_USAGE_SIGN) ? "ES256" : "ECMR";
        }
        k["kid"] = key.kid;
        k["x"] = base64_url_encode(key.public_key, key.key_len);
        k["y"] = base64_url_encode(key.public_key + key.key_len, key.key_len);
        
        JsonArray key_ops = k.createNestedArray("key_ops");
        if (key.usage == TANG_USAGE_SIGN) {
            key_ops.add("verify");
        } else {
            key_ops.add("deriveKey");
        }
    }

    String payload_json;
    serializeJson(doc, payload_json);

    // 3. Create JWS Header
    DynamicJsonDocument headerDoc(256);
    if (signing_key->curve_id == MBEDTLS_ECP_DP_SECP521R1) {
        headerDoc["alg"] = "ES512";
    } else {
        headerDoc["alg"] = "ES256";
    }
    headerDoc["cty"] = "jwk-set+json"; 
    
    String header_json;
    serializeJson(headerDoc, header_json);

    // 4. Sign
    String protected_header = base64_url_encode((const uint8_t*)header_json.c_str(), header_json.length());
    String payload_b64 = base64_url_encode((const uint8_t*)payload_json.c_str(), payload_json.length());
    String signing_input = protected_header + "." + payload_b64;
    
    // Hash (SHA-256 for P-256, SHA-512 for P-521)
    uint8_t hash[64];
    size_t hash_len;
    
    if (signing_key->curve_id == MBEDTLS_ECP_DP_SECP521R1) {
        mbedtls_sha512_context sha_ctx;
        mbedtls_sha512_init(&sha_ctx);
        mbedtls_sha512_starts(&sha_ctx, 0); // 0 = SHA-512
        mbedtls_sha512_update(&sha_ctx, (const uint8_t*)signing_input.c_str(), signing_input.length());
        mbedtls_sha512_finish(&sha_ctx, hash);
        mbedtls_sha512_free(&sha_ctx);
        hash_len = 64;
    } else {
        mbedtls_sha256_context sha_ctx;
        mbedtls_sha256_init(&sha_ctx);
        mbedtls_sha256_starts(&sha_ctx, 0);
        mbedtls_sha256_update(&sha_ctx, (const uint8_t*)signing_input.c_str(), signing_input.length());
        mbedtls_sha256_finish(&sha_ctx, hash);
        mbedtls_sha256_free(&sha_ctx);
        hash_len = 32;
    }

    uint8_t signature[132]; // Enough for P-521 (66*2)
    if (!sign_data(signing_key->private_key, signing_key->curve_id, signing_key->key_len, hash, hash_len, signature)) {
         server_http.send(500, "text/plain", "Signing failed");
         return;
    }

    String signature_b64 = base64_url_encode(signature, signing_key->key_len * 2);

    // Construct JWS JSON Serialization (Flattened)
    DynamicJsonDocument jwsDoc(payload_b64.length() + protected_header.length() + signature_b64.length() + 512); // Allocate enough for JSON structure
    jwsDoc["payload"] = payload_b64;
    jwsDoc["protected"] = protected_header;
    jwsDoc["signature"] = signature_b64;
    
    String jws_json;
    serializeJson(jwsDoc, jws_json);

    server_http.send(200, "application/json", jws_json);
    DEBUG_PRINTLN("Sent signed JWKSet (JSON Serialization).");
}

/**
 * @brief Handles /rec/{kid} - Key Exchange
 */
void handleRec() {
    DEBUG_PRINTLN("Received request for /rec");
    
    if (active_keys.empty()) {
        server_http.send(503, "text/plain", "Server not active");
        return;
    }

    String uri = server_http.uri();
    String prefix = "/rec/";
    if (!uri.startsWith(prefix)) {
         server_http.send(400, "text/plain", "Invalid URI format");
         return;
    }
    String kid = uri.substring(prefix.length());
    if (kid.endsWith("/")) kid.remove(kid.length() - 1);

    DEBUG_PRINTF("Requested KID: %s\n", kid.c_str());

    const TangKey* exchange_key = nullptr;
    for (const auto& key : active_keys) {
        if (key.kid.equals(kid) && key.usage == TANG_USAGE_EXCHANGE) {
            exchange_key = &key;
            break;
        }
    }

    if (!exchange_key) {
        server_http.send(404, "text/plain", "Key ID not found or not an exchange key");
        return;
    }

    if (!server_http.hasArg("plain")) {
        server_http.send(400, "text/plain", "Missing body");
        return;
    }
    
    DynamicJsonDocument reqDoc(2048);
    DeserializationError error = deserializeJson(reqDoc, server_http.arg("plain"));
    
    if (error) {
        server_http.send(400, "text/plain", "Invalid JSON");
        return;
    }

    // Check key type and curve compatibility
    String kty = reqDoc["kty"];
    String crv = reqDoc["crv"];
    
    if (kty != "EC") {
         server_http.send(400, "text/plain", "Unsupported key type");
         return;
    }
    
    // Explicitly reject mixed curve operations even if logic could handle it (Tang strictness)
    if (exchange_key->curve_id == MBEDTLS_ECP_DP_SECP521R1 && crv != "P-521") {
         server_http.send(400, "text/plain", "Curve mismatch: Server key is P-521");
         return;
    }
    if (exchange_key->curve_id == MBEDTLS_ECP_DP_SECP256R1 && crv != "P-256") {
         server_http.send(400, "text/plain", "Curve mismatch: Server key is P-256");
         return;
    }

    uint8_t client_pub[132];
    String x_str = reqDoc["x"];
    String y_str = reqDoc["y"];
    
    if (base64_url_decode(x_str, client_pub, exchange_key->key_len) != exchange_key->key_len || 
        base64_url_decode(y_str, client_pub + exchange_key->key_len, exchange_key->key_len) != exchange_key->key_len) {
        server_http.send(400, "text/plain", "Invalid x/y coordinates length");
        return;
    }

    uint8_t shared_point[132]; // X || Y
    if (!compute_ecdh_shared_secret(client_pub, exchange_key->private_key, 
                                    exchange_key->curve_id, exchange_key->key_len, 
                                    shared_point)) {
        server_http.send(500, "text/plain", "ECDH operation failed");
        return;
    }

    DynamicJsonDocument respDoc(1024);
    respDoc["kty"] = "EC";
    respDoc["crv"] = crv;
    respDoc["x"] = base64_url_encode(shared_point, exchange_key->key_len);
    respDoc["y"] = base64_url_encode(shared_point + exchange_key->key_len, exchange_key->key_len);
    respDoc["key_ops"].add("deriveKey"); 

    String response;
    serializeJson(respDoc, response);
    server_http.send(200, "application/json", response);
    DEBUG_PRINTLN("Sent ECDH result.");
}

/**
 * @brief PROVISION Endpoint
 */
void handleProvision() {
    // Keys must be provisioned on every boot unless persistent storage is implemented.
    // Strict mode: deny re-provisioning if keys are already loaded to prevent accidental state changes.
    if (!active_keys.empty()) {
        server_http.send(400, "text/plain", "Keys already loaded. Deactivate first.");
        return;
    }
    
    if (!server_http.hasArg("plain")) {
         server_http.send(400, "text/plain", "Missing body");
         return;
    }
    
    DynamicJsonDocument doc(8192); // Increased for larger P-521 payloads
    DeserializationError error = deserializeJson(doc, server_http.arg("plain"));
    
    if (error) {
        server_http.send(400, "text/plain", "Invalid JSON");
        return;
    }
    
    JsonArray keys = doc["keys"];
    if (keys.isNull()) {
        server_http.send(400, "text/plain", "Missing 'keys' array");
        return;
    }

    int count = 0;
    for (JsonObject k : keys) {
        TangKey newKey;
        newKey.kid = k["kid"].as<String>();
        
        bool usage_found = false;
        
        // 1. Check standard 'key_ops'
        JsonArray ops = k["key_ops"].as<JsonArray>();
        if (!ops.isNull()) {
            for (JsonVariant v : ops) {
                String op = v.as<String>();
                if (op == "sign" || op == "verify") {
                    newKey.usage = TANG_USAGE_SIGN;
                    usage_found = true;
                    break;
                } 
                if (op == "deriveKey") {
                    newKey.usage = TANG_USAGE_EXCHANGE;
                    usage_found = true;
                    break;
                }
            }
        }

        // 2. Fallback to 'alg' (if key_ops missing)
        if (!usage_found) {
             String alg = k["alg"];
             if (alg.startsWith("ES")) {
                 newKey.usage = TANG_USAGE_SIGN;
                 usage_found = true;
             }
             else if (alg == "ECMR") {
                 newKey.usage = TANG_USAGE_EXCHANGE;
                 usage_found = true;
             }
        }

        if (!usage_found) {
            DEBUG_PRINTLN("Skipping key with unknown usage (no usage, key_ops, or alg): " + newKey.kid);
            continue;
        } 

        // Detect Curve
        String crv = k["crv"];
        if (crv == "P-521") {
            newKey.curve_id = MBEDTLS_ECP_DP_SECP521R1;
            newKey.key_len = 66; // 528 bits = 66 bytes (rounded up from 521 params usually fits in 66)
        } else if (crv == "P-256") {
            newKey.curve_id = MBEDTLS_ECP_DP_SECP256R1;
            newKey.key_len = 32;
        } else {
            DEBUG_PRINTLN("Skipping unknown curve: " + crv);
            continue;
        }

        String d_str = k["d"];
        String x_str = k["x"];
        String y_str = k["y"];

        if (base64_url_decode(d_str, newKey.private_key, newKey.key_len) != newKey.key_len ||
            base64_url_decode(x_str, newKey.public_key, newKey.key_len) != newKey.key_len ||
            base64_url_decode(y_str, newKey.public_key + newKey.key_len, newKey.key_len) != newKey.key_len) {
            DEBUG_PRINTLN("Failed to decode key data for kid: " + newKey.kid);
            continue;
        }

        active_keys.push_back(newKey);
        count++;
    }

    if (count > 0) {
        is_active = true;
        server_http.send(200, "text/plain", "Provisioned " + String(count) + " keys.");
        DEBUG_PRINTLN("Provisioned keys.");
    } else {
        server_http.send(400, "text/plain", "No valid keys found in payload.");
    }
}


// --- Administration Handlers ---

void handleDeactivate() {
    deactivate_server();
    active_keys.clear();
    // Force vector to release memory
    std::vector<TangKey>().swap(active_keys);
    server_http.send(200, "text/plain", "Server deactivated and keys cleared.");
}

void handleReboot() {
    server_http.send(200, "text/plain", "Rebooting...");
    // Future Improvement: Gracefully shut down network stack before restart
    delay(1000);
    ESP.restart();
}

void handleNotFound() {
    if (server_http.uri().startsWith("/rec/")) {
        handleRec();
        return;
    }
    server_http.send(404, "text/plain", "Not found");
}

void deactivate_server() {
    is_active = false;
    // Secure erase
    for (auto& k : active_keys) {
        memset(k.private_key, 0, 32);
        memset(k.public_key, 0, 64);
    }
    active_keys.clear();
    DEBUG_PRINTLN("Server DEACTIVATED. Tang keys cleared from memory.");
}

#endif // HANDLERS_H
