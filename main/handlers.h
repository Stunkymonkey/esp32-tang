#ifndef HANDLERS_H
#define HANDLERS_H

// --- Tang Protocol Handlers ---

void handleAdv()
{
  if (!is_active)
  {
    server_http.send(503, "text/plain", "Server not active. POST to /activate first.");
    return;
  }

  // 1. Create the payload (JWK set)
  DynamicJsonDocument payload_doc(768);
  JsonArray keys = payload_doc.createNestedArray("keys");

  // Add signing/verification key (used to verify this advertisement)
  JsonObject sig_key = keys.createNestedObject();
  sig_key["alg"] = "ES256";
  sig_key["kty"] = "EC";
  sig_key["crv"] = "P-256";
  sig_key["x"] = base64_url_encode(tang_sig_public_key, 32);
  sig_key["y"] = base64_url_encode(tang_sig_public_key + 32, 32);
  JsonArray sig_key_ops = sig_key.createNestedArray("key_ops");
  sig_key_ops.add("verify");

  // Add recovery key (used for ECMR key derivation)
  JsonObject rec_key = keys.createNestedObject();
  rec_key["alg"] = "ECMR";
  rec_key["kty"] = "EC";
  rec_key["crv"] = "P-256";
  rec_key["x"] = base64_url_encode(tang_exc_public_key, 32);
  rec_key["y"] = base64_url_encode(tang_exc_public_key + 32, 32);
  JsonArray rec_key_ops = rec_key.createNestedArray("key_ops");
  rec_key_ops.add("deriveKey");

  String payload_json;
  serializeJson(payload_doc, payload_json);
  String payload_b64 = base64_url_encode((uint8_t *)payload_json.c_str(), payload_json.length());

  // 2. Create the protected header
  DynamicJsonDocument protected_doc(128);
  protected_doc["alg"] = "ES256";
  protected_doc["cty"] = "jwk-set+json";

  String protected_json;
  serializeJson(protected_doc, protected_json);
  String protected_b64 = base64_url_encode((uint8_t *)protected_json.c_str(), protected_json.length());

  // 3. Create signing input and sign it
  String signing_input = protected_b64 + "." + payload_b64;
  uint8_t hash[32];
  mbedtls_sha256((uint8_t *)signing_input.c_str(), signing_input.length(), hash, 0);

  uint8_t signature[64];
  if (!sign_ecdsa_p256(hash, tang_sig_private_key, signature))
  {
    server_http.send(500, "text/plain", "Signing failed");
    return;
  }
  String signature_b64 = base64_url_encode(signature, 64);

  // 4. Build final JWS response
  DynamicJsonDocument jws_doc(1024);
  jws_doc["payload"] = payload_b64;
  jws_doc["protected"] = protected_b64;
  jws_doc["signature"] = signature_b64;

  String response;
  serializeJson(jws_doc, response);
  server_http.send(200, "application/json", response);
  DEBUG_PRINTLN("Served /adv");
}

void handleRec()
{
  // Support both /rec and /rec/{kid} paths
  String uri = server_http.uri();
  if (!uri.startsWith("/rec"))
  {
    server_http.send(404, "text/plain", "Not found");
    return;
  }

  if (!is_active)
  {
    server_http.send(403, "text/plain", "Server not active");
    return;
  }

  if (!server_http.hasArg("plain"))
  {
    server_http.send(400, "text/plain", "Bad Request: Missing body");
    return;
  }

  String body = server_http.arg("plain");
  DynamicJsonDocument reqDoc(512);
  DeserializationError error = deserializeJson(reqDoc, body);
  if (error)
  {
    server_http.send(400, "text/plain", "Bad Request: Invalid JSON");
    return;
  }

  // Extract client's ephemeral public key from the request
  const char *x_b64 = reqDoc["x"];
  const char *y_b64 = reqDoc["y"];

  if (!x_b64 || !y_b64)
  {
    server_http.send(400, "text/plain", "Bad Request: Missing x or y coordinates");
    return;
  }

  // Decode client's public key
  uint8_t client_pub_key[64];
  int x_len = base64_url_decode(String(x_b64), client_pub_key, 32);
  int y_len = base64_url_decode(String(y_b64), client_pub_key + 32, 32);

  if (x_len != 32 || y_len != 32)
  {
    server_http.send(400, "text/plain", "Bad Request: Invalid key coordinates");
    return;
  }

  // Perform ECDH to get the shared point (both X and Y coordinates)
  uint8_t shared_point[64];
  if (!compute_ecdh_shared_point(client_pub_key, tang_exc_private_key, shared_point))
  {
    server_http.send(500, "text/plain", "ECDH computation failed");
    return;
  }

  // Return the shared point as a JWK with ECMR algorithm and deriveKey operation
  DynamicJsonDocument respDoc(512);
  respDoc["alg"] = "ECMR";
  respDoc["kty"] = "EC";
  respDoc["crv"] = "P-256";
  respDoc["x"] = base64_url_encode(shared_point, 32);
  respDoc["y"] = base64_url_encode(shared_point + 32, 32);
  JsonArray key_ops = respDoc.createNestedArray("key_ops");
  key_ops.add("deriveKey");

  String response;
  serializeJson(respDoc, response);
  server_http.send(200, "application/jose+json", response);
  DEBUG_PRINTF("Served %s\n", uri.c_str());
}

// --- Administration Handlers ---

void handlePub()
{
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

void handleActivate()
{
  if (is_active)
  {
    server_http.send(400, "text/plain", "Already active");
    return;
  }
  if (!server_http.hasArg("plain"))
  {
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
  if (!compute_ecdh_shared_secret(eph_pub_key, admin_private_key, shared_secret))
  {
    server_http.send(500, "text/plain", "Activation ECDH failed");
    return;
  }

  // 2. Derive CEK using Concat KDF
  uint8_t cek[16];
  const char *enc_alg_id = "A128GCM";
  const char *protected_header_b64 = reqDoc["protected"];
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
  if (decoded_len < 0)
  {
    server_http.send(400, "text/plain", "Bad Request: Invalid ciphertext encoding");
    return;
  }

  if (!jwe_gcm_decrypt(password_buf, decoded_len, cek, sizeof(cek), iv_buf, sizeof(iv_buf), tag_buf, sizeof(tag_buf), (const uint8_t *)protected_header_b64, strlen(protected_header_b64)))
  {
    server_http.send(401, "text/plain", "JWE decryption failed: invalid message or tag");
    return;
  }

  // 4. Use decrypted password to decrypt the locally stored Tang keys
  char *password_str = (char *)password_buf;
  DEBUG_PRINTF("Decrypted activation password: %s\n", password_str);

  // Decrypt signing key
  uint8_t encrypted_tang_sig_key[32];
  uint8_t gcm_sig_tag[GCM_TAG_SIZE];
  for (int i = 0; i < 32; ++i)
    encrypted_tang_sig_key[i] = EEPROM.read(EEPROM_TANG_SIG_KEY_ADDR + i);
  for (int i = 0; i < GCM_TAG_SIZE; ++i)
    gcm_sig_tag[i] = EEPROM.read(EEPROM_TANG_SIG_TAG_ADDR + i);

  if (!crypt_local_data_gcm(encrypted_tang_sig_key, 32, password_str, false, gcm_sig_tag))
  {
    DEBUG_PRINTLN("GCM tag check failed for signing key! Invalid password.");
    server_http.send(401, "text/plain", "Activation failed: invalid password for stored key");
    return;
  }
  memcpy(tang_sig_private_key, encrypted_tang_sig_key, 32);
  compute_ec_public_key(tang_sig_private_key, tang_sig_public_key);

  // Decrypt exchange key
  uint8_t encrypted_tang_exc_key[32];
  uint8_t gcm_exc_tag[GCM_TAG_SIZE];
  for (int i = 0; i < 32; ++i)
    encrypted_tang_exc_key[i] = EEPROM.read(EEPROM_TANG_EXC_KEY_ADDR + i);
  for (int i = 0; i < GCM_TAG_SIZE; ++i)
    gcm_exc_tag[i] = EEPROM.read(EEPROM_TANG_EXC_TAG_ADDR + i);

  if (!crypt_local_data_gcm(encrypted_tang_exc_key, 32, password_str, false, gcm_exc_tag))
  {
    DEBUG_PRINTLN("GCM tag check failed for exchange key! Invalid password.");
    server_http.send(401, "text/plain", "Activation failed: invalid password for stored key");
    return;
  }
  memcpy(tang_exc_private_key, encrypted_tang_exc_key, 32);
  compute_ec_public_key(tang_exc_private_key, tang_exc_public_key);

  is_active = true;
  activation_timestamp = millis();
  DEBUG_PRINTLN("Server ACTIVATED.");
  server_http.send(200, "text/plain", "Server activated successfully");
}

void handleDeactivate()
{
  if (server_http.method() == HTTP_GET)
  {
    deactivate_server();
    server_http.send(200, "text/plain", "Server deactivated");
    return;
  }

  if (server_http.method() == HTTP_POST)
  {
    if (!is_active)
    {
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
    if (!compute_ecdh_shared_secret(eph_pub_key, admin_private_key, shared_secret))
    {
      server_http.send(500, "text/plain", "Deactivation ECDH failed");
      return;
    }

    uint8_t cek[16];
    const char *enc_alg_id = "A128GCM";
    const char *protected_header_b64 = reqDoc["protected"];
    concat_kdf(cek, sizeof(cek), shared_secret, sizeof(shared_secret), enc_alg_id, strlen(enc_alg_id));

    uint8_t iv_buf[12], tag_buf[16];
    base64_url_decode(reqDoc["iv"].as<String>(), iv_buf, sizeof(iv_buf));
    base64_url_decode(reqDoc["tag"].as<String>(), tag_buf, sizeof(tag_buf));

    uint8_t password_buf[65] = {0};
    int decoded_len = base64_url_decode(reqDoc["ciphertext"].as<String>(), password_buf, sizeof(password_buf));
    if (decoded_len < 0)
    {
      server_http.send(400, "text/plain", "Bad Request: Invalid ciphertext encoding");
      return;
    }

    if (!jwe_gcm_decrypt(password_buf, decoded_len, cek, sizeof(cek), iv_buf, sizeof(iv_buf), tag_buf, sizeof(tag_buf), (const uint8_t *)protected_header_b64, strlen(protected_header_b64)))
    {
      server_http.send(401, "text/plain", "JWE decryption failed for new password");
      return;
    }

    char *new_password_str = (char *)password_buf;
    DEBUG_PRINTF("Received new password for saving: %s\n", new_password_str);

    // Save signing key
    uint8_t sig_key_to_save[32];
    uint8_t new_sig_gcm_tag[GCM_TAG_SIZE];
    memcpy(sig_key_to_save, tang_sig_private_key, 32);
    crypt_local_data_gcm(sig_key_to_save, 32, new_password_str, true, new_sig_gcm_tag);

    for (int i = 0; i < 32; ++i)
      EEPROM.write(EEPROM_TANG_SIG_KEY_ADDR + i, sig_key_to_save[i]);
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
      EEPROM.write(EEPROM_TANG_SIG_TAG_ADDR + i, new_sig_gcm_tag[i]);

    // Save exchange key
    uint8_t exc_key_to_save[32];
    uint8_t new_exc_gcm_tag[GCM_TAG_SIZE];
    memcpy(exc_key_to_save, tang_exc_private_key, 32);
    crypt_local_data_gcm(exc_key_to_save, 32, new_password_str, true, new_exc_gcm_tag);

    for (int i = 0; i < 32; ++i)
      EEPROM.write(EEPROM_TANG_EXC_KEY_ADDR + i, exc_key_to_save[i]);
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
      EEPROM.write(EEPROM_TANG_EXC_TAG_ADDR + i, new_exc_gcm_tag[i]);

    EEPROM.commit();

    DEBUG_PRINTLN("New encrypted Tang keys saved to EEPROM.");
    deactivate_server();
    server_http.send(200, "text/plain", "Key saved and server deactivated");
  }
}

void handleReboot()
{
  server_http.send(200, "text/plain", "Rebooting...");
  delay(1000);
  ESP.restart();
}

void handleNotFound()
{
  server_http.send(404, "text/plain", "Not found");
}

#endif // HANDLERS_H
