#ifndef HELPERS_H
#define HELPERS_H

#include "bearssl.h"
#include "bearssl_hash.h"
#include "bearssl_aead.h"
#include "bearssl_rand.h"
#include "bearssl_ec.h"
#include "esp_system.h" // For esp_fill_random

// --- Helper Functions ---

/**
 * @brief Seeds a BearSSL PRNG context using the ESP32's hardware RNG.
 * This is crucial for providing a strong entropy source.
 * @param ctx Pointer to the PRNG class context.
 * @return 1 on success.
 */
int seeder_esp32(const br_prng_class **ctx)
{
	uint8_t seed[32];
	esp_fill_random(seed, sizeof(seed));
	(*ctx)->update(ctx, seed, sizeof(seed));
	return 1;
}

/**
 * @brief Prints a byte array as a hex string to the Serial console.
 */
void print_hex(const uint8_t* data, int len) {
#if defined(DEBUG_SERIAL) && DEBUG_SERIAL > 0
    for (int i = 0; i < len; ++i) {
        if (data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
    }
    Serial.println();
#endif
}

/**
 * @brief Base64URL encodes a byte array. This is a self-contained implementation.
 */
String base64_url_encode(const uint8_t* data, size_t len) {
    String encoded_string;
    encoded_string.reserve((len + 2) / 3 * 4); // Pre-allocate memory
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (size_t i = 0; i < len; i += 3) {
        uint32_t octet_a = i < len ? data[i] : 0;
        uint32_t octet_b = (i + 1) < len ? data[i + 1] : 0;
        uint32_t octet_c = (i + 2) < len ? data[i + 2] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_string += b64_table[(triple >> 18) & 0x3F];
        encoded_string += b64_table[(triple >> 12) & 0x3F];

        if (i + 1 < len) {
            encoded_string += b64_table[(triple >> 6) & 0x3F];
        }
        if (i + 2 < len) {
            encoded_string += b64_table[triple & 0x3F];
        }
    }

    // Replace standard Base64 characters with URL-safe ones
    encoded_string.replace('+', '-');
    encoded_string.replace('/', '_');

    // Remove padding, as it's not used in Base64URL
    // The loop above naturally omits padding characters.

    return encoded_string;
}


/**
 * @brief Decodes a Base64URL string into a byte array.
 * This is a self-contained implementation to avoid dependency issues.
 * @return Decoded length on success, -1 on failure.
 */
int base64_url_decode(String b64_url, uint8_t* output, int max_len) {
    String b64 = b64_url;
    b64.replace('-', '+');
    b64.replace('_', '/');
    while (b64.length() % 4) {
        b64 += "=";
    }

    int input_len = b64.length();
    int output_len = (input_len / 4) * 3;
    if (b64.endsWith("==")) {
        output_len -= 2;
    } else if (b64.endsWith("=")) {
        output_len -= 1;
    }

    if (output_len > max_len) {
        return -1;
    }

    int i = 0, j = 0;
    uint32_t accumulator = 0;
    int bits = 0;

    for (i = 0; i < input_len; i++) {
        char c = b64[i];
        if (c >= 'A' && c <= 'Z') {
            accumulator = (accumulator << 6) | (c - 'A');
        } else if (c >= 'a' && c <= 'z') {
            accumulator = (accumulator << 6) | (c - 'a' + 26);
        } else if (c >= '0' && c <= '9') {
            accumulator = (accumulator << 6) | (c - '0' + 52);
        } else if (c == '+') {
            accumulator = (accumulator << 6) | 62;
        } else if (c == '/') {
            accumulator = (accumulator << 6) | 63;
        } else if (c == '=') {
            break;
        } else {
            return -1; // Invalid character
        }

        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output[j++] = (accumulator >> bits) & 0xFF;
        }
    }

    return j;
}

/**
 * @brief Writes a 32-bit unsigned integer to a buffer in big-endian format.
 */
void write_be32(uint8_t* buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

/**
 * @brief Generates a new secp256r1 key pair using BearSSL.
 * @param pub_key Buffer for the public key (64 bytes, X || Y).
 * @param priv_key Buffer for the private key (32 bytes).
 * @return true on success, false on failure.
 */
bool generate_ec_keypair(uint8_t* pub_key, uint8_t* priv_key) {
    br_ec_private_key sk;
    br_ec_public_key pk;
    unsigned char tmp[BR_EC_KBUF_PUB_MAX_256 + BR_EC_KBUF_PRIV_MAX_256];

    br_hmac_drbg_context drbg_ctx;
    br_sha256_context hash_ctx;
    br_sha256_init(&hash_ctx);
    br_hmac_drbg_init(&drbg_ctx, &br_sha256_vtable, NULL, 0);
    seeder_esp32(&drbg_ctx.vtable);

    if (br_ec_keygen(&drbg_ctx.vtable, &br_ec_p256_m31, &sk, &pk, tmp) == 0) {
        DEBUG_PRINTLN("br_ec_keygen failed");
        return false;
    }

    memcpy(priv_key, sk.x, sk.xlen);

    if (pk.qlen == 65 && pk.q[0] == 0x04) {
        memcpy(pub_key, pk.q + 1, 64);
    } else {
        DEBUG_PRINTLN("Invalid public key format from br_ec_keygen");
        return false;
    }

    return true;
}

/**
 * @brief Computes a public key from a private key using BearSSL.
 * @param priv_key The private key (32 bytes).
 * @param pub_key Buffer for the public key (64 bytes, X || Y).
 * @return true on success, false on failure.
 */
bool compute_ec_public_key(const uint8_t* priv_key, uint8_t* pub_key) {
    br_ec_private_key sk;
    br_ec_public_key pk;
    unsigned char pk_buf[65];

    sk.curve = BR_EC_secp256r1;
    sk.x = (unsigned char*)priv_key;
    sk.xlen = 32;
    pk.q = pk_buf;
    pk.qlen = sizeof(pk_buf);

    if (br_ec_compute_pub(&br_ec_p256_m31, &pk, &sk) == 0) {
        DEBUG_PRINTLN("br_ec_compute_pub failed");
        return false;
    }

    if (pk.qlen == 65 && pk.q[0] == 0x04) {
        memcpy(pub_key, pk.q + 1, 64);
    } else {
        DEBUG_PRINTLN("Invalid public key format from br_ec_compute_pub");
        return false;
    }

    return true;
}

/**
 * @brief Computes an ECDH shared secret using BearSSL.
 * @param eph_pub_key The ephemeral public key from the client (64 bytes, X || Y).
 * @param priv_key The server's private key (32 bytes).
 * @param shared_secret Buffer for the resulting shared secret (32 bytes).
 * @return true on success, false on failure.
 */
bool compute_ecdh_shared_secret(const uint8_t* eph_pub_key, const uint8_t* priv_key, uint8_t* shared_secret) {
    br_ec_private_key sk;
    br_ec_public_key pk;
    unsigned char pk_buf[65];

    sk.curve = BR_EC_secp256r1;
    sk.x = (unsigned char*)priv_key;
    sk.xlen = 32;

    pk_buf[0] = 0x04;
    memcpy(pk_buf + 1, eph_pub_key, 64);
    pk.curve = BR_EC_secp256r1;
    pk.q = pk_buf;
    pk.qlen = sizeof(pk_buf);

    if (br_ec_compute_secret(&br_ec_p256_m31, shared_secret, &sk, &pk) == 0) {
        DEBUG_PRINTLN("br_ec_compute_secret failed");
        return false;
    }

    return true;
}


/**
 * @brief Implements the Concat KDF using the BearSSL C API.
 */
void concat_kdf(uint8_t* output_key, size_t output_key_len_bytes,
                const uint8_t* shared_secret, size_t shared_secret_len,
                const char* alg_id, size_t alg_id_len) {

    br_sha256_context sha_ctx;
    br_sha256_init(&sha_ctx);

    uint8_t round_counter[4];
    write_be32(round_counter, 1);

    br_sha256_update(&sha_ctx, round_counter, 4);
    br_sha256_update(&sha_ctx, shared_secret, shared_secret_len);

    uint8_t field_len_be[4];
    write_be32(field_len_be, alg_id_len);
    br_sha256_update(&sha_ctx, field_len_be, 4);
    br_sha256_update(&sha_ctx, (const uint8_t*)alg_id, alg_id_len);

    const uint8_t zeros[4] = {0, 0, 0, 0};
    br_sha256_update(&sha_ctx, zeros, 4);
    br_sha256_update(&sha_ctx, zeros, 4);

    write_be32(field_len_be, output_key_len_bytes * 8);
    br_sha256_update(&sha_ctx, field_len_be, 4);

    uint8_t digest[32];
    br_sha256_out(&sha_ctx, digest);

    memcpy(output_key, digest, output_key_len_bytes);
}

/**
 * @brief Decrypts data using AES-GCM with the BearSSL C API.
 */
bool jwe_gcm_decrypt(uint8_t* ciphertext_buf, size_t ciphertext_len,
                     const uint8_t* cek, size_t cek_len,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* tag, size_t tag_len,
                     const uint8_t* aad, size_t aad_len) {
    br_gcm_context gcm_ctx;
    br_gcm_init(&gcm_ctx, &br_aes_big_ct_gcm, cek, cek_len);
    br_gcm_reset(&gcm_ctx, iv, iv_len);
    br_gcm_aad_inject(&gcm_ctx, aad, aad_len);
    br_gcm_flip(&gcm_ctx);
    br_gcm_run(&gcm_ctx, 0, ciphertext_buf, ciphertext_len);

    uint8_t calculated_tag[16];
    br_gcm_get_tag(&gcm_ctx, calculated_tag);

    return (memcmp(calculated_tag, tag, tag_len) == 0);
}

/**
 * @brief Derives a key from a password using SHA-256 with the BearSSL C API.
 */
void derive_key_from_password(uint8_t* output_key, size_t key_len, const char* password) {
    br_sha256_context sha_ctx;
    br_sha256_init(&sha_ctx);
    br_sha256_update(&sha_ctx, (const uint8_t*)password, strlen(password));
    uint8_t hash[32];
    br_sha256_out(&sha_ctx, hash);
    memcpy(output_key, hash, key_len);
}

/**
 * @brief Encrypts or decrypts local data using AES-GCM with the BearSSL C API.
 */
bool crypt_local_data_gcm(uint8_t* data, size_t data_len, const char* pw, bool encrypt, uint8_t* tag_buffer) {
    byte key[16], iv[12];
    derive_key_from_password(key, sizeof(key), pw);
    memset(iv, 0, 12);

    br_gcm_context gcm_ctx;
    br_gcm_init(&gcm_ctx, &br_aes_big_ct_gcm, key, sizeof(key));
    br_gcm_reset(&gcm_ctx, iv, sizeof(iv));
    br_gcm_flip(&gcm_ctx);

    if (encrypt) {
        br_gcm_run(&gcm_ctx, 1, data, data_len);
        br_gcm_get_tag(&gcm_ctx, tag_buffer);
        return true;
    } else {
        br_gcm_run(&gcm_ctx, 0, data, data_len);
        uint8_t calculated_tag[GCM_TAG_SIZE];
        br_gcm_get_tag(&gcm_ctx, calculated_tag);
        return (memcmp(calculated_tag, tag_buffer, GCM_TAG_SIZE) == 0);
    }
}

/**
 * @brief Clears sensitive key material from memory and deactivates the server.
 */
void deactivate_server() {
    is_active = false;
    activation_timestamp = 0;
    memset(tang_private_key, 0, sizeof(tang_private_key));
    memset(tang_public_key, 0, sizeof(tang_public_key));
    DEBUG_PRINTLN("Server DEACTIVATED. Tang keys cleared from memory.");
}

#endif // HELPERS_H
