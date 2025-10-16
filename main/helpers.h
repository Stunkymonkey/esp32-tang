#ifndef HELPERS_H
#define HELPERS_H

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "esp_system.h" // For esp_fill_random

// Debug macros (duplicated from TangServer.h to fix include order)
#ifndef DEBUG_PRINTLN
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif

// --- Constants ---
extern const int GCM_TAG_SIZE;

// --- Helper Functions ---

// Global entropy and DRBG contexts for reuse (extern for access from other modules)
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
static bool rng_initialized = false;

/**
 * @brief Initialize the random number generator using ESP32's hardware RNG.
 * This is crucial for providing a strong entropy source.
 * @return 0 on success, negative on failure.
 */
int init_rng() {
    if (rng_initialized) {
        return 0;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "esp32_tang_server";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
        return ret;
    }

    rng_initialized = true;
    return 0;
}

/**
 * @brief Cleanup RNG resources
 */
void cleanup_rng() {
    if (rng_initialized) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        rng_initialized = false;
    }
}

/**
 * @brief Get the random number generator function and context
 * @param rng_func Pointer to store the RNG function
 * @param rng_ctx Pointer to store the RNG context
 * @return 0 on success, negative on failure
 */
int get_rng_context(int (**rng_func)(void *, unsigned char *, size_t), void **rng_ctx) {
    if (init_rng() != 0) {
        return -1;
    }
    *rng_func = mbedtls_ctr_drbg_random;
    *rng_ctx = &ctr_drbg;
    return 0;
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
 * @brief Generates a new secp256r1 key pair using mbedTLS.
 * @param pub_key Buffer for the public key (64 bytes, X || Y).
 * @param priv_key Buffer for the private key (32 bytes).
 * @return true on success, false on failure.
 */
bool generate_ec_keypair(uint8_t* pub_key, uint8_t* priv_key) {
    if (init_rng() != 0) {
        DEBUG_PRINTLN("RNG initialization failed");
        return false;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = 0;

    // Load the secp256r1 curve
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Generate the key pair
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ecp_gen_keypair failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Export private key (32 bytes)
    ret = mbedtls_mpi_write_binary(&d, priv_key, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to export private key: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Export public key (64 bytes: 32 for X, 32 for Y)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to export public key X: -0x%04x\n", -ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), pub_key + 32, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to export public key Y: -0x%04x\n", -ret);
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
}

/**
 * @brief Computes a public key from a private key using mbedTLS.
 * @param priv_key The private key (32 bytes).
 * @param pub_key Buffer for the public key (64 bytes, X || Y).
 * @return true on success, false on failure.
 */
bool compute_ec_public_key(const uint8_t* priv_key, uint8_t* pub_key) {
    if (init_rng() != 0) {
        DEBUG_PRINTLN("RNG initialization failed");
        return false;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = 0;

    // Load the secp256r1 curve
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Load private key
    ret = mbedtls_mpi_read_binary(&d, priv_key, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to load private key: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Compute public key Q = d * G
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ecp_mul failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Export public key (64 bytes: 32 for X, 32 for Y)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to export public key X: -0x%04x\n", -ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), pub_key + 32, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to export public key Y: -0x%04x\n", -ret);
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
}

/**
 * @brief Computes an ECDH shared secret using mbedTLS.
 * @param eph_pub_key The ephemeral public key from the client (64 bytes, X || Y).
 * @param priv_key The server's private key (32 bytes).
 * @param shared_secret Buffer for the resulting shared secret (32 bytes).
 * @return true on success, false on failure.
 */
bool compute_ecdh_shared_secret(const uint8_t* eph_pub_key, const uint8_t* priv_key, uint8_t* shared_secret) {
    if (init_rng() != 0) {
        DEBUG_PRINTLN("RNG initialization failed");
        return false;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, z;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);

    int ret = 0;

    // Load the secp256r1 curve
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Load private key
    ret = mbedtls_mpi_read_binary(&d, priv_key, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to load private key: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Load ephemeral public key
    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), eph_pub_key, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to load ephemeral public key X: -0x%04x\n", -ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), eph_pub_key + 32, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to load ephemeral public key Y: -0x%04x\n", -ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to set Q.Z: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Verify the point is valid
    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    if (ret != 0) {
        DEBUG_PRINTF("Invalid ephemeral public key: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Compute shared secret: z = d * Q
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ecp_mul failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    // Export the X coordinate as the shared secret
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), shared_secret, 32);
    if (ret != 0) {
        DEBUG_PRINTF("Failed to export shared secret: -0x%04x\n", -ret);
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);

    return (ret == 0);
}


/**
 * @brief Implements the Concat KDF using the mbedTLS C API.
 */
void concat_kdf(uint8_t* output_key, size_t output_key_len_bytes,
                const uint8_t* shared_secret, size_t shared_secret_len,
                const char* alg_id, size_t alg_id_len) {

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); // 0 for SHA-256 (not SHA-224)

    uint8_t round_counter[4];
    write_be32(round_counter, 1);

    mbedtls_sha256_update(&sha_ctx, round_counter, 4);
    mbedtls_sha256_update(&sha_ctx, shared_secret, shared_secret_len);

    uint8_t field_len_be[4];
    write_be32(field_len_be, alg_id_len);
    mbedtls_sha256_update(&sha_ctx, field_len_be, 4);
    mbedtls_sha256_update(&sha_ctx, (const uint8_t*)alg_id, alg_id_len);

    const uint8_t zeros[4] = {0, 0, 0, 0};
    mbedtls_sha256_update(&sha_ctx, zeros, 4);
    mbedtls_sha256_update(&sha_ctx, zeros, 4);

    write_be32(field_len_be, output_key_len_bytes * 8);
    mbedtls_sha256_update(&sha_ctx, field_len_be, 4);

    uint8_t digest[32];
    mbedtls_sha256_finish(&sha_ctx, digest);
    mbedtls_sha256_free(&sha_ctx);

    memcpy(output_key, digest, output_key_len_bytes);
}

/**
 * @brief Decrypts data using AES-GCM with the mbedTLS C API.
 */
bool jwe_gcm_decrypt(uint8_t* ciphertext_buf, size_t ciphertext_len,
                     const uint8_t* cek, size_t cek_len,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* tag, size_t tag_len,
                     const uint8_t* aad, size_t aad_len) {
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);

    int ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, cek, cek_len * 8);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_gcm_setkey failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, ciphertext_len, iv, iv_len,
                                   aad, aad_len, tag, tag_len,
                                   ciphertext_buf, ciphertext_buf);

    mbedtls_gcm_free(&gcm_ctx);

    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_gcm_auth_decrypt failed: -0x%04x\n", -ret);
        return false;
    }

    return true;
}

/**
 * @brief Derives a key from a password using SHA-256 with the mbedTLS C API.
 */
void derive_key_from_password(uint8_t* output_key, size_t key_len, const char* password) {
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&sha_ctx, (const uint8_t*)password, strlen(password));

    uint8_t hash[32];
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    memcpy(output_key, hash, key_len);
}

/**
 * @brief Encrypts or decrypts local data using AES-GCM with the mbedTLS C API.
 */
bool crypt_local_data_gcm(uint8_t* data, size_t data_len, const char* pw, bool encrypt, uint8_t* tag_buffer) {
    byte key[16], iv[12];
    derive_key_from_password(key, sizeof(key), pw);
    memset(iv, 0, 12);

    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);

    int ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, sizeof(key) * 8);
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_gcm_setkey failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }

    if (encrypt) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, data_len,
                                        iv, sizeof(iv), NULL, 0,
                                        data, data, GCM_TAG_SIZE, tag_buffer);
    } else {
        ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, data_len, iv, sizeof(iv),
                                       NULL, 0, tag_buffer, GCM_TAG_SIZE,
                                       data, data);
    }

    mbedtls_gcm_free(&gcm_ctx);

    if (ret != 0) {
        DEBUG_PRINTF("GCM operation failed: -0x%04x\n", -ret);
        return false;
    }

    return true;
}

// deactivate_server() function moved to TangServer.h to avoid dependency issues

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
