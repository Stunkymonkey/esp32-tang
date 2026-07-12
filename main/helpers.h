#ifndef HELPERS_H
#define HELPERS_H

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/base64.h>
#include <esp_system.h> // For esp_fill_random

// Debug macros (duplicated from TangServer.h to fix include order)
#ifndef DEBUG_PRINTLN
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif

// --- Constants ---
// None currently needed globally

// --- Helper Functions ---

// Global entropy and DRBG contexts for reuse (extern for access from other modules)
mbedtls_entropy_context* entropy = nullptr;
mbedtls_ctr_drbg_context* ctr_drbg = nullptr;
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
    
    entropy = new mbedtls_entropy_context;
    ctr_drbg = new mbedtls_ctr_drbg_context;

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    const char *pers = "esp32_tang_server";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
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
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_entropy_free(entropy);
        delete ctr_drbg;
        delete entropy;
        ctr_drbg = nullptr;
        entropy = nullptr;
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
    *rng_ctx = ctr_drbg;
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
    // Step 1: Calculate required buffer size
    size_t output_len = 0;
    mbedtls_base64_encode(nullptr, 0, &output_len, data, len);

    // Step 2: Allocate buffer and perform encoding
    uint8_t* buffer = new uint8_t[output_len + 1]; // +1 for null terminator
    if (mbedtls_base64_encode(buffer, output_len, &output_len, data, len) != 0) {
        delete[] buffer;
        return String(); // Return empty string on failure
    }
    buffer[output_len] = '\0'; // Null-terminate

    // Step 3: Convert to String
    String encoded = String((char*)buffer);
    delete[] buffer;

    // Step 4: Replace standard Base64 characters with URL-safe ones
    encoded.replace('+', '-');
    encoded.replace('/', '_');

    // Step 5: Remove padding
    int padIndex = encoded.indexOf('=');
    if (padIndex != -1) {
        encoded.remove(padIndex);
    }

    return encoded;
}


/**
 * @brief Decodes a Base64URL string into a byte array.
 * This is a self-contained implementation to avoid dependency issues.
 * @return Decoded length on success, -1 on failure.
 */

 int base64_url_decode(String b64_url, uint8_t* output, int max_len) {
     // Step 1: Convert Base64URL to standard Base64
     String b64 = b64_url;
     b64.replace('-', '+');
     b64.replace('_', '/');
     while (b64.length() % 4) {
         b64 += "=";
     }

     // Step 2: Decode using mbedTLS
     size_t decoded_len = 0;
     int ret = mbedtls_base64_decode(output, max_len, &decoded_len,
                                     (const uint8_t*)b64.c_str(), b64.length());

     if (ret != 0) {
         return -1; // Decoding failed
     }

     return decoded_len;
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
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, ctr_drbg);
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
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, ctr_drbg);
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
 * @param eph_pub_key The ephemeral public key from the client (X || Y).
 * @param priv_key The server's private key.
 * @param curve_id The curve ID (P-256 or P-521).
 * @param key_len The length of the coordinate/private key (32 or 66).
 * @param result_pub_key Buffer for the resulting shared secret (X || Y).
 * @return true on success, false on failure.
 */
bool compute_ecdh_shared_secret(const uint8_t* eph_pub_key, const uint8_t* priv_key, 
                                mbedtls_ecp_group_id curve_id, size_t key_len, 
                                uint8_t* result_pub_key) {
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

    // Load the specified curve
    ret = mbedtls_ecp_group_load(&grp, curve_id);
    
    // Load private key
    if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv_key, key_len);

    // Load ephemeral public key
    if (ret == 0) ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), eph_pub_key, key_len);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), eph_pub_key + key_len, key_len);
    if (ret == 0) ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);

    // Verify the point is valid
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(&grp, &Q);

    // Compute shared secret: result_Q = d * Q
    if (ret == 0) ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, mbedtls_ctr_drbg_random, ctr_drbg);

    // Export both X and Y using standard function to ensure affine coordinates (handles Z normalization)
    // 1 byte header (0x04) + key_len (X) + key_len (Y)
    size_t out_len = 0;
    uint8_t buffer[133]; // Max size: 1 + 66 + 66 = 133 for P-521
    
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &out_len, buffer, sizeof(buffer));
    }

    if (ret == 0) {
        // Validation: Verify output length matches expected 1 + 2*key_len
        if (out_len != 1 + 2 * key_len) {
            DEBUG_PRINTF("EC point write length mismatch: %d vs expected %d\n", out_len, 1 + 2 * key_len);
            ret = -1;
        } else {
            // Copy X and Y, skipping the 0x04 header
            memcpy(result_pub_key, buffer + 1, key_len);            // Copy X
            memcpy(result_pub_key + key_len, buffer + 1 + key_len, key_len); // Copy Y
        }
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    if (ret != 0) {
         DEBUG_PRINTF("compute_ecdh_shared_secret failed: -0x%04x\n", -ret);
         return false;
    }
    return true;
}

/**
 * @brief Signs data using ECDSA.
 * @param priv_key Private key.
 * @param curve_id The curve ID (P-256 or P-521).
 * @param key_len The length of the private key (32 or 66).
 * @param hash The hash of the data to sign.
 * @param hash_len Length of the hash (32 or 64).
 * @param signature Output buffer for the signature (2 * key_len: R || S).
 * @return true on success, false on failure.
 */
bool sign_data(const uint8_t* priv_key, mbedtls_ecp_group_id curve_id, size_t key_len, 
               const uint8_t* hash, size_t hash_len, uint8_t* signature) {
    if (init_rng() != 0) return false;

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, curve_id);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv_key, key_len);
    
    // Sign the hash
    if (ret == 0) {
        ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hash_len, mbedtls_ctr_drbg_random, ctr_drbg);
    }

    if (ret == 0) {
        // Export R and S (key_len bytes each)
        ret = mbedtls_mpi_write_binary(&r, signature, key_len);
        if (ret == 0) ret = mbedtls_mpi_write_binary(&s, signature + key_len, key_len);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (ret != 0) {
        DEBUG_PRINTF("sign_data failed: -0x%04x\n", -ret);
        return false;
    }
    return true;
}

// deactivate_server is in TangServer.h for global access


#endif // HELPERS_H
