#ifndef CERT_HELPER_H
#define CERT_HELPER_H

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "mbedtls/base64.h"
#include "mbedtls/oid.h"
#include "esp_system.h"

// Debug macros (duplicated from TangServer.h to fix include order)
#ifndef DEBUG_PRINTLN
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif

// Forward declare the RNG functions from helpers.h
int init_rng();
void cleanup_rng();
int get_rng_context(int (**rng_func)(void *, unsigned char *, size_t), void **rng_ctx);

namespace CertHelper {

/**
 * @brief Encodes binary data to PEM format using mbedTLS
 * @param data Binary data to encode
 * @param data_len Length of binary data
 * @param header PEM header (e.g., "CERTIFICATE", "RSA PRIVATE KEY")
 * @param buffer Output buffer for PEM data
 * @param buffer_len Size of output buffer
 * @return true on success, false on failure
 */
bool encode_to_pem(const unsigned char *data, size_t data_len, const char *header, char* buffer, size_t buffer_len) {
    // Calculate required buffer size for base64 encoding
    size_t base64_len = 0;
    int ret = mbedtls_base64_encode(NULL, 0, &base64_len, data, data_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        DEBUG_PRINTF("Failed to calculate base64 length: -0x%04x\n", -ret);
        return false;
    }

    // Allocate temporary buffer for base64 data
    unsigned char *base64_buf = (unsigned char *)malloc(base64_len);
    if (!base64_buf) {
        DEBUG_PRINTLN("Failed to allocate base64 buffer");
        return false;
    }

    // Encode to base64
    ret = mbedtls_base64_encode(base64_buf, base64_len, &base64_len, data, data_len);
    if (ret != 0) {
        DEBUG_PRINTF("Base64 encoding failed: -0x%04x\n", -ret);
        free(base64_buf);
        return false;
    }

    // Build PEM format
    int pem_len = snprintf(buffer, buffer_len, "-----BEGIN %s-----\n", header);
    if (pem_len < 0 || pem_len >= (int)buffer_len) {
        free(base64_buf);
        return false;
    }

    // Add base64 data in 64-character lines
    size_t remaining = buffer_len - pem_len;
    size_t pos = 0;
    while (pos < base64_len && remaining > 65) { // Need space for line + newline
        size_t line_len = (base64_len - pos > 64) ? 64 : (base64_len - pos);
        int written = snprintf(buffer + pem_len, remaining, "%.*s\n", (int)line_len, base64_buf + pos);
        if (written < 0) {
            free(base64_buf);
            return false;
        }
        pem_len += written;
        remaining -= written;
        pos += line_len;
    }

    // Add footer
    int footer_len = snprintf(buffer + pem_len, remaining, "-----END %s-----\n", header);
    if (footer_len < 0 || footer_len >= (int)remaining) {
        free(base64_buf);
        return false;
    }

    free(base64_buf);
    return true;
}

} // namespace CertHelper

#endif // CERT_HELPER_H
