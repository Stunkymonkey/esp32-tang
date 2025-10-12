#ifndef CERT_HELPER_H
#define CERT_HELPER_H

#include "bearssl.h"
#include "bearssl_x509.h"
#include "bearssl_rsa.h"
#include "bearssl_pem.h"

// Forward declare the seeder from helpers.h
int seeder_esp32(const br_prng_class **ctx);

namespace CertHelper {

// Helper to encode data to PEM format
void encode_to_pem(const unsigned char *data, size_t len, const char *name, char* buffer, size_t buffer_len) {
    br_pem_encoder_context pem_ctx;
    br_pem_encoder_init(&pem_ctx);
    br_pem_encoder_begin_object(&pem_ctx, name);
    br_pem_encoder_write(&pem_ctx, data, len);
    br_pem_encoder_end_object(&pem_ctx);

    size_t out_len = br_pem_encoder_get_len(&pem_ctx);
    if (out_len < buffer_len) {
        memcpy(buffer, br_pem_encoder_get_blob(&pem_ctx), out_len);
        buffer[out_len] = '\0';
    }
}

/**
 * @brief Generates a new self-signed X.509 certificate and private key using BearSSL C API.
 * @return true on success, false on failure.
 */
bool generate_cert(const char* commonName, int days_valid,
                   char* key_buffer, size_t key_buffer_len,
                   char* cert_buffer, size_t cert_buffer_len) {

    DEBUG_PRINTLN("Generating 2048-bit RSA key with BearSSL C API...");

    // 1. Initialize a DRBG context and seed it with the ESP32 hardware RNG
    br_hmac_drbg_context drbg_ctx;
    br_sha256_context hash_ctx;
    br_sha256_init(&hash_ctx);

    // Use the hardware seeder to provide a high-quality random seed
    uint8_t seed[48];
    esp_fill_random(seed, sizeof(seed));
    br_hmac_drbg_init(&drbg_ctx, &br_sha256_vtable, seed, sizeof(seed));

    // 2. Generate RSA private key using the seeded DRBG
    br_rsa_private_key pk;
    // Allocate space for the private key components on the stack
    unsigned char sk_buf[BR_RSA_KBUF_PRIV_2048];
    pk.p = sk_buf;
    pk.q = sk_buf + 256;
    pk.dp = sk_buf + 512;
    pk.dq = sk_buf + 768;
    pk.iq = sk_buf + 1024;

    if (br_rsa_i31_keygen(&drbg_ctx.vtable, &pk, sk_buf, 2048, 65537) == 0) {
        DEBUG_PRINTLN("RSA key generation failed!");
        return false;
    }

    // 3. Create self-signed certificate
    br_x509_minimal_context xc;
    br_sha256_context x509_hash_ctx;
    br_sha256_init(&x509_hash_ctx);

    long current_time = 1577836800; // Mock time (Jan 1, 2020) for reproducibility
    br_x509_minimal_init_full(&xc, &br_sha256_vtable, (br_hash_compat_context *)&x509_hash_ctx);

    br_x509_minimal_set_validity(&xc, current_time, current_time + (days_valid * 86400L));
    br_x509_minimal_set_subject_name(&xc, "CN=", commonName);
    br_x509_minimal_set_issuer_key(&xc, &pk.vtable);

    unsigned char cert_data_buf[1500];
    size_t cert_len = br_x509_minimal_end(&xc, cert_data_buf, &pk.vtable);
    if (cert_len == 0) {
        DEBUG_PRINTLN("Certificate signing failed!");
        return false;
    }

    // 4. Encode private key and certificate to PEM format
    unsigned char pk_der[BR_RSA_DER_LEN_2048];
    size_t pk_len = br_rsa_i31_der_encode_private_key(pk_der, &pk);

    encode_to_pem(pk_der, pk_len, "RSA PRIVATE KEY", key_buffer, key_buffer_len);
    encode_to_pem(cert_data_buf, cert_len, "CERTIFICATE", cert_buffer, cert_buffer_len);

    DEBUG_PRINTLN("Certificate and key generated successfully with BearSSL C API.");
    return true;
}

} // namespace CertHelper

#endif // CERT_HELPER_H
