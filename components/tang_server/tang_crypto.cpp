#include "tang_crypto.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <esp_heap_caps.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "esphome/core/log.h"

namespace esphome::tang_server {

static const char *const TAG = "tang_server.crypto";

const char *const TANG_THP_ALGS[TANG_THP_ALG_COUNT] = {"S1", "S224", "S256", "S384", "S512"};

// --- Secrets in RAM ---

TangKey::~TangKey() { mbedtls_platform_zeroize(this->private_key, sizeof(this->private_key)); }

const char *TangKey::crv() const { return this->curve_id == MBEDTLS_ECP_DP_SECP521R1 ? "P-521" : "P-256"; }

const std::string &TangKey::thp_by_alg(const char *alg) const {
  for (size_t i = 0; i < TANG_THP_ALG_COUNT; i++) {
    if (strcmp(TANG_THP_ALGS[i], alg) == 0)
      return this->thp[i];
  }
  static const std::string EMPTY;
  return EMPTY;
}

void wipe(std::string &s) {
  // capacity() excludes the terminator, which is part of the buffer too.
  mbedtls_platform_zeroize(s.data(), s.capacity() + 1);
  s.clear();
}

void wipe(std::vector<uint8_t> &v) {
  mbedtls_platform_zeroize(v.data(), v.capacity());
  v.clear();
}

void *WipingAllocator::allocate(size_t size) { return malloc(size); }

void WipingAllocator::deallocate(void *ptr) {
  if (ptr == nullptr)
    return;
  // ArduinoJson passes no size; the heap knows the block's.
  mbedtls_platform_zeroize(ptr, heap_caps_get_allocated_size(ptr));
  free(ptr);
}

void *WipingAllocator::reallocate(void *ptr, size_t new_size) {
  // realloc() may move the block and leave the old copy behind unwiped, so
  // move it by hand. On failure the old block stays valid, as with realloc().
  void *moved = malloc(new_size);
  if (moved == nullptr)
    return nullptr;
  if (ptr != nullptr) {
    memcpy(moved, ptr, std::min(heap_caps_get_allocated_size(ptr), new_size));
    this->deallocate(ptr);
  }
  return moved;
}

WipingAllocator *WipingAllocator::instance() {
  static WipingAllocator allocator;
  return &allocator;
}

// --- RNG ---

namespace {
mbedtls_entropy_context entropy;      // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
mbedtls_ctr_drbg_context ctr_drbg;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
bool rng_initialized = false;         // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
}  // namespace

int init_rng() {
  if (rng_initialized)
    return 0;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char *pers = "esp32_tang_server";
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,
                                  strlen(pers));
  if (ret != 0) {
    ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
    // Release what the init calls set up, so a retry starts clean.
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
  }

  rng_initialized = true;
  return 0;
}

// --- Base64URL ---

std::string base64_url_encode(const uint8_t *data, size_t len) {
  size_t output_len = 0;
  mbedtls_base64_encode(nullptr, 0, &output_len, data, len);

  // output_len includes the terminator mbedTLS writes.
  std::string encoded(output_len, '\0');
  if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(encoded.data()), encoded.size(), &output_len, data,
                            len) != 0)
    return {};
  encoded.resize(output_len);

  // Standard Base64 to URL-safe, without padding.
  std::replace(encoded.begin(), encoded.end(), '+', '-');
  std::replace(encoded.begin(), encoded.end(), '/', '_');
  encoded.erase(std::find(encoded.begin(), encoded.end(), '='), encoded.end());
  return encoded;
}

int base64_url_decode(const char *input, size_t input_len, uint8_t *output, size_t max_len) {
  // The input may be a private key. Size the working copy up front so the
  // padding never reallocates it, and wipe it on return.
  std::string b64;
  b64.reserve(input_len + 3);
  ScopedWipe<std::string> wipe_b64{b64};

  b64.assign(input, input_len);
  std::replace(b64.begin(), b64.end(), '-', '+');
  std::replace(b64.begin(), b64.end(), '_', '/');
  while (b64.size() % 4)
    b64 += '=';

  size_t decoded_len = 0;
  if (mbedtls_base64_decode(output, max_len, &decoded_len, reinterpret_cast<const unsigned char *>(b64.data()),
                            b64.size()) != 0)
    return -1;
  return static_cast<int>(decoded_len);
}

// --- Thumbprints ---

namespace {

/// The canonical JWK of an EC public key as defined by RFC 7638: required
/// members only, lexicographically ordered, no whitespace. This exact string
/// is what clients hash to derive the key ID.
std::string jwk_canonical_ec(const char *crv, const std::string &x, const std::string &y) {
  return std::string(R"({"crv":")") + crv + R"(","kty":"EC","x":")" + x + R"(","y":")" + y + R"("})";
}

/// The Base64URL thumbprint of a canonical JWK, or an empty string if the
/// algorithm is unknown.
std::string jwk_thumbprint(const std::string &jwk_json, const char *alg) {
  const auto *input = reinterpret_cast<const uint8_t *>(jwk_json.data());
  size_t input_len = jwk_json.size();
  uint8_t digest[64];
  size_t digest_len;

  if (strcmp(alg, "S1") == 0) {
    if (mbedtls_sha1(input, input_len, digest) != 0)
      return {};
    digest_len = 20;
  } else if (strcmp(alg, "S224") == 0) {
    if (mbedtls_sha256(input, input_len, digest, 1) != 0)
      return {};
    digest_len = 28;
  } else if (strcmp(alg, "S256") == 0) {
    if (mbedtls_sha256(input, input_len, digest, 0) != 0)
      return {};
    digest_len = 32;
  } else if (strcmp(alg, "S384") == 0) {
    if (mbedtls_sha512(input, input_len, digest, 1) != 0)
      return {};
    digest_len = 48;
  } else if (strcmp(alg, "S512") == 0) {
    if (mbedtls_sha512(input, input_len, digest, 0) != 0)
      return {};
    digest_len = 64;
  } else {
    return {};
  }

  return base64_url_encode(digest, digest_len);
}

/// clevis derives the ID from the advertised JWK (RFC 7638 thumbprint) and
/// never uses a "kid" member, so the thumbprints are authoritative. The kid
/// supplied at provisioning time is still accepted for clients that use it.
bool key_matches_id(const TangKey &key, const std::string &id) {
  if (!key.kid.empty() && key.kid == id)
    return true;
  return std::find(key.thp.begin(), key.thp.end(), id) != key.thp.end();
}

// --- EC operations ---

/// Checks that a private key belongs to a public key: pub_key (X || Y) must
/// be a valid point equal to priv_key * G.
bool ec_keypair_matches(const uint8_t *priv_key, const uint8_t *pub_key, mbedtls_ecp_group_id curve_id,
                        size_t key_len) {
  if (init_rng() != 0)
    return false;

  mbedtls_ecp_keypair pub, prv;
  mbedtls_ecp_keypair_init(&pub);
  mbedtls_ecp_keypair_init(&prv);

  // Uncompressed point encoding: 0x04 || X || Y
  uint8_t point[133];
  point[0] = 0x04;
  memcpy(point + 1, pub_key, 2 * key_len);

  int ret = mbedtls_ecp_read_key(curve_id, &prv, priv_key, key_len);
  if (ret == 0)
    ret = mbedtls_ecp_group_load(&pub.MBEDTLS_PRIVATE(grp), curve_id);
  if (ret == 0) {
    ret = mbedtls_ecp_point_read_binary(&pub.MBEDTLS_PRIVATE(grp), &pub.MBEDTLS_PRIVATE(Q), point, 1 + 2 * key_len);
  }
  if (ret == 0)
    ret = mbedtls_ecp_check_pubkey(&pub.MBEDTLS_PRIVATE(grp), &pub.MBEDTLS_PRIVATE(Q));
  // check_pub_priv() compares pub.Q with prv.Q and then prv.Q with d * G,
  // but read_key() only sets d. Give prv the claimed public point.
  if (ret == 0)
    ret = mbedtls_ecp_copy(&prv.MBEDTLS_PRIVATE(Q), &pub.MBEDTLS_PRIVATE(Q));
  if (ret == 0)
    ret = mbedtls_ecp_check_pub_priv(&pub, &prv, mbedtls_ctr_drbg_random, &ctr_drbg);

  // Frees and wipes the copy of the private key.
  mbedtls_ecp_keypair_free(&pub);
  mbedtls_ecp_keypair_free(&prv);

  if (ret != 0) {
    ESP_LOGD(TAG, "ec_keypair_matches failed: -0x%04x", -ret);
    return false;
  }
  return true;
}

/// ECDSA signature (R || S, key_len bytes each) over a hash.
bool sign_data(const uint8_t *priv_key, mbedtls_ecp_group_id curve_id, size_t key_len, const uint8_t *hash,
               size_t hash_len, uint8_t *signature) {
  if (init_rng() != 0)
    return false;

  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  int ret = mbedtls_ecp_group_load(&grp, curve_id);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&d, priv_key, key_len);
  if (ret == 0)
    ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hash_len, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&r, signature, key_len);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&s, signature + key_len, key_len);

  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  if (ret != 0) {
    ESP_LOGE(TAG, "sign_data failed: -0x%04x", -ret);
    return false;
  }
  return true;
}

/// ECMR: multiplies the client's point (X || Y) by the server's private key.
/// @return 0 on success, or an mbedTLS error; MBEDTLS_ERR_ECP_INVALID_KEY
/// means the client sent a point that is not on the curve.
int compute_ecdh_shared_secret(const uint8_t *eph_pub_key, const uint8_t *priv_key, mbedtls_ecp_group_id curve_id,
                               size_t key_len, uint8_t *result_pub_key) {
  int ret = init_rng();
  if (ret != 0)
    return ret;

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  ret = mbedtls_ecp_group_load(&grp, curve_id);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&d, priv_key, key_len);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), eph_pub_key, key_len);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), eph_pub_key + key_len, key_len);
  if (ret == 0)
    ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
  if (ret == 0)
    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
  if (ret == 0)
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);

  // Uncompressed export normalizes Z: 0x04 || X || Y
  size_t out_len = 0;
  uint8_t buffer[133];  // 1 + 66 + 66 for P-521
  if (ret == 0)
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &out_len, buffer, sizeof(buffer));
  if (ret == 0) {
    if (out_len != 1 + 2 * key_len) {
      ESP_LOGE(TAG, "EC point write length mismatch: %zu vs expected %zu", out_len, 1 + 2 * key_len);
      ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    } else {
      memcpy(result_pub_key, buffer + 1, 2 * key_len);
    }
  }

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);

  if (ret != 0)
    ESP_LOGD(TAG, "compute_ecdh_shared_secret failed: -0x%04x", -ret);
  return ret;
}

// --- JWK parsing ---

bool parse_usage(JsonObjectConst k, KeyUsage &usage) {
  // 1. Standard 'key_ops'
  for (JsonVariantConst v : k["key_ops"].as<JsonArrayConst>()) {
    const char *op = v | "";
    if (strcmp(op, "sign") == 0 || strcmp(op, "verify") == 0) {
      usage = KeyUsage::SIGN;
      return true;
    }
    if (strcmp(op, "deriveKey") == 0) {
      usage = KeyUsage::EXCHANGE;
      return true;
    }
  }

  // 2. Fallback to 'alg'
  const char *alg = k["alg"] | "";
  if (strncmp(alg, "ES", 2) == 0) {
    usage = KeyUsage::SIGN;
    return true;
  }
  if (strcmp(alg, "ECMR") == 0) {
    usage = KeyUsage::EXCHANGE;
    return true;
  }
  return false;
}

/// Decodes a Base64URL member into exactly `len` bytes.
bool decode_member(JsonObjectConst k, const char *name, uint8_t *out, size_t len) {
  JsonVariantConst v = k[name];
  if (!v.is<const char *>())
    return false;
  const char *s = v.as<const char *>();
  return base64_url_decode(s, strlen(s), out, len) == static_cast<int>(len);
}

/// @return nullptr on success, or what is wrong with the key.
const char *parse_key(JsonObjectConst k, TangKey &key) {
  if (k.isNull())
    return "not an object";
  if (strcmp(k["kty"] | "", "EC") != 0)
    return "kty is not EC";
  if (!parse_usage(k, key.usage))
    return "no usage in key_ops or alg";

  const char *crv = k["crv"] | "";
  if (strcmp(crv, "P-521") == 0) {
    key.curve_id = MBEDTLS_ECP_DP_SECP521R1;
    key.key_len = 66;
  } else if (strcmp(crv, "P-256") == 0) {
    key.curve_id = MBEDTLS_ECP_DP_SECP256R1;
    key.key_len = 32;
  } else {
    return "crv is not P-256 or P-521";
  }

  if (!decode_member(k, "d", key.private_key, key.key_len) || !decode_member(k, "x", key.public_key, key.key_len) ||
      !decode_member(k, "y", key.public_key + key.key_len, key.key_len))
    return "d, x or y is missing or has the wrong length";

  // A mismatched pair would advertise one key and sign or exchange with
  // another, which clients can only detect as a broken server.
  if (!ec_keypair_matches(key.private_key, key.public_key, key.curve_id, key.key_len))
    return "d does not match x/y";

  // Optional: tang's own .jwk files carry no "kid".
  if (k["kid"].is<const char *>())
    key.kid = k["kid"].as<const char *>();

  // Derive the canonical JWK from the re-encoded coordinates, so the
  // thumbprint always matches the key exactly as /adv publishes it.
  std::string canonical = jwk_canonical_ec(crv, base64_url_encode(key.public_key, key.key_len),
                                           base64_url_encode(key.public_key + key.key_len, key.key_len));
  for (size_t i = 0; i < TANG_THP_ALG_COUNT; i++)
    key.thp[i] = jwk_thumbprint(canonical, TANG_THP_ALGS[i]);
  return nullptr;
}

void hash_for_curve(mbedtls_ecp_group_id curve_id, const std::string &input, uint8_t *hash, size_t &hash_len) {
  const auto *data = reinterpret_cast<const uint8_t *>(input.data());
  // SHA-512 for ES512 (P-521), SHA-256 for ES256 (P-256)
  if (curve_id == MBEDTLS_ECP_DP_SECP521R1) {
    mbedtls_sha512(data, input.size(), hash, 0);
    hash_len = 64;
  } else {
    mbedtls_sha256(data, input.size(), hash, 0);
    hash_len = 32;
  }
}

}  // namespace

bool parse_keys(const char *json, size_t len, std::vector<TangKey> &keys, std::string &error) {
  // The document copies every string, "d" included, so it wipes as it frees.
  JsonDocument doc(WipingAllocator::instance());
  if (deserializeJson(doc, json, len)) {
    error = "Invalid JSON";
    return false;
  }

  JsonArrayConst array = doc["keys"];
  if (array.isNull() || array.size() == 0) {
    error = "Missing 'keys' array";
    return false;
  }

  // Reserved up front so no TangKey is copied; any copy would be wiped anyway.
  std::vector<TangKey> parsed;
  parsed.reserve(array.size());
  bool has_sign = false, has_exchange = false;
  for (JsonVariantConst v : array) {
    TangKey &key = parsed.emplace_back();
    const char *problem = parse_key(v.as<JsonObjectConst>(), key);
    if (problem != nullptr) {
      char buf[96];
      snprintf(buf, sizeof(buf), "Key %zu: %s", parsed.size() - 1, problem);
      error = buf;
      return false;
    }
    has_sign |= key.usage == KeyUsage::SIGN;
    has_exchange |= key.usage == KeyUsage::EXCHANGE;
  }

  if (!has_sign || !has_exchange) {
    error = "Need a signing key and an exchange key";
    return false;
  }

  keys = std::move(parsed);
  return true;
}

Result build_adv(const std::vector<TangKey> &keys, const std::string &thp) {
  // With a thumbprint, the set is signed by that signing key, and an unknown
  // thumbprint yields 404, as in tangd's find_jws().
  const TangKey *signing_key = nullptr;
  for (const auto &key : keys) {
    if (key.usage != KeyUsage::SIGN)
      continue;
    if (thp.empty() || key_matches_id(key, thp)) {
      signing_key = &key;
      break;
    }
  }
  if (signing_key == nullptr) {
    if (!thp.empty())
      return Result::text(404, "No signing key with this thumbprint");
    return Result::text(500, "No signing key available");
  }

  // 1. The JWKSet payload
  JsonDocument doc;
  JsonArray jwks = doc["keys"].to<JsonArray>();
  for (const auto &key : keys) {
    JsonObject k = jwks.add<JsonObject>();
    bool p521 = key.curve_id == MBEDTLS_ECP_DP_SECP521R1;
    bool sign = key.usage == KeyUsage::SIGN;
    k["kty"] = "EC";
    k["crv"] = key.crv();
    k["alg"] = sign ? (p521 ? "ES512" : "ES256") : "ECMR";
    // No "kid": tangd advertises the raw JWKs, which carry no key ID.
    // Clients address keys by their RFC 7638 thumbprint instead.
    k["x"] = base64_url_encode(key.public_key, key.key_len);
    k["y"] = base64_url_encode(key.public_key + key.key_len, key.key_len);
    k["key_ops"].add(sign ? "verify" : "deriveKey");
  }
  std::string payload_json;
  serializeJson(doc, payload_json);

  // 2. The JWS protected header
  const char *header_json = signing_key->curve_id == MBEDTLS_ECP_DP_SECP521R1
                                ? R"({"alg":"ES512","cty":"jwk-set+json"})"
                                : R"({"alg":"ES256","cty":"jwk-set+json"})";

  // 3. Sign
  std::string protected_header = base64_url_encode(reinterpret_cast<const uint8_t *>(header_json), strlen(header_json));
  std::string payload_b64 =
      base64_url_encode(reinterpret_cast<const uint8_t *>(payload_json.data()), payload_json.size());
  std::string signing_input = protected_header + "." + payload_b64;

  uint8_t hash[64];
  size_t hash_len;
  hash_for_curve(signing_key->curve_id, signing_input, hash, hash_len);

  uint8_t signature[132];  // R || S, 66 bytes each for P-521
  if (!sign_data(signing_key->private_key, signing_key->curve_id, signing_key->key_len, hash, hash_len, signature))
    return Result::text(500, "Signing failed");

  // 4. Flattened JWS JSON serialization
  JsonDocument jws;
  jws["payload"] = payload_b64;
  jws["protected"] = protected_header;
  jws["signature"] = base64_url_encode(signature, signing_key->key_len * 2);

  Result result{200, "application/jose+json", {}};
  serializeJson(jws, result.body);
  return result;
}

Result exchange(const std::vector<TangKey> &keys, const std::string &thp, const char *body, size_t len) {
  const TangKey *exchange_key = nullptr;
  for (const auto &key : keys) {
    if (key.usage == KeyUsage::EXCHANGE && key_matches_id(key, thp)) {
      exchange_key = &key;
      break;
    }
  }
  if (exchange_key == nullptr)
    return Result::text(404, "No exchange key with this thumbprint");

  if (len == 0)
    return Result::text(400, "Missing body");

  JsonDocument req;
  if (deserializeJson(req, body, len))
    return Result::text(400, "Invalid JSON");

  if (strcmp(req["kty"] | "", "EC") != 0)
    return Result::text(400, "Unsupported key type");
  // Reject mixed curves, as tangd does.
  if (strcmp(req["crv"] | "", exchange_key->crv()) != 0)
    return Result::text(400, "Curve mismatch");

  size_t key_len = exchange_key->key_len;
  JsonObjectConst client = req.as<JsonObjectConst>();
  uint8_t client_pub[132];
  if (!decode_member(client, "x", client_pub, key_len) || !decode_member(client, "y", client_pub + key_len, key_len))
    return Result::text(400, "Invalid x/y coordinates length");

  uint8_t shared_point[132];  // X || Y
  int ret = compute_ecdh_shared_secret(client_pub, exchange_key->private_key, exchange_key->curve_id, key_len,
                                       shared_point);
  if (ret == MBEDTLS_ERR_ECP_INVALID_KEY)
    return Result::text(400, "Client key is not a point on the curve");
  if (ret != 0)
    return Result::text(500, "ECDH operation failed");

  JsonDocument resp;
  resp["alg"] = "ECMR";
  resp["kty"] = "EC";
  resp["crv"] = exchange_key->crv();
  resp["x"] = base64_url_encode(shared_point, key_len);
  resp["y"] = base64_url_encode(shared_point + key_len, key_len);
  resp["key_ops"].add("deriveKey");

  Result result{200, "application/jwk+json", {}};
  serializeJson(resp, result.body);
  return result;
}

}  // namespace esphome::tang_server
