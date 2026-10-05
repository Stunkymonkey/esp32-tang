#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <ArduinoJson.h>
#include <mbedtls/ecp.h>

// The Tang protocol: JWK parsing, /adv signing and the ECMR exchange. Knows
// nothing about HTTP or ESPHome entities; callers pass bytes and keys and get
// a status and a body back.
//
// Not thread-safe: the DRBG is shared, so every call that takes keys must run
// under the owner's mutex.

namespace esphome::tang_server {

// Hash algorithms tangd accepts for thumbprint lookups (see supported_hashes()
// in tang's keys.c). clevis writes S256 by default, S1 in older versions.
static constexpr size_t TANG_THP_ALG_COUNT = 5;
extern const char *const TANG_THP_ALGS[TANG_THP_ALG_COUNT];

enum class KeyUsage : uint8_t { SIGN, EXCHANGE };

struct TangKey {
  std::string kid;
  // RFC 7638 thumbprints in the order of TANG_THP_ALGS, computed once when the
  // key is loaded.
  std::array<std::string, TANG_THP_ALG_COUNT> thp;
  KeyUsage usage;
  mbedtls_ecp_group_id curve_id;  // MBEDTLS_ECP_DP_SECP256R1 or MBEDTLS_ECP_DP_SECP521R1
  uint8_t private_key[66];        // Max size for P-521
  uint8_t public_key[132];        // Max size for P-521 (X || Y)
  size_t key_len;                 // Actual length of private key (32 or 66)

  TangKey() = default;
  TangKey(const TangKey &) = default;
  TangKey &operator=(const TangKey &) = default;
  // Wipe the private key whenever a copy goes away: the temporary built
  // while parsing, the old storage when a vector reallocates, and every key
  // on deactivation. Unlike memset(), this cannot be optimized out.
  ~TangKey();

  const char *crv() const;
  const std::string &thp_by_alg(const char *alg) const;
};

/// Status and body of a protocol operation, for the caller to send.
struct Result {
  int status;
  const char *content_type;
  std::string body;

  static Result text(int status, const char *message) { return {status, "text/plain", message}; }
};

/// Overwrite the whole buffer, including spare capacity, and empty it.
void wipe(std::string &s);
void wipe(std::vector<uint8_t> &v);

/// Wipes a string or vector when it goes out of scope, for data that carries
/// private keys or passwords.
template<typename T> struct ScopedWipe {
  T &buf;
  ~ScopedWipe() { wipe(this->buf); }
};

/// ArduinoJson allocator that zeroes every block before it is freed, for
/// documents that may hold private keys or passwords. ArduinoJson 7 copies
/// every string into the document, so the input buffer is not the only copy.
class WipingAllocator : public ArduinoJson::Allocator {
 public:
  void *allocate(size_t size) override;
  void deallocate(void *ptr) override;
  void *reallocate(void *ptr, size_t new_size) override;

  static WipingAllocator *instance();
};

std::string base64_url_encode(const uint8_t *data, size_t len);
/// @return the decoded length, or -1 if the input is invalid or does not fit.
int base64_url_decode(const char *input, size_t input_len, uint8_t *output, size_t max_len);

/// Seeds the DRBG on first use. @return 0 on success.
int init_rng();

/// Parses a `{"keys": [...]}` payload. Every key must be a valid EC JWK on
/// P-256 or P-521 whose `d` matches `x`/`y`, and the set must contain a
/// signing and an exchange key. On any error nothing is returned in `keys`
/// and `error` holds a short message that is safe to log and send.
bool parse_keys(const char *json, size_t len, std::vector<TangKey> &keys, std::string &error);

/// The keys as a compact `{"keys": [...]}` payload that parse_keys()
/// accepts, private parts included. The caller wipes the result.
std::string serialize_keys(const std::vector<TangKey> &keys);

/// Signed advertisement for /adv (empty `thp`) or /adv/<thp>.
Result build_adv(const std::vector<TangKey> &keys, const std::string &thp);

/// ECMR exchange for /rec/<thp> with the client's JWK in `body`.
Result exchange(const std::vector<TangKey> &keys, const std::string &thp, const char *body, size_t len);

}  // namespace esphome::tang_server
