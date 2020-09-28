#pragma once

#include "openssl/asn1.h"
#include "openssl/crypto.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#ifndef OPENSSL_IS_BORINGSSL

#include <cstddef>    // for size_t
#include <cstdint>    // for uint8_t
#include <inttypes.h> // for PRIu64

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Cbs {

#define DECIMAL_SIZE(type) ((sizeof(type) * 8 + 2) / 3 + 1)

#define CBS_ASN1_TAG_SHIFT 24
#define CBS_ASN1_CONSTRUCTED (0x20u << CBS_ASN1_TAG_SHIFT)
#define CBS_ASN1_CONTEXT_SPECIFIC (0x80u << CBS_ASN1_TAG_SHIFT)

#define CBS_ASN1_BOOLEAN 0x1u
#define CBS_ASN1_INTEGER 0x2u
#define CBS_ASN1_BITSTRING 0x3u
#define CBS_ASN1_OCTETSTRING 0x4u
#define CBS_ASN1_NULL 0x5u
#define CBS_ASN1_OBJECT 0x6u
#define CBS_ASN1_ENUMERATED 0xau
#define CBS_ASN1_UTF8STRING 0xcu
#define CBS_ASN1_SEQUENCE (0x10u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_SET (0x11u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_NUMERICSTRING 0x12u
#define CBS_ASN1_PRINTABLESTRING 0x13u
#define CBS_ASN1_T61STRING 0x14u
#define CBS_ASN1_VIDEOTEXSTRING 0x15u
#define CBS_ASN1_IA5STRING 0x16u
#define CBS_ASN1_UTCTIME 0x17u
#define CBS_ASN1_GENERALIZEDTIME 0x18u
#define CBS_ASN1_GRAPHICSTRING 0x19u
#define CBS_ASN1_VISIBLESTRING 0x1au
#define CBS_ASN1_GENERALSTRING 0x1bu
#define CBS_ASN1_UNIVERSALSTRING 0x1cu
#define CBS_ASN1_BMPSTRING 0x1eu

struct cbb_buffer_st {
  uint8_t* buf;
  size_t len;      // The number of valid bytes.
  size_t cap;      // The size of buf.
  char can_resize; /* One iff |buf| is owned by this object. If not then |buf|
                      cannot be resized. */
  char error;      /* One iff there was an error writing to this CBB. All future
                      operations will fail. */
};

struct CBB {
  struct cbb_buffer_st* base;
  // child points to a child CBB if a length-prefix is pending.
  CBB* child;
  // offset is the number of bytes from the start of |base->buf| to this |CBB|'s
  // pending length prefix.
  size_t offset;
  // pending_len_len contains the number of bytes in this |CBB|'s pending
  // length-prefix, or zero if no length-prefix is pending.
  uint8_t pending_len_len;
  char pending_is_asn1;
  // is_child is true iff this is a child |CBB| (as opposed to a top-level
  // |CBB|). Top-level objects are valid arguments for |CBB_finish|.
  char is_child;
};

struct CBS {
  const uint8_t* data;
  size_t len;
};

void CBS_init(CBS* cbs, const uint8_t* data, size_t len);

size_t CBS_len(const CBS* cbs);
const uint8_t* CBS_data(const CBS* cbs);

int CBS_get_u8_length_prefixed(CBS* cbs, CBS* out);
int CBS_get_u16_length_prefixed(CBS* cbs, CBS* out);

int CBS_get_asn1(CBS* cbs, CBS* out, unsigned tag_value);
int CBS_get_optional_asn1(CBS* cbs, CBS* out, int* out_present, unsigned tag);
char* CBS_asn1_oid_to_text(const CBS* cbs);
int CBS_get_any_asn1_element(CBS* cbs, CBS* out, unsigned* out_tag, size_t* out_header_len);

// These functions are used outside of Envoy repository (e.g. by jwt_verify_lib)
int BN_cmp_word(BIGNUM* a, BN_ULONG b);
RSA* RSA_public_key_from_bytes(const uint8_t* in, size_t in_len);

} // namespace Cbs
} // namespace Common
} // namespace Extensions
} // namespace Envoy

#endif
