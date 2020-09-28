#include "cbs.h"

#ifndef OPENSSL_IS_BORINGSSL

#include <assert.h>
#include <string.h>

#define CBS_ASN1_TAG_SHIFT 24
#define CBS_ASN1_CONSTRUCTED (0x20u << CBS_ASN1_TAG_SHIFT)
#define CBS_ASN1_SEQUENCE (0x10u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_TAG_NUMBER_MASK ((1u << (5 + CBS_ASN1_TAG_SHIFT)) - 1)
#define CBS_ASN1_INTEGER 0x2u
#define CBS_ASN1_CONTEXT_SPECIFIC (0x80u << CBS_ASN1_TAG_SHIFT)

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Cbs {

void CBS_init(CBS* cbs, const uint8_t* data, size_t len) {
  cbs->data = data;
  cbs->len = len;
}

static int cbs_get(CBS* cbs, const uint8_t** p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

static int cbs_get_u(CBS* cbs, uint64_t* out, size_t len) {
  uint64_t result = 0;
  const uint8_t* data;

  if (!cbs_get(cbs, &data, len)) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

int CBS_get_bytes(CBS* cbs, CBS* out, size_t len) {
  const uint8_t* v;
  if (!cbs_get(cbs, &v, len)) {
    return 0;
  }
  CBS_init(out, v, len);
  return 1;
}

static int cbb_buffer_reserve(struct cbb_buffer_st* base, uint8_t** out, size_t len) {
  size_t newlen;

  if (base == NULL) {
    return 0;
  }

  newlen = base->len + len;
  if (newlen < base->len) {
    // Overflow
    goto err;
  }

  if (newlen > base->cap) {
    size_t newcap = base->cap * 2;
    uint8_t* newbuf;

    if (!base->can_resize) {
      goto err;
    }

    if (newcap < base->cap || newcap < newlen) {
      newcap = newlen;
    }
    newbuf = static_cast<uint8_t*>(realloc(base->buf, newcap));
    if (newbuf == NULL) {
      goto err;
    }

    base->buf = newbuf;
    base->cap = newcap;
  }

  if (out) {
    *out = base->buf + base->len;
  }

  return 1;

err:
  base->error = 1;
  return 0;
}

static int cbb_buffer_add(struct cbb_buffer_st* base, uint8_t** out, size_t len) {
  if (!cbb_buffer_reserve(base, out, len)) {
    return 0;
  }
  // This will not overflow or |cbb_buffer_reserve| would have failed.
  base->len += len;
  return 1;
}

static int cbs_get_length_prefixed(CBS* cbs, CBS* out, size_t len_len) {
  uint64_t len;
  if (!cbs_get_u(cbs, &len, len_len)) {
    return 0;
  }
  // If |len_len| <= 3 then we know that |len| will fit into a |size_t|, even on
  // 32-bit systems.
  assert(len_len <= 3);
  return CBS_get_bytes(cbs, out, len);
}

size_t CBS_len(const CBS* cbs) { return cbs->len; }

const uint8_t* CBS_data(const CBS* cbs) { return cbs->data; }

int CBS_get_u8_length_prefixed(CBS* cbs, CBS* out) { return cbs_get_length_prefixed(cbs, out, 1); }

int CBS_get_u16_length_prefixed(CBS* cbs, CBS* out) { return cbs_get_length_prefixed(cbs, out, 2); }

// These functions are used outside of Envoy repository (e.g. by jwt_verify_lib)

int BN_cmp_word(BIGNUM* a, BN_ULONG b) {
  BIGNUM* b_bn = BN_new();

  BN_set_word(b_bn, b);

  int result = BN_cmp(a, b_bn);

  BN_free(b_bn);

  return result;
}

int CBS_get(CBS* cbs, const uint8_t** p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

int CBS_skip(CBS* cbs, size_t len) {
  const uint8_t* dummy;
  return CBS_get(cbs, &dummy, len);
}

int CBS_get_u8(CBS* cbs, uint8_t* out) {
  const uint8_t* v;
  if (!CBS_get(cbs, &v, 1)) {
    return 0;
  }
  *out = *v;
  return 1;
}

int parse_base128_integer(CBS* cbs, uint64_t* out) {
  uint64_t v = 0;
  uint8_t b;
  do {
    if (!CBS_get_u8(cbs, &b)) {
      return 0;
    }
    if ((v >> (64 - 7)) != 0) {
      // The value is too large.
      return 0;
    }
    if (v == 0 && b == 0x80) {
      // The value must be minimally encoded.
      return 0;
    }
    v = (v << 7) | (b & 0x7f);

    // Values end at an octet with the high bit cleared.
  } while (b & 0x80);

  *out = v;
  return 1;
}

int parse_asn1_tag(CBS* cbs, unsigned* out) {
  uint8_t tag_byte;
  if (!CBS_get_u8(cbs, &tag_byte)) {
    return 0;
  }

  // ITU-T X.690 section 8.1.2.3 specifies the format for identifiers with a tag
  // number no greater than 30.
  //
  // If the number portion is 31 (0x1f, the largest value that fits in the
  // allotted bits), then the tag is more than one byte long and the
  // continuation bytes contain the tag number. This parser only supports tag
  // numbers less than 31 (and thus single-byte tags).
  unsigned tag = (static_cast<unsigned>(tag_byte) & 0xe0) << CBS_ASN1_TAG_SHIFT;
  unsigned tag_number = tag_byte & 0x1f;
  if (tag_number == 0x1f) {
    uint64_t v;
    if (!parse_base128_integer(cbs, &v) ||
        // Check the tag number is within our supported bounds.
        v > CBS_ASN1_TAG_NUMBER_MASK ||
        // Small tag numbers should have used low tag number form.
        v < 0x1f) {
      return 0;
    }
    tag_number = static_cast<unsigned>(v);
  }

  tag |= tag_number;

  *out = tag;
  return 1;
}

int CBS_get_u(CBS* cbs, uint32_t* out, size_t len) {
  uint32_t result = 0;
  const uint8_t* data;

  if (!CBS_get(cbs, &data, len)) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

static int cbs_get_any_asn1_element(CBS* cbs, CBS* out, unsigned* out_tag, size_t* out_header_len,
                                    int* out_ber_found, int ber_ok) {
  CBS header = *cbs;
  CBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }
  if (ber_ok) {
    *out_ber_found = 0;
  }

  unsigned tag;
  if (!parse_asn1_tag(&header, &tag)) {
    return 0;
  }
  if (out_tag != NULL) {
    *out_tag = tag;
  }

  uint8_t length_byte;
  if (!CBS_get_u8(&header, &length_byte)) {
    return 0;
  }

  size_t header_len = CBS_len(cbs) - CBS_len(&header);

  size_t len;
  // The format for the length encoding is specified in ITU-T X.690 section
  // 8.1.3.
  if ((length_byte & 0x80) == 0) {
    // Short form length.
    len = static_cast<size_t>(length_byte) + header_len;
    if (out_header_len != NULL) {
      *out_header_len = header_len;
    }
  } else {
    // The high bit indicate that this is the long form, while the next 7 bits
    // encode the number of subsequent octets used to encode the length (ITU-T
    // X.690 clause 8.1.3.5.b).
    const size_t num_bytes = length_byte & 0x7f;
    uint64_t len64;

    if (ber_ok && (tag & CBS_ASN1_CONSTRUCTED) != 0 && num_bytes == 0) {
      // indefinite length
      if (out_header_len != NULL) {
        *out_header_len = header_len;
      }
      *out_ber_found = 1;
      return CBS_get_bytes(cbs, out, header_len);
    }

    // ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
    // used as the first byte of the length. If this parser encounters that
    // value, num_bytes will be parsed as 127, which will fail this check.
    if (num_bytes == 0 || num_bytes > 4) {
      return 0;
    }
    if (!cbs_get_u(&header, &len64, num_bytes)) {
      return 0;
    }
    // ITU-T X.690 section 10.1 (DER length forms) requires encoding the
    // length with the minimum number of octets. BER could, technically, have
    // 125 superfluous zero bytes. We do not attempt to handle that and still
    // require that the length fit in a |uint32_t| for BER.
    if (len64 < 128) {
      // Length should have used short-form encoding.
      if (ber_ok) {
        *out_ber_found = 1;
      } else {
        return 0;
      }
    }
    if ((len64 >> ((num_bytes - 1) * 8)) == 0) {
      // Length should have been at least one byte shorter.
      if (ber_ok) {
        *out_ber_found = 1;
      } else {
        return 0;
      }
    }
    len = len64;
    if (len + header_len + num_bytes < len) {
      // Overflow.
      return 0;
    }
    len += header_len + num_bytes;
    if (out_header_len != NULL) {
      *out_header_len = header_len + num_bytes;
    }
  }

  return CBS_get_bytes(cbs, out, len);
}

int CBS_get_any_asn1(CBS* cbs, CBS* out, unsigned* out_tag) {
  size_t header_len;
  if (!CBS_get_any_asn1_element(cbs, out, out_tag, &header_len)) {
    return 0;
  }

  if (!CBS_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int CBS_get_any_asn1_element(CBS* cbs, CBS* out, unsigned* out_tag, size_t* out_header_len) {
  return cbs_get_any_asn1_element(cbs, out, out_tag, out_header_len, NULL, 0 /* DER only */);
}

static int cbs_get_asn1(CBS* cbs, CBS* out, unsigned tag_value, int skip_header) {
  size_t header_len;
  unsigned tag;
  CBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }

  if (!CBS_get_any_asn1_element(cbs, out, &tag, &header_len) || tag != tag_value) {
    return 0;
  }

  if (skip_header && !CBS_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int CBS_get_asn1(CBS* cbs, CBS* out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 1 /* skip header */);
}

int BN_parse_asn1_unsigned(CBS* cbs, BIGNUM* ret) {
  CBS child;
  CBS_init(&child, NULL, 0);
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_INTEGER) || child.len == 0) {
    //      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
    return 0;
  }

  if (child.data[0] & 0x80) {
    //      OPENSSL_PUT_ERROR(BN, BN_R_NEGATIVE_NUMBER);
    return 0;
  }

  // INTEGERs must be minimal.
  if (child.data[0] == 0x00 && child.len > 1 && !(child.data[1] & 0x80)) {
    //      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
    return 0;
  }

  return BN_bin2bn(child.data, child.len, ret) != NULL;
}

int parse_integer(CBS* cbs, BIGNUM** out) {
  assert(*out == NULL);
  *out = BN_new();
  if (*out == NULL) {
    return 0;
  }
  return BN_parse_asn1_unsigned(cbs, *out);
}

RSA* RSA_parse_public_key(CBS* cbs) {
  RSA* rsa = RSA_new();
  if (rsa == NULL) {
    return NULL;
  }
  BIGNUM* bn_n = NULL;
  BIGNUM* bn_e = NULL;
  CBS child;
  CBS_init(&child, NULL, 0);
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_SEQUENCE)) {
    RSA_free(rsa);
    return NULL;
  } else {

    if (!parse_integer(&child, &bn_n) || !parse_integer(&child, &bn_e) || child.len != 0) {
      RSA_free(rsa);
      return NULL;
    } else {
      RSA_set0_key(rsa, bn_n, bn_e, NULL);
    }
  }

  if (!BN_is_odd(bn_e) || BN_num_bits(bn_e) < 2) {
    RSA_free(rsa);
    return NULL;
  }

  return rsa;
}

RSA* RSA_public_key_from_bytes(const uint8_t* in, size_t in_len) {
  CBS cbs;
  CBS_init(&cbs, in, in_len);
  RSA* ret = RSA_parse_public_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  return ret;
}

int CBS_is_valid_asn1_integer(const CBS* cbs, int* out_is_negative) {
  CBS copy = *cbs;
  uint8_t first_byte, second_byte;
  if (!CBS_get_u8(&copy, &first_byte)) {
    return 0; // INTEGERs may not be empty.
  }
  if (out_is_negative != NULL) {
    *out_is_negative = (first_byte & 0x80) != 0;
  }
  if (!CBS_get_u8(&copy, &second_byte)) {
    return 1; // One byte INTEGERs are always minimal.
  }
  if ((first_byte == 0x00 && (second_byte & 0x80) == 0) ||
      (first_byte == 0xff && (second_byte & 0x80) != 0)) {
    return 0; // The value is minimal iff the first 9 bits are not all equal.
  }
  return 1;
}

int CBS_is_unsigned_asn1_integer(const CBS* cbs) {
  int is_negative;
  return CBS_is_valid_asn1_integer(cbs, &is_negative) && !is_negative;
}

int CBS_get_asn1_element(CBS* cbs, CBS* out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 0 /* include header */);
}

int CBS_peek_asn1_tag(const CBS* cbs, unsigned tag_value) {
  if (CBS_len(cbs) < 1) {
    return 0;
  }

  CBS copy = *cbs;
  unsigned actual_tag;
  return parse_asn1_tag(&copy, &actual_tag) && tag_value == actual_tag;
}

int CBS_get_asn1_uint64(CBS* cbs, uint64_t* out) {
  CBS bytes;
  if (!CBS_get_asn1(cbs, &bytes, CBS_ASN1_INTEGER) || !CBS_is_unsigned_asn1_integer(&bytes)) {
    return 0;
  }

  *out = 0;
  const uint8_t* data = CBS_data(&bytes);
  size_t len = CBS_len(&bytes);
  for (size_t i = 0; i < len; i++) {
    if ((*out >> 56) != 0) {
      // Too large to represent as a uint64_t.
      return 0;
    }
    *out <<= 8;
    *out |= data[i];
  }

  return 1;
}

int CBS_get_asn1_int64(CBS* cbs, int64_t* out) {
  int is_negative;
  CBS bytes;
  if (!CBS_get_asn1(cbs, &bytes, CBS_ASN1_INTEGER) ||
      !CBS_is_valid_asn1_integer(&bytes, &is_negative)) {
    return 0;
  }
  const uint8_t* data = CBS_data(&bytes);
  const size_t len = CBS_len(&bytes);
  if (len > sizeof(int64_t)) {
    return 0;
  }
  union {
    int64_t i;
    uint8_t bytes[sizeof(int64_t)];
  } u;
  memset(u.bytes, is_negative ? 0xff : 0, sizeof(u.bytes)); // Sign-extend.
  for (size_t i = 0; i < len; i++) {
    u.bytes[i] = data[len - i - 1];
  }
  *out = u.i;
  return 1;
}

int CBS_get_asn1_bool(CBS* cbs, int* out) {
  CBS bytes;
  if (!CBS_get_asn1(cbs, &bytes, CBS_ASN1_BOOLEAN) || CBS_len(&bytes) != 1) {
    return 0;
  }

  const uint8_t value = *CBS_data(&bytes);
  if (value != 0 && value != 0xff) {
    return 0;
  }

  *out = !!value;
  return 1;
}

int CBS_get_optional_asn1(CBS* cbs, CBS* out, int* out_present, unsigned tag) {
  int present = 0;

  if (CBS_peek_asn1_tag(cbs, tag)) {
    if (!CBS_get_asn1(cbs, out, tag)) {
      return 0;
    }
    present = 1;
  }

  if (out_present != NULL) {
    *out_present = present;
  }

  return 1;
}

static int cbb_init(CBB* cbb, uint8_t* buf, size_t cap) {
  // This assumes that |cbb| has already been zeroed.
  struct cbb_buffer_st* base;

  base = static_cast<struct cbb_buffer_st*>(malloc(sizeof(struct cbb_buffer_st)));
  if (base == NULL) {
    return 0;
  }

  base->buf = buf;
  base->len = 0;
  base->cap = cap;
  base->can_resize = 1;
  base->error = 0;

  cbb->base = base;
  cbb->is_child = 0;
  return 1;
}

// CBB_flush recurses and then writes out any pending length prefix. The
// current length of the underlying base is taken to be the length of the
// length-prefixed data.
static int CBB_flush(CBB* cbb) {
  size_t child_start, i, len;

  // If |cbb->base| has hit an error, the buffer is in an undefined state, so
  // fail all following calls. In particular, |cbb->child| may point to invalid
  // memory.
  if (cbb->base == NULL || cbb->base->error) {
    return 0;
  }

  if (cbb->child == NULL || cbb->child->pending_len_len == 0) {
    return 1;
  }

  child_start = cbb->child->offset + cbb->child->pending_len_len;

  if (!CBB_flush(cbb->child) || child_start < cbb->child->offset || cbb->base->len < child_start) {
    goto err;
  }

  len = cbb->base->len - child_start;

  if (cbb->child->pending_is_asn1) {
    // For ASN.1 we assume that we'll only need a single byte for the length.
    // If that turned out to be incorrect, we have to move the contents along
    // in order to make space.
    uint8_t len_len;
    uint8_t initial_length_byte;

    assert(cbb->child->pending_len_len == 1);

    if (len > 0xfffffffe) {
      // Too large.
      goto err;
    } else if (len > 0xffffff) {
      len_len = 5;
      initial_length_byte = 0x80 | 4;
    } else if (len > 0xffff) {
      len_len = 4;
      initial_length_byte = 0x80 | 3;
    } else if (len > 0xff) {
      len_len = 3;
      initial_length_byte = 0x80 | 2;
    } else if (len > 0x7f) {
      len_len = 2;
      initial_length_byte = 0x80 | 1;
    } else {
      len_len = 1;
      initial_length_byte = len;
      len = 0;
    }

    if (len_len != 1) {
      // We need to move the contents along in order to make space.
      size_t extra_bytes = len_len - 1;
      if (!cbb_buffer_add(cbb->base, NULL, extra_bytes)) {
        goto err;
      }
      memmove(cbb->base->buf + child_start + extra_bytes, cbb->base->buf + child_start, len);
    }
    cbb->base->buf[cbb->child->offset++] = initial_length_byte;
    cbb->child->pending_len_len = len_len - 1;
  }

  for (i = cbb->child->pending_len_len - 1; i < cbb->child->pending_len_len; i--) {
    cbb->base->buf[cbb->child->offset + i] = static_cast<uint8_t>(len);
    len >>= 8;
  }
  if (len != 0) {
    goto err;
  }

  cbb->child->base = NULL;
  cbb->child = NULL;

  return 1;

err:
  cbb->base->error = 1;
  return 0;
}

static void CBB_zero(CBB* cbb) { memset(cbb, 0, sizeof(CBB)); }

static int CBB_init(CBB* cbb, size_t initial_capacity) {
  CBB_zero(cbb);

  uint8_t* buf = static_cast<uint8_t*>(malloc(initial_capacity));
  if (initial_capacity > 0 && buf == NULL) {
    return 0;
  }

  if (!cbb_init(cbb, buf, initial_capacity)) {
    free(buf);
    return 0;
  }

  return 1;
}

static int CBB_add_bytes(CBB* cbb, const uint8_t* data, size_t len) {
  uint8_t* dest;

  if (!CBB_flush(cbb) || !cbb_buffer_add(cbb->base, &dest, len)) {
    return 0;
  }
  memcpy(dest, data, len);
  return 1;
}

static int cbb_buffer_add_u(struct cbb_buffer_st* base, uint64_t v, size_t len_len) {
  if (len_len == 0) {
    return 1;
  }

  uint8_t* buf;
  if (!cbb_buffer_add(base, &buf, len_len)) {
    return 0;
  }

  for (size_t i = len_len - 1; i < len_len; i--) {
    buf[i] = v;
    v >>= 8;
  }

  if (v != 0) {
    base->error = 1;
    return 0;
  }

  return 1;
}

static int CBB_add_u8(CBB* cbb, uint8_t value) {
  if (!CBB_flush(cbb)) {
    return 0;
  }

  return cbb_buffer_add_u(cbb->base, value, 1);
}

static int add_decimal(CBB* out, uint64_t v) {
  char buf[DECIMAL_SIZE(uint64_t) + 1];
  BIO_snprintf(buf, sizeof(buf), "%" PRIu64, v);
  return CBB_add_bytes(out, reinterpret_cast<const uint8_t*>(buf), strlen(buf));
}

static void CBB_cleanup(CBB* cbb) {
  // Child |CBB|s are non-owning. They are implicitly discarded and should not
  // be used with |CBB_cleanup| or |ScopedCBB|.
  assert(!cbb->is_child);
  if (cbb->is_child) {
    return;
  }

  if (cbb->base) {
    if (cbb->base->can_resize) {
      free(cbb->base->buf);
    }
    free(cbb->base);
  }
  cbb->base = NULL;
}

static int CBB_finish(CBB* cbb, uint8_t** out_data, size_t* out_len) {
  if (cbb->is_child) {
    return 0;
  }

  if (!CBB_flush(cbb)) {
    return 0;
  }

  if (cbb->base->can_resize && (out_data == NULL || out_len == NULL)) {
    // |out_data| and |out_len| can only be NULL if the CBB is fixed.
    return 0;
  }

  if (out_data != NULL) {
    *out_data = cbb->base->buf;
  }
  if (out_len != NULL) {
    *out_len = cbb->base->len;
  }
  cbb->base->buf = NULL;
  CBB_cleanup(cbb);
  return 1;
}

char* CBS_asn1_oid_to_text(const CBS* cbs) {
  CBB cbb;
  CBS copy = *cbs;

  if (!CBB_init(&cbb, 32)) {
    goto err;
  }

  // The first component is 40 * value1 + value2, where value1 is 0, 1, or 2.
  uint64_t v;
  if (!parse_base128_integer(&copy, &v)) {
    goto err;
  }

  if (v >= 80) {
    if (!CBB_add_bytes(&cbb, reinterpret_cast<const uint8_t*>("2."), 2) ||
        !add_decimal(&cbb, v - 80)) {
      goto err;
    }
  } else if (!add_decimal(&cbb, v / 40) || !CBB_add_u8(&cbb, '.') || !add_decimal(&cbb, v % 40)) {
    goto err;
  }

  while (CBS_len(&copy) != 0) {
    if (!parse_base128_integer(&copy, &v) || !CBB_add_u8(&cbb, '.') || !add_decimal(&cbb, v)) {
      goto err;
    }
  }

  uint8_t* txt;
  size_t txt_len;
  if (!CBB_add_u8(&cbb, '\0') || !CBB_finish(&cbb, &txt, &txt_len)) {
    goto err;
  }

  return reinterpret_cast<char*>(txt);

err:
  CBB_cleanup(&cbb);
  return NULL;
}

} // namespace Cbs
} // namespace Common
} // namespace Extensions
} // namespace Envoy

#endif // OPENSSL_IS_BORINGSSL
