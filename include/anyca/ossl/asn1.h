/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSSL_ASN1_H
#define ANYCA_OSSL_ASN1_H

/**
 * @file asn1.h
 * @brief Common ASN.1 parsing and conversion helpers.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One DER tag-length-value element. */
typedef struct ossl_asn1_tlv {
	/** Tag number without the constructed bit. */
	int tag;
	/** Tag class, e.g. V_ASN1_UNIVERSAL or V_ASN1_CONTEXT_SPECIFIC. */
	int xclass;
	/** Whether the encoding uses the constructed form. */
	bool constructed;
	/** Start of the content octets; points into the caller's buffer. */
	const unsigned char *content;
	/** Number of content octets. */
	long content_length;
} ossl_asn1_tlv_t;

/**
 * Read one definite-length DER element.
 *
 * On success *cursor advances past the element header; the caller skips
 * content_length bytes to reach the next element.  Indefinite lengths and
 * malformed encodings are rejected.
 */
bool ossl_asn1_read_tlv(const unsigned char **cursor,
				      long available, ossl_asn1_tlv_t *tlv);

/** Read one DER element and require its tag and class. */
bool ossl_asn1_expect_tlv(const unsigned char **cursor,
					long available, int tag, int xclass,
					ossl_asn1_tlv_t *tlv);

/**
 * Convert a non-negative ASN.1 INTEGER to canonical unsigned big-endian
 * bytes: sign padding and leading zeroes are removed, and zero becomes one
 * 0x00 byte.  output is osal_malloc()ed; release it with osal_free().  When
 * negative is not NULL it reports a negative input, which fails without
 * allocating.
 */
bool ossl_asn1_integer_to_bytes(const ASN1_INTEGER *integer,
					      unsigned char **data,
					      size_t *length, bool *negative);

/**
 * Convert unsigned big-endian bytes to an ASN.1 INTEGER, adding a sign byte
 * when needed.  Zero is rejected because callers use this for X.509 serial
 * and CRL numbers.  Release with ASN1_INTEGER_free().
 */
ASN1_INTEGER *ossl_asn1_integer_from_bytes(
	const unsigned char *data, size_t length);

/** Create an ASN.1 INTEGER from an unsigned 64-bit value; release with
 *  ASN1_INTEGER_free(). */
ASN1_INTEGER *ossl_asn1_integer_from_uint64(uint64_t value);

/** Format an ASN.1 INTEGER as an osal_malloc()ed hexadecimal string. */
char *ossl_asn1_integer_to_hex(const ASN1_INTEGER *integer);

/** Convert an ASN.1 time (UTCTIME or GENERALIZEDTIME) to Unix time. */
bool ossl_asn1_time_to_epoch(const ASN1_TIME *time,
					   int64_t *epoch);

/**
 * Create an ASN.1 time from Unix time.  OpenSSL selects the encoding that can
 * represent the value.  Release with ASN1_TIME_free().
 */
ASN1_TIME *ossl_asn1_time_from_epoch(int64_t epoch);

/** Create an ASN.1 time for the current moment; release with
 *  ASN1_TIME_free(). */
ASN1_TIME *ossl_asn1_time_now(void);

/** Create an ASN.1 GENERALIZEDTIME from Unix time; release with
 *  ASN1_GENERALIZEDTIME_free(). */
ASN1_GENERALIZEDTIME *ossl_asn1_generalized_time_from_epoch(
	int64_t epoch);

/**
 * Create a BIT STRING from bytes with zero unused bits.
 *
 * ASN1_BIT_STRING_set() does not initialize the unused-bits field, so this
 * helper marks it explicitly; otherwise trailing zero bits would be reported
 * as unused.  Release with ASN1_BIT_STRING_free().
 */
ASN1_BIT_STRING *ossl_asn1_bit_string_from_bytes(
	const unsigned char *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSSL_ASN1_H
