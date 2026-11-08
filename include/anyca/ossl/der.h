/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSSL_DER_H
#define ANYCA_OSSL_DER_H

/**
 * @file der.h
 * @brief DER encoding helpers for OpenSSL objects.
 *
 * Encoded buffers use osal_malloc(), so callers release them with
 * ossl_der_release() and never mix OpenSSL and project allocations.
 */

#include <stdbool.h>
#include <stddef.h>

#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

/** DER-encoded value; data is osal_malloc()ed. */
typedef struct ossl_der {
	unsigned char *data;
	size_t length;
} ossl_der_t;

/**
 * Growable DER output buffer; data is osal_malloc()ed.
 *
 * Zero-initialise the structure before first use.  A buffer can be reused
 * after ossl_der_buf_release().
 */
typedef struct ossl_der_buf {
	unsigned char *data;
	size_t length;
	size_t capacity;
} ossl_der_buf_t;

/**
 * Append raw bytes to a DER output buffer.  length may be zero, in which case
 * data is ignored.
 */
bool ossl_der_buf_append(ossl_der_buf_t *buf,
				       const void *data, size_t length);

/**
 * Append content wrapped in one DER tag-length-value element.
 *
 * out and content must be distinct.  The tag is written verbatim, so
 * constructed and context-specific tags are supported.
 */
bool ossl_der_buf_wrap(ossl_der_buf_t *out, unsigned char tag,
				     const ossl_der_buf_t *content);

/** Release a DER output buffer.  NULL is a no-op. */
void ossl_der_buf_release(ossl_der_buf_t *buf);

/**
 * Encode an OpenSSL object through its ASN.1 item descriptor, e.g.
 * ossl_der_encode_item(ASN1_ITEM_rptr(X509_NAME), name, &der).  Release with
 * ossl_der_release().
 */
bool ossl_der_encode_item(const ASN1_ITEM *item,
					const void *object, ossl_der_t *der);

/**
 * Decode one complete DER value through its ASN.1 item descriptor.
 *
 * The input must contain exactly one value and no trailing bytes.  The result
 * is allocated by OpenSSL; release it with the type-specific free function,
 * e.g. X509_free() or ASN1_item_free().
 */
bool ossl_der_decode_item(const ASN1_ITEM *item,
					const unsigned char *der, size_t length,
					void **object);

/**
 * Encode a raw r||s ECDSA signature as a DER ECDSA-Sig-Value.
 *
 * PKCS #11 returns two fixed-width big-endian integers; X.509 and OCSP
 * require SEQUENCE { r INTEGER, s INTEGER }.  raw_length must be nonzero and
 * even; the first half is r.  Release with ossl_der_release().
 */
bool ossl_der_encode_ecdsa_signature(const unsigned char *raw,
						   size_t raw_length,
						   ossl_der_t *der);

/** Release an encoding produced by this module.  NULL is a no-op. */
void ossl_der_release(ossl_der_t *der);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSSL_DER_H
