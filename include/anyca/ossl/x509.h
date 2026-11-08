/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSSL_X509_H
#define ANYCA_OSSL_X509_H

/**
 * @file x509.h
 * @brief X.509 certificate helpers.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/x509.h>

#include <anyca/ossl/der.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Load one DER-encoded certificate from a file; release with X509_free(). */
X509 *ossl_x509_load_der_file(const char *path);

/** Decode exactly one DER certificate from memory; release with X509_free(). */
X509 *ossl_x509_load_der(const unsigned char *der,
				       size_t length);

/** Decode exactly one DER CRL from memory; release with X509_CRL_free(). */
X509_CRL *ossl_x509_crl_load_der(const unsigned char *der,
					       size_t length);

/**
 * Load a PKCS #10 request from a PEM or DER file, trying PEM first.  Release
 * with X509_REQ_free().
 */
X509_REQ *ossl_x509_req_load_file(const char *path);

/**
 * Extract a public key from a DER or PEM certificate, PKCS #10 request or
 * SubjectPublicKeyInfo.
 *
 * A search helper: it accepts any of the three structures in either encoding
 * and does not verify signatures or trust.  Release with EVP_PKEY_free().
 */
EVP_PKEY *ossl_x509_load_public_key(const unsigned char *data,
						  size_t length);

/** Encode an X.509 Name as DER. */
bool ossl_x509_name_encode(const X509_NAME *name,
					 ossl_der_t *der);

/** Decode exactly one DER-encoded X.509 Name; trailing bytes are rejected. */
bool ossl_x509_name_decode(const unsigned char *der,
					 size_t length, X509_NAME **name);

/** Encode a SubjectPublicKeyInfo as DER. */
bool ossl_x509_pubkey_encode(const X509_PUBKEY *public_key,
					   ossl_der_t *der);

/** Decode exactly one DER SubjectPublicKeyInfo; trailing bytes are rejected. */
bool ossl_x509_pubkey_decode(const unsigned char *der,
					   size_t length,
					   X509_PUBKEY **public_key);

/** Encode an EVP public key as a DER SubjectPublicKeyInfo. */
bool ossl_x509_spki_encode(const EVP_PKEY *public_key,
					 ossl_der_t *der);

/**
 * Build the AlgorithmIdentifier for a signature algorithm NID.
 *
 * RSA PKCS #1 schemes carry explicit NULL parameters; ECDSA and ML-DSA
 * schemes omit them.  Release with X509_ALGOR_free().
 */
X509_ALGOR *ossl_x509_signature_algorithm_new(
	int signature_nid);

/**
 * Return the subjectPublicKey BIT STRING contents of a certificate.  The
 * bytes point into certificate and must not be released by the caller.
 */
bool ossl_x509_public_key_bits(const X509 *certificate,
					     const unsigned char **bits,
					     size_t *length);

/**
 * Extract the certificate serial as unsigned big-endian bytes without sign
 * padding; zero is one 0x00 byte.  serial is osal_malloc()ed; release it with
 * osal_free().
 */
bool ossl_x509_serial(const X509 *certificate,
				    unsigned char **serial,
				    size_t *serial_length);

/** Read notAfter as Unix time. */
bool ossl_x509_not_after(const X509 *certificate,
				       int64_t *not_after);

/** Tell whether the certificate is valid now: notBefore <= now < notAfter. */
bool ossl_x509_valid_now(const X509 *certificate);

/**
 * Tell whether the certificate contains an extended key usage.
 *
 * @param nid EKU purpose NID, e.g. NID_OCSP_sign.
 */
bool ossl_x509_has_eku(const X509 *certificate, int nid);

/**
 * Build a non-critical subjectKeyIdentifier extension from the SHA-1 of the
 * subjectPublicKey BIT STRING contents (RFC 5280).  Release with
 * X509_EXTENSION_free().
 */
X509_EXTENSION *ossl_x509_subject_key_identifier(
	const X509_PUBKEY *public_key);

/**
 * Build a non-critical authorityKeyIdentifier extension.  Uses the issuer's
 * subjectKeyIdentifier when present, otherwise derives it from the issuer
 * public key.  Release with X509_EXTENSION_free().
 */
X509_EXTENSION *ossl_x509_authority_key_identifier(
	const X509 *issuer_certificate);

/**
 * Create an extension from a DER-encoded extension value.  der is the
 * extnValue contents without tag and length; oid is dotted-decimal.  Release
 * with X509_EXTENSION_free().
 */
X509_EXTENSION *ossl_x509_extension_new_der(
	const char *oid, bool critical, const unsigned char *der,
	size_t length);

/**
 * Create an extension from an OpenSSL extension value structure.  Release with
 * X509_EXTENSION_free().
 */
X509_EXTENSION *ossl_x509_extension_new_by_nid(
	int nid, bool critical, const void *value);

/**
 * Append an extension to a stack, creating the stack when needed.  On failure
 * the extension is released.
 */
bool ossl_x509_extension_push(
	STACK_OF(X509_EXTENSION) **extensions, X509_EXTENSION *extension);

/**
 * Duplicate an extension stack.  Release with
 * sk_X509_EXTENSION_pop_free(..., X509_EXTENSION_free); returns NULL when
 * extensions is NULL or empty.
 */
STACK_OF(X509_EXTENSION) *ossl_x509_extension_copy_stack(
	const STACK_OF(X509_EXTENSION) *extensions);

/** Format an extension OID as an osal_malloc()ed dotted-decimal string. */
char *ossl_x509_extension_oid(
	X509_EXTENSION *extension);

/**
 * Read the criticality and DER value of an extension.  value points into
 * extension and must not be released by the caller.
 */
bool ossl_x509_extension_data(
	X509_EXTENSION *extension, bool *critical,
	const unsigned char **value, size_t *value_length);

/**
 * Tell whether one certificate was issued by another: the issuer name must
 * match and issuer's public key must verify the signature.  Trust and path
 * validation are the caller's responsibility.
 */
bool ossl_x509_issued_by(X509 *certificate,
				       const X509 *issuer);

/**
 * Verify a certificate signature with the certificate's own public key.  It
 * does not compare names or establish trust.
 */
bool ossl_x509_verify_self_signature(X509 *certificate);

/**
 * Tell whether one CRL was issued by a certificate: the issuer name must
 * match and issuer's public key must verify the CRL signature.  Trust and
 * freshness are the caller's responsibility.
 */
bool ossl_x509_crl_issued_by(X509_CRL *crl,
					   const X509 *issuer);

/** Verify a certificate request with its own public key. */
bool ossl_x509_req_verify_self(X509_REQ *request);

/**
 * Verify a data signature with the certificate's public key.
 *
 * Accepts SHA-256 with RSA PKCS #1 v1.5 (PKCS #1 form), ECDSA (raw PKCS #11
 * r || s), and ML-DSA-44/65/87 signatures, matching the algorithms callers can
 * request from the HSM.  This only checks possession of the key, not trust or
 * validity.
 */
bool ossl_x509_verify_data(const X509 *certificate,
					 const void *data, size_t data_length,
					 const unsigned char *signature,
					 size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSSL_X509_H
