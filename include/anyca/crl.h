/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_CRL_H
#define ANYCA_CRL_H

/**
 * @file crl.h
 * @brief Minimal X.509 v2 CRL builder.
 *
 * Collect the fields, revoked entries and extensions, encode the TBS with
 * crl_builder_tbs(), sign it with the caller's key and assemble the CRL with
 * crl_builder_assemble().  Issuer, revocation and numbering data belong to
 * the caller.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Owned DER-encoded CRL or TBSCertList. */
typedef struct crl_blob {
	unsigned char *data;
	size_t length;
} crl_blob_t;

/** Signature scheme of a generated CRL. */
typedef enum crl_signature_scheme {
	CRL_SIGNATURE_RSA = 0,
	CRL_SIGNATURE_ECDSA,
	CRL_SIGNATURE_ML_DSA_44,
	CRL_SIGNATURE_ML_DSA_65,
	CRL_SIGNATURE_ML_DSA_87,
} crl_signature_scheme_t;

/**
 * Digest algorithm used for a CRL signature.
 *
 * SHA-384 is the default and has value zero, so zero-initialized callers
 * select it.
 */
typedef enum crl_digest_algorithm {
	CRL_DIGEST_SHA384 = 0,
	CRL_DIGEST_SHA1,
	CRL_DIGEST_SHA256,
	CRL_DIGEST_SHA512,
} crl_digest_algorithm_t;

/** Default CRL signature digest (SHA-384). */
#define CRL_DIGEST_DEFAULT CRL_DIGEST_SHA384

/** Opaque X.509 v2 CRL builder. */
typedef struct crl_builder crl_builder_t;

/** Allocate an empty v2 builder; release with crl_builder_free(). */
crl_builder_t *crl_builder_new(void);

/** Release a builder and everything it owns.  NULL is a no-op. */
void crl_builder_free(crl_builder_t *builder);

/**
 * Set the issuer name from a DER-encoded CA certificate.
 *
 * The certificate supplies the issuer name and authority key identifier
 * source and is retained to validate the assembled signature.
 */
bool crl_builder_set_issuer_certificate(
	crl_builder_t *builder, const unsigned char *der, size_t length);

/**
 * Set thisUpdate and nextUpdate as Unix times.
 *
 * this_update zero selects the current time when the TBS is encoded;
 * next_update is required because RFC 5280 CRLs must carry it.
 */
bool crl_builder_set_update_times(crl_builder_t *builder,
						int64_t this_update,
						int64_t next_update);

/**
 * Add one revoked certificate.
 *
 * serial is canonical big-endian bytes.  reason is an RFC 5280 reasonCode in
 * 0..10 excluding 7; zero omits the reasonCode entry extension.
 */
bool crl_builder_add_revoked_certificate(
	crl_builder_t *builder, const unsigned char *serial,
	size_t serial_length, int64_t revoked_at, int reason);

/** Add the CRL number extension (non-critical). */
bool crl_builder_add_crl_number(crl_builder_t *builder,
					      uint64_t number);

/**
 * Add authorityKeyIdentifier (non-critical) from the issuer certificate.
 *
 * Uses the issuer's subjectKeyIdentifier when present, otherwise the SHA-1 of
 * the issuer public-key bits.  The issuer certificate must be set first.
 */
bool crl_builder_add_authority_key_identifier(
	crl_builder_t *builder);

/**
 * Add an arbitrary CRL extension.
 *
 * der is the extension value contents, i.e. the extnValue OCTET STRING
 * payload without its tag and length; it may be NULL when length is zero.
 * oid is numeric or a known OpenSSL name.
 */
bool crl_builder_add_extension(crl_builder_t *builder,
					     const char *oid, bool critical,
					     const unsigned char *der,
					     size_t length);

/**
 * DER-encode the TBSCertList to be signed by the caller.
 *
 * The result is the exact input for the signing operation; pass it and the
 * signature to crl_builder_assemble().
 *
 * @param tbs receives the DER encoding; release with crl_blob_free().
 */
bool crl_builder_tbs(const crl_builder_t *builder,
				   crl_signature_scheme_t scheme,
				   crl_digest_algorithm_t digest,
				   crl_blob_t *tbs);

/**
 * Assemble and DER-encode the CRL from a signed TBS.
 *
 * tbs must be the exact output of crl_builder_tbs() for this builder,
 * scheme and digest.  signature uses the signer's raw form: PKCS #1 v1.5
 * bytes for RSA, r || s for ECDSA.  The result is re-parsed and its signature
 * verified against the issuer certificate before it is returned.
 *
 * @param crl receives the DER encoding; release with crl_blob_free().
 */
bool crl_builder_assemble(
	const crl_builder_t *builder, crl_signature_scheme_t scheme,
	crl_digest_algorithm_t digest, const unsigned char *tbs,
	size_t tbs_length, const unsigned char *signature,
	size_t signature_length, crl_blob_t *crl);

/** Release a blob returned by crl_builder_tbs() or crl_builder_assemble(). */
void crl_blob_free(crl_blob_t *crl);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_CRL_H
