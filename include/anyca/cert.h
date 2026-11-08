/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_CERT_H
#define ANYCA_CERT_H

/**
 * @file cert.h
 * @brief Minimal X.509 v3 certificate builder.
 *
 * Set the fields and extensions, encode the TBS with cert_builder_tbs(),
 * sign it with the caller's key, then assemble the certificate with
 * cert_builder_assemble().  cert_request_t loads and verifies PKCS #10
 * requests.  Certificate profiles belong to the caller.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Owned DER-encoded certificate or TBSCertificate. */
typedef struct cert_blob {
	unsigned char *data;
	size_t length;
} cert_blob_t;

/** Signature scheme of a generated certificate. */
typedef enum cert_signature_scheme {
	CERT_SIGNATURE_RSA = 0,
	CERT_SIGNATURE_ECDSA,
	CERT_SIGNATURE_ML_DSA_44,
	CERT_SIGNATURE_ML_DSA_65,
	CERT_SIGNATURE_ML_DSA_87,
} cert_signature_scheme_t;

/** ML-DSA parameter set of a generated subject public key. */
typedef enum cert_ml_dsa_parameter_set {
	CERT_ML_DSA_44 = 0,
	CERT_ML_DSA_65,
	CERT_ML_DSA_87,
} cert_ml_dsa_parameter_set_t;

/**
 * Digest algorithm used for a certificate signature.
 *
 * SHA-384 is the default and has value zero, so zero-initialized callers
 * select it.
 */
typedef enum cert_digest_algorithm {
	CERT_DIGEST_SHA384 = 0,
	CERT_DIGEST_SHA1,
	CERT_DIGEST_SHA256,
	CERT_DIGEST_SHA512,
} cert_digest_algorithm_t;

/** Default certificate signature digest (SHA-384). */
#define CERT_DIGEST_DEFAULT CERT_DIGEST_SHA384

/** Opaque X.509 v3 certificate builder. */
typedef struct cert_builder cert_builder_t;

/**
 * Allocate an empty v3 builder.
 *
 * Defaults are a self-signed issuer, 3650-day validity and 16 random serial
 * bytes when none is set.  Release with cert_builder_free().
 *
 * @return the new builder, or NULL when allocation fails.
 */
cert_builder_t *cert_builder_new(void);

/** Release a builder and everything it owns.  NULL is a no-op. */
void cert_builder_free(cert_builder_t *builder);

/**
 * Set the serial number.
 *
 * Must be positive, at most 20 bytes, and must not have the high bit set when
 * 20 bytes long.  NULL with length zero clears it and restores the random
 * default.
 *
 * @return true on success; false on invalid input or allocation failure.
 */
bool cert_builder_set_serial(cert_builder_t *builder,
					   const unsigned char *serial,
					   size_t serial_length);

/**
 * Set the subject distinguished name.
 *
 * Accepts "CN=Example,O=AnyCA,C=CN" or a leading '/' with '/' separators;
 * RFC 2253 backslash escapes are supported.  The string is parsed and copied.
 *
 * @return true on success; false on invalid input or an invalid name.
 */
bool cert_builder_set_subject(cert_builder_t *builder,
					    const char *subject);

/**
 * Set the subject distinguished name from a DER-encoded X.509 Name.
 *
 * The name is copied exactly, preserving attribute types and string
 * encodings.  The buffer must contain exactly one Name.
 *
 * @return true on success; false on invalid input or decode error.
 */
bool cert_builder_set_subject_der(cert_builder_t *builder,
						const unsigned char *der,
						size_t length);

/**
 * Set the issuer distinguished name without an issuer certificate.
 *
 * The issuer defaults to the subject when unset.  Use
 * cert_builder_set_issuer_certificate() instead when the signing key differs
 * from the subject key, so the issuer key and signature are checked.
 */
bool cert_builder_set_issuer(cert_builder_t *builder,
					   const char *issuer);

/**
 * Set the issuer from a DER-encoded CA certificate.
 *
 * The issuer name comes from the certificate subject; the certificate is
 * retained to validate the assembled signature and must be a CA.
 */
bool cert_builder_set_issuer_certificate(
	cert_builder_t *builder, const unsigned char *der, size_t length);

/**
 * Set the validity period.
 *
 * not_before is Unix time; zero selects now.  validity_days zero selects the
 * 3650-day default.
 */
bool cert_builder_set_validity(cert_builder_t *builder,
					     int64_t not_before,
					     uint32_t validity_days);

/**
 * Set the subject public key from RSA key material.
 *
 * modulus and exponent are unsigned big-endian integers; the key is encoded
 * as a SubjectPublicKeyInfo and copied.
 */
bool cert_builder_set_rsa_public_key(
	cert_builder_t *builder, const unsigned char *modulus,
	size_t modulus_length, const unsigned char *exponent,
	size_t exponent_length);

/**
 * Set the subject public key from EC key material.
 *
 * ec_params is the DER-encoded namedCurve OID; ec_point is the uncompressed
 * EC point without the PKCS #11 OCTET STRING wrapper.  The key is encoded as
 * a SubjectPublicKeyInfo and copied.
 */
bool cert_builder_set_ec_public_key(
	cert_builder_t *builder, const unsigned char *ec_params,
	size_t ec_params_length, const unsigned char *ec_point,
	size_t ec_point_length);

/**
 * Set the subject public key from raw ML-DSA key material.
 *
 * key is the raw public key (the PKCS #11 CKA_VALUE), encoded in a
 * SubjectPublicKeyInfo whose algorithm OID is selected by parameter_set.
 */
bool cert_builder_set_ml_dsa_public_key(
	cert_builder_t *builder, cert_ml_dsa_parameter_set_t parameter_set,
	const unsigned char *key, size_t key_length);

/**
 * Set the subject public key from a DER-encoded SubjectPublicKeyInfo.
 *
 * The buffer must contain exactly one SPKI.
 */
bool cert_builder_set_public_key_der(
	cert_builder_t *builder, const unsigned char *der, size_t length);

/**
 * Add an arbitrary extension.
 *
 * der is the extension value contents, i.e. the extnValue OCTET STRING
 * payload without its tag and length; it may be NULL when length is zero.
 * oid is numeric or a known OpenSSL name.
 */
bool cert_builder_add_extension(cert_builder_t *builder,
					      const char *oid, bool critical,
					      const unsigned char *der,
					      size_t length);

/**
 * Add subjectKeyIdentifier (non-critical) from the subject public key, which
 * must be set first.
 */
bool cert_builder_add_subject_key_identifier(
	cert_builder_t *builder);

/**
 * Add authorityKeyIdentifier (non-critical) from the issuer certificate.
 *
 * Uses the issuer's subjectKeyIdentifier when present, otherwise the SHA-1 of
 * the issuer public-key bits.  The issuer certificate must be set first.
 */
bool cert_builder_add_authority_key_identifier(
	cert_builder_t *builder);

/**
 * Add basicConstraints (critical).
 *
 * path_length is emitted only when has_path_length is true, which requires
 * is_ca.
 */
bool cert_builder_add_basic_constraints(
	cert_builder_t *builder, bool is_ca, bool has_path_length,
	uint32_t path_length);

/** Add keyUsage (critical) from cert_key_usage_t bits; the mask must not be
 *  empty. */
bool cert_builder_add_key_usage(cert_builder_t *builder,
					      uint32_t bits);

/** Key usage bits understood by cert_builder_add_key_usage(). */
typedef enum cert_key_usage {
	CERT_KU_DIGITAL_SIGNATURE = 1U << 0,
	CERT_KU_NON_REPUDIATION = 1U << 1,
	CERT_KU_CONTENT_COMMITMENT = 1U << 1,
	CERT_KU_KEY_ENCIPHERMENT = 1U << 2,
	CERT_KU_DATA_ENCIPHERMENT = 1U << 3,
	CERT_KU_KEY_AGREEMENT = 1U << 4,
	CERT_KU_KEY_CERT_SIGN = 1U << 5,
	CERT_KU_CRL_SIGN = 1U << 6,
	CERT_KU_ENCIPHER_ONLY = 1U << 7,
	CERT_KU_DECIPHER_ONLY = 1U << 8,
} cert_key_usage_t;

/** Add extendedKeyUsage (non-critical) from count >= 1 OID strings. */
bool cert_builder_add_extended_key_usage(
	cert_builder_t *builder, const char *const *oids, size_t count);

/** One certificate policy for cert_builder_add_certificate_policies(). */
typedef struct cert_policy {
	/** Policy OID, numeric or a known OpenSSL name. */
	const char *oid;
	/** Optional CPS URI qualifier; NULL or empty omits the qualifier. */
	const char *cps_uri;
} cert_policy_t;

/**
 * Add certificatePolicies (non-critical).
 *
 * Each policy becomes a PolicyInformation with its OID and, when cps_uri is
 * set, an id-qt-cps qualifier.  count must be at least one.
 */
bool cert_builder_add_certificate_policies(
	cert_builder_t *builder, const cert_policy_t *policies, size_t count);

/**
 * Add authorityInfoAccess (non-critical).
 *
 * issuer URIs become id-ad-caIssuers access descriptions and OCSP URIs
 * id-ad-OCSP descriptions, all as URI GeneralNames.  Nothing is added when
 * both counts are zero.
 */
bool cert_builder_add_authority_info_access(
	cert_builder_t *builder, const char *const *issuer_uris,
	size_t issuer_uris_count, const char *const *ocsp_uris,
	size_t ocsp_uris_count);

/**
 * Add cRLDistributionPoints (non-critical) as one DistributionPoint with URI
 * fullNames.  Nothing is added when count is zero.
 */
bool cert_builder_add_crl_distribution_points(
	cert_builder_t *builder, const char *const *uris, size_t count);

/**
 * DER-encode the TBSCertificate to be signed by the caller.
 *
 * The result is the exact input for the signing operation; pass it and the
 * signature to cert_builder_assemble().  When no serial was set, 16 random
 * bytes are generated.
 *
 * @param tbs receives the DER encoding; release with cert_blob_free().
 */
bool cert_builder_tbs(const cert_builder_t *builder,
				    cert_signature_scheme_t scheme,
				    cert_digest_algorithm_t digest,
				    cert_blob_t *tbs);

/**
 * Assemble and DER-encode the certificate from a signed TBS.
 *
 * tbs must be the exact output of cert_builder_tbs() for this builder,
 * scheme and digest.  signature uses the signer's raw form: PKCS #1 v1.5
 * bytes for RSA, r || s for ECDSA.  The result is re-parsed and its signature
 * verified before it is returned.
 *
 * @param certificate receives the DER encoding; release with
 *                    cert_blob_free().
 */
bool cert_builder_assemble(
	const cert_builder_t *builder, cert_signature_scheme_t scheme,
	cert_digest_algorithm_t digest, const unsigned char *tbs,
	size_t tbs_length, const unsigned char *signature,
	size_t signature_length, cert_blob_t *certificate);

/** Release a blob returned by cert_builder_tbs() or cert_builder_assemble(). */
void cert_blob_free(cert_blob_t *certificate);

/** Opaque PKCS #10 certificate signing request. */
typedef struct cert_request cert_request_t;

/**
 * Load and verify a PKCS #10 request from a DER or PEM file.
 *
 * The request self-signature is verified, checking possession of the subject
 * key.  Release the result with cert_request_free().
 *
 * @return the request, or NULL when the file cannot be read, the request is
 *         malformed or its signature is invalid.
 */
cert_request_t *cert_request_load_file(const char *path);

/** Release a request.  NULL is a no-op. */
void cert_request_free(cert_request_t *request);

/** Copy the request subject into a builder as DER, preserving attribute
 *  types and string encodings. */
bool cert_request_set_subject(const cert_request_t *request,
					    cert_builder_t *builder);

/** Copy the request public key into a builder. */
bool cert_request_set_public_key(const cert_request_t *request,
					       cert_builder_t *builder);

/** Read the basicConstraints requested by a CSR; absent fields are false. */
bool cert_request_is_ca(const cert_request_t *request,
				      bool *present, bool *is_ca);

/** Number of requested extensions in the CSR. */
size_t cert_request_extension_count(const cert_request_t *request);

/**
 * Read one requested extension.
 *
 * value is the extension value contents, i.e. the extnValue OCTET STRING
 * payload.  oid, value and value_length remain valid until the request is
 * freed.
 */
bool cert_request_extension(const cert_request_t *request,
					  size_t index, const char **oid,
					  bool *critical,
					  const unsigned char **value,
					  size_t *value_length);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_CERT_H
