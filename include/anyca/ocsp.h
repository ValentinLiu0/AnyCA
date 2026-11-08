/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OCSP_H
#define ANYCA_OCSP_H

/**
 * @file ocsp.h
 * @brief OCSP request inspection and response generation (RFC 6960).
 *
 * Parses DER requests, exposes CertIDs and serial numbers, and builds signed
 * responses.  The caller supplies certificate statuses and the signing
 * operation (normally the HSM).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Opaque OpenSSL type used by this interface.  Declaring it here keeps the
 * OpenSSL headers out of every consumer of ocsp.h.
 */
typedef struct x509_st X509;

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum digest size held by an ocsp_cert_id_t (EVP_MAX_MD_SIZE). */
#define OCSP_MAX_HASH_SIZE 64

/** OCSP operation result.  OCSP_OK is zero, failures are negative. */
typedef enum ocsp_result {
	OCSP_OK = 0,
	OCSP_ERR_ARGUMENT = -1,
	OCSP_ERR_REQUEST_DECODE = -2,
	OCSP_ERR_RESPONSE_ENCODE = -3,
	OCSP_ERR_SIGN = -4,
	OCSP_ERR_MEMORY = -5,
} ocsp_result_t;

/** Certificate status reported in a SingleResponse. */
typedef enum ocsp_cert_status {
	OCSP_CERT_STATUS_GOOD = 0,
	OCSP_CERT_STATUS_REVOKED,
	OCSP_CERT_STATUS_UNKNOWN,
} ocsp_cert_status_t;

/** Status of one query, including revocation details for REVOKED. */
typedef struct ocsp_cert_status_info {
	ocsp_cert_status_t status;
	/** revocationTime as Unix time; used only when status is REVOKED. */
	int64_t revoked_at;
	/** RFC 5280 CRLReason; 0 (unspecified) omits the reason. */
	int reason;
} ocsp_cert_status_info_t;

/** OCSPResponse responseStatus values (RFC 6960, section 4.2.1). */
typedef enum ocsp_response_status {
	OCSP_RESP_STATUS_SUCCESSFUL = 0,
	OCSP_RESP_STATUS_MALFORMED_REQUEST = 1,
	OCSP_RESP_STATUS_INTERNAL_ERROR = 2,
	OCSP_RESP_STATUS_TRY_LATER = 3,
	OCSP_RESP_STATUS_SIG_REQUIRED = 5,
	OCSP_RESP_STATUS_UNAUTHORIZED = 6,
} ocsp_response_status_t;

/** Parsed OCSP request; created by ocsp_request_parse(). */
typedef struct ocsp_request ocsp_request_t;

/**
 * Parse and validate a DER-encoded OCSP request; a request with no queries is
 * rejected.  Validation covers the version (v1 only), nonce length (RFC
 * 8954), unrecognized critical extensions, and every CertID and serial.
 * Release with ocsp_request_free().
 */
ocsp_result_t ocsp_request_parse(const unsigned char *req,
					       size_t size,
					       ocsp_request_t **request);

/** Release a request returned by ocsp_request_parse().  NULL is a no-op. */
void ocsp_request_free(ocsp_request_t *request);

/** Number of single requests (queries) in request; 0 when request is NULL. */
size_t
ocsp_request_query_count(const ocsp_request_t *request);

/**
 * CertID fields of one query.  Hashes are copied into fixed buffers, so the
 * structure owns no memory; use ocsp_request_serial() for the serial.
 */
typedef struct ocsp_cert_id {
	/** OpenSSL NID of the CertID hash algorithm; NID_undef when unknown. */
	int hash_nid;
	unsigned char issuer_name_hash[OCSP_MAX_HASH_SIZE];
	size_t issuer_name_hash_length;
	/** Empty (length 0) when the request omits the issuer key hash. */
	unsigned char issuer_key_hash[OCSP_MAX_HASH_SIZE];
	size_t issuer_key_hash_length;
} ocsp_cert_id_t;

/** Copy the CertID fields of query index into cert_id, which is zeroed
 *  first.  An empty issuer key hash yields length 0. */
ocsp_result_t ocsp_request_cert_id(const ocsp_request_t *request,
						 size_t index,
						 ocsp_cert_id_t *cert_id);

/**
 * Copy the serialNumber of query index as canonical big-endian bytes: the
 * DER INTEGER value without tag, length or sign padding; zero is one 0x00
 * byte.  Release the buffer with osal_free().
 */
ocsp_result_t ocsp_request_serial(const ocsp_request_t *request,
						size_t index,
						unsigned char **serial,
						size_t *serial_length);

/** Signing key kind; selects the response signature algorithm. */
typedef enum ocsp_signer_type {
	OCSP_SIGNER_RSA = 0,
	OCSP_SIGNER_ECDSA,
	OCSP_SIGNER_ML_DSA_44,
	OCSP_SIGNER_ML_DSA_65,
	OCSP_SIGNER_ML_DSA_87,
} ocsp_signer_type_t;

/** Signature algorithm used to sign an OCSP response. */
typedef enum ocsp_signature_algorithm {
	/** Use the default for the signer key type (SHA-256). */
	OCSP_SIGNATURE_DEFAULT = 0,
	OCSP_SIGNATURE_RSA_SHA1,
	OCSP_SIGNATURE_RSA_SHA256,
	OCSP_SIGNATURE_RSA_SHA384,
	OCSP_SIGNATURE_RSA_SHA512,
	OCSP_SIGNATURE_ECDSA_SHA1,
	OCSP_SIGNATURE_ECDSA_SHA256,
	OCSP_SIGNATURE_ECDSA_SHA384,
	OCSP_SIGNATURE_ECDSA_SHA512,
	OCSP_SIGNATURE_ML_DSA_44,
	OCSP_SIGNATURE_ML_DSA_65,
	OCSP_SIGNATURE_ML_DSA_87,
} ocsp_signature_algorithm_t;

/** Determine the signing key kind from a certificate public key. */
ocsp_result_t ocsp_get_signer_type(const X509 *certificate,
						 ocsp_signer_type_t *type);

/** Default response signature algorithm for a signer key type: SHA-256, or
 *  OCSP_SIGNATURE_DEFAULT when the type is unknown. */
ocsp_signature_algorithm_t
ocsp_default_signature_algorithm(ocsp_signer_type_t signer_type);

/**
 * Select the first client-preferred signature algorithm that is supported.
 *
 * Reads the id-pkix-ocsp-pref-sig-algs request extension (RFC 6960 section
 * 4.4.7).  Returns OCSP_SIGNATURE_DEFAULT when the extension is absent or
 * malformed, or when none of its algorithms is in supported[].
 */
ocsp_signature_algorithm_t
ocsp_request_preferred_signature(
	const ocsp_request_t *request,
	const ocsp_signature_algorithm_t *supported, size_t supported_count);

/**
 * Signature produced by an ocsp_sign_cb.
 *
 * data is allocated by the callback with osal_malloc() and released by
 * ocsp_generate_response().  ECDSA callbacks return raw PKCS #11 r || s,
 * which is converted to ASN.1 DER.
 */
typedef struct ocsp_signature {
	unsigned char *data;
	size_t length;
} ocsp_signature_t;

/**
 * Sign the DER-encoded ResponseData of a BasicOCSPResponse.
 *
 * The callback stores the signature and returns OCSP_OK.  A buffer left in
 * signature on failure is released by ocsp_generate_response().
 */
typedef ocsp_result_t (*ocsp_sign_cb)(void *context,
				      const unsigned char *tbs, size_t tbs_length,
				      ocsp_signature_t *signature);

/** Inputs for building a complete OCSP response. */
typedef struct ocsp_response_params {
	/** Certificate whose subject is used as the byName ResponderID. */
	const X509 *signer_certificate;

	/**
	 * Status of every single request, in request order; the count must
	 * match the request.  A REVOKED entry needs revoked_at > 0 and a
	 * CRLReason in 0..10.
	 */
	const ocsp_cert_status_info_t *cert_statuses;
	size_t cert_status_count;

	/** nextUpdate = now + this many minutes; 0 omits nextUpdate. */
	uint32_t next_update_minutes;

	/**
	 * Signature algorithm; OCSP_SIGNATURE_DEFAULT selects SHA-256 for
	 * the signer key type.  The algorithm must match the signer
	 * certificate's key type.
	 */
	ocsp_signature_algorithm_t signature_algorithm;

	/** Signing operation for the ResponseData. */
	ocsp_sign_cb sign;
	void *sign_context;
} ocsp_response_params_t;

/**
 * Render an OCSP request as human-readable text.  The returned string is
 * osal_malloc()ed; release it with osal_free().
 */
char *ocsp_request_to_string(const unsigned char *req,
				       size_t size);

/**
 * Generate a complete DER-encoded OCSP response for a parsed request.
 *
 * Builds one SingleResponse per query from params->cert_statuses, signs the
 * ResponseData with params->sign and the selected algorithm, and echoes the
 * request nonce when present.
 *
 * @param resp receives an osal_malloc()ed DER buffer; release with
 *             osal_free().  NULL on failure.
 */
ocsp_result_t ocsp_generate_response(
	const ocsp_request_t *request, const ocsp_response_params_t *params,
	unsigned char **resp, size_t *resp_size);

/**
 * Generate a DER-encoded OCSPResponse carrying only an error responseStatus
 * and no responseBytes.  The successful status is rejected.
 *
 * @param resp receives an osal_malloc()ed DER buffer; release with
 *             osal_free().  NULL on failure.
 */
ocsp_result_t ocsp_generate_error_response(
	ocsp_response_status_t response_status, unsigned char **resp,
	size_t *resp_size);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OCSP_H
