/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_SERVER_OCSP_RESPONDER_H
#define ANYCA_SERVER_OCSP_RESPONDER_H

/**
 * @file ocsp_responder.h
 * @brief OCSP responder: request -> CA -> store status -> signed response.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** OCSP responder result.  OCSP_RESPONDER_OK is zero. */
typedef enum ocsp_responder_status {
	OCSP_RESPONDER_OK = 0,
	OCSP_RESPONDER_ERR_ARGUMENT,
	OCSP_RESPONDER_ERR_REQUEST_DECODE,
	OCSP_RESPONDER_ERR_CA_NOT_FOUND,
	OCSP_RESPONDER_ERR_UNAUTHORIZED,
	OCSP_RESPONDER_ERR_SIGNER,
	OCSP_RESPONDER_ERR_SIGN,
	OCSP_RESPONDER_ERR_RESPONSE_ENCODE,
	OCSP_RESPONDER_ERR_UNKNOWN
} ocsp_responder_status_t;

/** Error reported to an OCSP client in an OCSPResponse. */
typedef enum ocsp_responder_wire_error {
	OCSP_RESPONDER_WIRE_MALFORMED_REQUEST = 0,
	OCSP_RESPONDER_WIRE_INTERNAL_ERROR,
	OCSP_RESPONDER_WIRE_UNAUTHORIZED,
} ocsp_responder_wire_error_t;

/**
 * Build an OCSPResponse carrying only an error responseStatus and no signed
 * ResponseData.
 *
 * @param resp receives an osal_malloc()ed DER response; release with
 *             osal_free().
 */
ocsp_responder_status_t ocsp_responder_generate_error(
	ocsp_responder_wire_error_t error, unsigned char **resp,
	size_t *resp_len);

/**
 * Generate a DER-encoded OCSP response for a request from endpoint.
 *
 * The endpoint selects the CA.  Each query is answered GOOD, REVOKED or
 * UNKNOWN from the store; a CertID whose issuer hashes do not match the CA is
 * UNKNOWN, while a missing issuer key hash makes the response UNAUTHORIZED.
 * Malformed requests get MALFORMED_REQUEST, and a store failure fails the
 * whole response.  The response is signed through the HSM with the request's
 * preferred signature algorithm when the signer supports it.
 *
 * @param endpoint endpoint path segment, e.g. "ca-good"; need not be
 *                 NUL-terminated and must not contain '/'.
 * @param resp     receives an osal_malloc()ed DER response; release with
 *                 osal_free().
 */
ocsp_responder_status_t ocsp_responder_generate(
	const char *endpoint, size_t endpoint_len, const unsigned char *req,
	size_t req_len, unsigned char **resp, size_t *resp_len);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_SERVER_OCSP_RESPONDER_H
