/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdbool.h>
#include <string.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>
#include <anyca/ca.h>
#include <anyca/core.h>
#include <anyca/hsm.h>
#include <anyca/ocsp.h>
#include <anyca/store.h>

#include "ocsp_responder.h"

/* HSM handle and signature algorithm used for one response. */
struct ocsp_signer {
	hsm_token_t *token;
	const char *key_label;
	const char *pin;
	hsm_sign_alg_t algorithm;
	ocsp_signature_algorithm_t signature_algorithm;
};

/* Response signature algorithms supported for each signer key type. */
static const ocsp_signature_algorithm_t ocsp_rsa_algorithms[] = {
	OCSP_SIGNATURE_RSA_SHA1,
	OCSP_SIGNATURE_RSA_SHA256,
	OCSP_SIGNATURE_RSA_SHA384,
	OCSP_SIGNATURE_RSA_SHA512,
};

static const ocsp_signature_algorithm_t ocsp_ecdsa_algorithms[] = {
	OCSP_SIGNATURE_ECDSA_SHA1,
	OCSP_SIGNATURE_ECDSA_SHA256,
	OCSP_SIGNATURE_ECDSA_SHA384,
	OCSP_SIGNATURE_ECDSA_SHA512,
};

static const ocsp_signature_algorithm_t ocsp_ml_dsa_44_algorithms[] = {
	OCSP_SIGNATURE_ML_DSA_44,
};

static const ocsp_signature_algorithm_t ocsp_ml_dsa_65_algorithms[] = {
	OCSP_SIGNATURE_ML_DSA_65,
};

static const ocsp_signature_algorithm_t ocsp_ml_dsa_87_algorithms[] = {
	OCSP_SIGNATURE_ML_DSA_87,
};

/* Map a response signature algorithm to the matching HSM sign algorithm. */
static bool _ocsp_hsm_algorithm(ocsp_signature_algorithm_t algorithm,
				hsm_sign_alg_t *hsm)
{
	switch (algorithm) {
	case OCSP_SIGNATURE_RSA_SHA1:
		*hsm = HSM_SIGN_RSA_PKCS1_SHA1;
		return true;
	case OCSP_SIGNATURE_RSA_SHA256:
		*hsm = HSM_SIGN_RSA_PKCS1_SHA256;
		return true;
	case OCSP_SIGNATURE_RSA_SHA384:
		*hsm = HSM_SIGN_RSA_PKCS1_SHA384;
		return true;
	case OCSP_SIGNATURE_RSA_SHA512:
		*hsm = HSM_SIGN_RSA_PKCS1_SHA512;
		return true;
	case OCSP_SIGNATURE_ECDSA_SHA1:
		*hsm = HSM_SIGN_ECDSA_SHA1;
		return true;
	case OCSP_SIGNATURE_ECDSA_SHA256:
		*hsm = HSM_SIGN_ECDSA_SHA256;
		return true;
	case OCSP_SIGNATURE_ECDSA_SHA384:
		*hsm = HSM_SIGN_ECDSA_SHA384;
		return true;
	case OCSP_SIGNATURE_ECDSA_SHA512:
		*hsm = HSM_SIGN_ECDSA_SHA512;
		return true;
	case OCSP_SIGNATURE_ML_DSA_44:
		*hsm = HSM_SIGN_ML_DSA_44;
		return true;
	case OCSP_SIGNATURE_ML_DSA_65:
		*hsm = HSM_SIGN_ML_DSA_65;
		return true;
	case OCSP_SIGNATURE_ML_DSA_87:
		*hsm = HSM_SIGN_ML_DSA_87;
		return true;
	default:
		return false;
	}
}

/* Look up the CA whose OCSP endpoint matches endpoint[0..endpoint_len). */
static ca_t *_ocsp_find_ca(const char *endpoint, size_t endpoint_len)
{
	char *name;
	ca_t *ca;

	if (endpoint == nullptr || endpoint_len == 0
	    || endpoint_len == SIZE_MAX)
		return nullptr;

	name = osal_malloc(endpoint_len + 1);
	if (name == nullptr) {
		LOGE("Failed to allocate the OCSP endpoint");
		return nullptr;
	}
	memcpy(name, endpoint, endpoint_len);
	name[endpoint_len] = '\0';

	ca = core_ca_by_ocsp_endpoint(name);
	if (ca == nullptr) {
		/*
		 * The endpoint comes straight from the request URI.  Replace
		 * control characters before logging so a crafted path cannot
		 * inject terminal escape sequences into the log.
		 */
		for (size_t i = 0; i < endpoint_len; i++) {
			unsigned char c = (unsigned char) name[i];

			if (c < 0x20 || c == 0x7f)
				name[i] = '?';
		}
		LOGW("No CA matches the OCSP endpoint \"%s\"", name);
	}

	osal_free(name);
	return ca;
}

/*
 * Select the response signature algorithm from the request preference or the
 * signer key type, and check that the signer is authorized for this CA.
 */
static ocsp_responder_status_t _ocsp_signer_init(const ca_t *ca,
						 const ocsp_request_t *request,
						 struct ocsp_signer *signer)
{
	const ocsp_signature_algorithm_t *supported;
	ocsp_signature_algorithm_t algorithm;
	ocsp_signature_algorithm_t default_algorithm;
	ocsp_signer_type_t signer_type;
	size_t supported_count;

	if (ca->ocsp_signer_certificate == nullptr
	    || ca->ocsp_signer_key_label == nullptr) {
		LOGE("CA %s has no OCSP signing certificate or key label",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		return OCSP_RESPONDER_ERR_SIGNER;
	}

	if (!ca_ocsp_signer_authorized(ca)) {
		LOGE("OCSP signing certificate is not authorized for CA %s",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		return OCSP_RESPONDER_ERR_SIGNER;
	}

	signer->token = core_ca_ocsp_signer_token(ca);
	if (signer->token == nullptr) {
		LOGE("No OCSP signer token for CA %s",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		return OCSP_RESPONDER_ERR_SIGNER;
	}
	signer->key_label = ca->ocsp_signer_key_label;
	signer->pin = ca->ocsp_signer_pin;

	if (ocsp_get_signer_type(ca->ocsp_signer_certificate, &signer_type)
	    != OCSP_OK) {
		LOGE("Unsupported OCSP signer certificate for CA %s",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		return OCSP_RESPONDER_ERR_SIGNER;
	}

	switch (signer_type) {
	case OCSP_SIGNER_RSA:
		supported = ocsp_rsa_algorithms;
		supported_count =
			sizeof ocsp_rsa_algorithms / sizeof ocsp_rsa_algorithms[0];
		break;
	case OCSP_SIGNER_ECDSA:
		supported = ocsp_ecdsa_algorithms;
		supported_count = sizeof ocsp_ecdsa_algorithms
			/ sizeof ocsp_ecdsa_algorithms[0];
		break;
	case OCSP_SIGNER_ML_DSA_44:
		supported = ocsp_ml_dsa_44_algorithms;
		supported_count = sizeof ocsp_ml_dsa_44_algorithms
			/ sizeof ocsp_ml_dsa_44_algorithms[0];
		break;
	case OCSP_SIGNER_ML_DSA_65:
		supported = ocsp_ml_dsa_65_algorithms;
		supported_count = sizeof ocsp_ml_dsa_65_algorithms
			/ sizeof ocsp_ml_dsa_65_algorithms[0];
		break;
	case OCSP_SIGNER_ML_DSA_87:
		supported = ocsp_ml_dsa_87_algorithms;
		supported_count = sizeof ocsp_ml_dsa_87_algorithms
			/ sizeof ocsp_ml_dsa_87_algorithms[0];
		break;
	default:
		return OCSP_RESPONDER_ERR_SIGNER;
	}

	default_algorithm = ocsp_default_signature_algorithm(signer_type);
	algorithm = ocsp_request_preferred_signature(request, supported,
						     supported_count);
	if (algorithm == OCSP_SIGNATURE_DEFAULT)
		algorithm = default_algorithm;

	if (algorithm == OCSP_SIGNATURE_DEFAULT
	    || !_ocsp_hsm_algorithm(algorithm, &signer->algorithm)) {
		LOGE("No supported OCSP signature algorithm for CA %s",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		return OCSP_RESPONDER_ERR_SIGNER;
	}
	signer->signature_algorithm = algorithm;

	return OCSP_RESPONDER_OK;
}

/* ocsp_sign_cb implementation: sign the ResponseData with the HSM key. */
static ocsp_result_t _ocsp_sign(void *context, const unsigned char *tbs,
				size_t tbs_length, ocsp_signature_t *signature)
{
	struct ocsp_signer *signer = context;
	const struct hsm_error *error;
	unsigned char *raw = nullptr;
	size_t raw_length = 0;
	hsm_status_t hsm_status;

	signature->data = nullptr;
	signature->length = 0;

	hsm_status = hsm_sign_with_pin(signer->token, signer->algorithm,
				       signer->key_label, signer->pin, tbs,
				       tbs_length, nullptr, 0,
				       &raw_length);
	if (hsm_status != HSM_OK || raw_length == 0) {
		error = hsm_get_last_error();
		LOGE("Failed to query the OCSP signature size: %s: %s",
		     hsm_status_to_string(hsm_status), error->message);
		return OCSP_ERR_SIGN;
	}

	raw = osal_malloc(raw_length);
	if (raw == nullptr) {
		LOGE("Failed to allocate the OCSP signature buffer");
		return OCSP_ERR_MEMORY;
	}

	hsm_status = hsm_sign_with_pin(signer->token, signer->algorithm,
				       signer->key_label, signer->pin, tbs,
				       tbs_length, raw, raw_length,
				       &raw_length);
	if (hsm_status != HSM_OK) {
		error = hsm_get_last_error();
		LOGE("Failed to sign the OCSP response: %s: %s",
		     hsm_status_to_string(hsm_status), error->message);
		osal_free(raw);
		return OCSP_ERR_SIGN;
	}

	signature->data = raw;
	signature->length = raw_length;
	return OCSP_OK;
}

/* Outcome of resolving one query. */
typedef enum ocsp_query_result {
	OCSP_QUERY_OK,
	OCSP_QUERY_UNAUTHORIZED,
	OCSP_QUERY_MALFORMED,
	OCSP_QUERY_ERROR,
} ocsp_query_result_t;

/*
 * Resolve one query against the CA's store: not issued -> UNKNOWN, revoked
 * -> REVOKED, otherwise GOOD.  A CertID with no issuer key hash (certutil
 * with an explicit URL) yields UNAUTHORIZED for the whole response.
 * MALFORMED means the request parser accepted the query but a CertID or
 * serial field is unusable; ERROR means a store or memory failure.  The
 * caller must fail the response instead of guessing in either case.
 */
static ocsp_query_result_t _ocsp_query_status(const ocsp_request_t *request,
					      size_t index, const ca_t *ca,
					      store_ca_id_t ca_id,
					      ocsp_cert_status_info_t *status)
{
	unsigned char *serial = nullptr;
	size_t serial_length = 0;
	ocsp_cert_id_t cert_id;
	store_revocation_t revocation = { 0 };
	ocsp_result_t serial_status;
	store_result_t result;

	status->status = OCSP_CERT_STATUS_UNKNOWN;
	status->revoked_at = 0;
	status->reason = 0;

	if (ocsp_request_cert_id(request, index, &cert_id) != OCSP_OK) {
		LOGW("OCSP query %zu has no valid CertID", index);
		return OCSP_QUERY_MALFORMED;
	}
	if (cert_id.issuer_key_hash_length == 0) {
		LOGW("OCSP query %zu has no issuer key hash; unauthorized",
		     index);
		return OCSP_QUERY_UNAUTHORIZED;
	}
	if (!ca_issuer_matches(ca, cert_id.hash_nid,
			       cert_id.issuer_name_hash,
			       cert_id.issuer_name_hash_length,
			       cert_id.issuer_key_hash,
			       cert_id.issuer_key_hash_length))
		return OCSP_QUERY_OK;

	serial_status = ocsp_request_serial(request, index, &serial,
					    &serial_length);
	if (serial_status != OCSP_OK) {
		if (serial_status == OCSP_ERR_MEMORY) {
			LOGE("Failed to allocate the OCSP certificate serial");
			return OCSP_QUERY_ERROR;
		}
		LOGW("OCSP query %zu has no valid certificate serial", index);
		return OCSP_QUERY_MALFORMED;
	}

	result = store_certificate_exists(ca_id, serial, serial_length);
	if (result == STORE_ERR_NOT_FOUND) {
		osal_free(serial);
		return OCSP_QUERY_OK;
	}
	if (result != STORE_OK) {
		LOGE("Failed to look up an issued certificate: %d",
		     (int) result);
		osal_free(serial);
		return OCSP_QUERY_ERROR;
	}

	result = store_revocation_get(ca_id, serial, serial_length, &revocation);
	osal_free(serial);
	if (result == STORE_OK) {
		status->status = OCSP_CERT_STATUS_REVOKED;
		status->revoked_at = revocation.revoked_at;
		status->reason = revocation.reason;
		store_revocation_free(&revocation);
		return OCSP_QUERY_OK;
	}
	if (result == STORE_ERR_NOT_FOUND) {
		status->status = OCSP_CERT_STATUS_GOOD;
		return OCSP_QUERY_OK;
	}

	LOGE("Failed to look up a revocation record: %d", (int) result);
	return OCSP_QUERY_ERROR;
}

ocsp_responder_status_t ocsp_responder_generate(const char *endpoint,
						size_t endpoint_len,
						const unsigned char *req,
						size_t req_len,
						unsigned char **resp,
						size_t *resp_len)
{
	ocsp_request_t *request = nullptr;
	ocsp_cert_status_info_t *statuses = nullptr;
	struct ocsp_signer signer = { 0 };
	ocsp_response_params_t params = { 0 };
	ocsp_result_t request_status;
	ocsp_result_t generate_status;
	ocsp_responder_status_t result = OCSP_RESPONDER_ERR_ARGUMENT;
	store_ca_id_t ca_id;
	size_t count;
	ca_t *ca;
	bool session_entered = false;

	if (resp == nullptr || resp_len == nullptr)
		return OCSP_RESPONDER_ERR_ARGUMENT;
	*resp = nullptr;
	*resp_len = 0;

	if (endpoint == nullptr || endpoint_len == 0 || req == nullptr
	    || req_len == 0) {
		LOGE("Invalid OCSP responder arguments");
		return OCSP_RESPONDER_ERR_ARGUMENT;
	}

	/*
	 * The session covers the store lookups and the signing: its refresh may
	 * replace CA objects and close their token handles, and the CRL timer
	 * runs a session on another thread.  OCSP handling runs on the HTTP
	 * thread, so this does not reduce request concurrency.
	 */
	core_session_begin();
	session_entered = true;

	ca = _ocsp_find_ca(endpoint, endpoint_len);
	if (ca == nullptr) {
		result = OCSP_RESPONDER_ERR_CA_NOT_FOUND;
		goto done;
	}

	ca_id = core_ca_store_id(ca);
	if (ca_id == 0) {
		LOGE("CA %s has no store identity",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		result = OCSP_RESPONDER_ERR_UNKNOWN;
		goto done;
	}

	request_status = ocsp_request_parse(req, req_len, &request);
	if (request_status != OCSP_OK) {
		result = request_status == OCSP_ERR_REQUEST_DECODE
			? OCSP_RESPONDER_ERR_REQUEST_DECODE
			: OCSP_RESPONDER_ERR_UNKNOWN;
		goto done;
	}

	count = ocsp_request_query_count(request);
	if (count == 0) {
		LOGE("OCSP request contains no queries");
		result = OCSP_RESPONDER_ERR_REQUEST_DECODE;
		goto done;
	}

	statuses = osal_calloc(count, sizeof *statuses);
	if (statuses == nullptr) {
		LOGE("Failed to allocate the OCSP status list");
		result = OCSP_RESPONDER_ERR_UNKNOWN;
		goto done;
	}

	for (size_t i = 0; i < count; i++) {
		ocsp_query_result_t query =
			_ocsp_query_status(request, i, ca, ca_id, &statuses[i]);

		if (query == OCSP_QUERY_UNAUTHORIZED) {
			result = OCSP_RESPONDER_ERR_UNAUTHORIZED;
			goto done;
		}
		if (query == OCSP_QUERY_MALFORMED) {
			result = OCSP_RESPONDER_ERR_REQUEST_DECODE;
			goto done;
		}
		if (query == OCSP_QUERY_ERROR) {
			result = OCSP_RESPONDER_ERR_UNKNOWN;
			goto done;
		}
		LOGD("OCSP query %zu: certificate %s", i,
		     statuses[i].status == OCSP_CERT_STATUS_GOOD ? "GOOD"
		     : statuses[i].status == OCSP_CERT_STATUS_REVOKED
			     ? "REVOKED"
			     : "UNKNOWN");
	}

	result = _ocsp_signer_init(ca, request, &signer);
	if (result != OCSP_RESPONDER_OK)
		goto done;

	params.signer_certificate = ca->ocsp_signer_certificate;
	params.cert_statuses = statuses;
	params.cert_status_count = count;
	params.next_update_minutes = ca->ocsp_update_period_min;
	params.signature_algorithm = signer.signature_algorithm;
	params.sign = _ocsp_sign;
	params.sign_context = &signer;

	generate_status =
		ocsp_generate_response(request, &params, resp, resp_len);
	switch (generate_status) {
	case OCSP_OK:
		result = OCSP_RESPONDER_OK;
		break;
	case OCSP_ERR_REQUEST_DECODE:
		result = OCSP_RESPONDER_ERR_REQUEST_DECODE;
		break;
	case OCSP_ERR_SIGN:
		result = OCSP_RESPONDER_ERR_SIGN;
		break;
	case OCSP_ERR_RESPONSE_ENCODE:
		result = OCSP_RESPONDER_ERR_RESPONSE_ENCODE;
		break;
	default:
		result = OCSP_RESPONDER_ERR_UNKNOWN;
		break;
	}

done:
	if (session_entered)
		core_session_end();
	osal_free(statuses);
	ocsp_request_free(request);
	return result;
}

/* Map a wire error to the OCSPResponse responseStatus value. */
static ocsp_response_status_t
_ocsp_error_to_response_status(ocsp_responder_wire_error_t error)
{
	switch (error) {
	case OCSP_RESPONDER_WIRE_MALFORMED_REQUEST:
		return OCSP_RESP_STATUS_MALFORMED_REQUEST;
	case OCSP_RESPONDER_WIRE_UNAUTHORIZED:
		return OCSP_RESP_STATUS_UNAUTHORIZED;
	case OCSP_RESPONDER_WIRE_INTERNAL_ERROR:
	default:
		return OCSP_RESP_STATUS_INTERNAL_ERROR;
	}
}

ocsp_responder_status_t ocsp_responder_generate_error(
	ocsp_responder_wire_error_t error, unsigned char **resp, size_t *resp_len)
{
	if (resp == nullptr || resp_len == nullptr) {
		LOGE("Invalid OCSP error response arguments");
		return OCSP_RESPONDER_ERR_ARGUMENT;
	}

	switch (ocsp_generate_error_response(
		_ocsp_error_to_response_status(error), resp, resp_len)) {
	case OCSP_OK:
		return OCSP_RESPONDER_OK;
	case OCSP_ERR_MEMORY:
		return OCSP_RESPONDER_ERR_UNKNOWN;
	default:
		return OCSP_RESPONDER_ERR_RESPONSE_ENCODE;
	}
}
