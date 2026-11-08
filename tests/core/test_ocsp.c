/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>
#include <anyca/ocsp.h>

#include "../test_support.h"
#include "test_suites.h"

static ocsp_result_t sign_callback(void *context, const unsigned char *tbs,
				   size_t tbs_length,
				   ocsp_signature_t *signature)
{
	unsigned char *raw = NULL;
	size_t raw_length = 0;

	if (!test_sign(context, tbs, tbs_length, &raw, &raw_length))
		return OCSP_ERR_SIGN;
	signature->data = osal_malloc(raw_length);
	if (signature->data == NULL) {
		OPENSSL_free(raw);
		return OCSP_ERR_MEMORY;
	}
	memcpy(signature->data, raw, raw_length);
	signature->length = raw_length;
	OPENSSL_free(raw);
	return OCSP_OK;
}

static unsigned char *make_request(X509 *leaf, X509 *ca, size_t *length)
{
	OCSP_REQUEST *request = OCSP_REQUEST_new();
	OCSP_CERTID *cert_id;
	unsigned char *der = NULL;
	int der_length;

	if (request == NULL)
		return NULL;
	cert_id = OCSP_cert_to_id(EVP_sha1(), leaf, ca);
	if (cert_id == NULL || OCSP_request_add0_id(request, cert_id) == NULL) {
		OCSP_CERTID_free(cert_id);
		OCSP_REQUEST_free(request);
		return NULL;
	}
	der_length = i2d_OCSP_REQUEST(request, &der);
	OCSP_REQUEST_free(request);
	if (der_length <= 0)
		return NULL;
	*length = (size_t) der_length;
	return der;
}

static void test_parse(void)
{
	EVP_PKEY *ca_key = test_rsa_key();
	EVP_PKEY *leaf_key = test_rsa_key();
	X509 *ca;
	X509 *leaf;
	unsigned char *der;
	size_t der_length = 0;
	ocsp_request_t *request = NULL;
	ocsp_cert_id_t cert_id;
	unsigned char *serial = NULL;
	size_t serial_length = 0;
	ocsp_signature_algorithm_t supported[] = {
		OCSP_SIGNATURE_RSA_SHA256
	};
	ocsp_signer_type_t signer_type;
	char *text;

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_key);
	ca = test_certificate(ca_key, NULL, NULL, 0x50, TEST_CERT_CA);
	leaf = test_certificate(leaf_key, ca, ca_key, 0x1234, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf);
	der = make_request(leaf, ca, &der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(der);

	CU_ASSERT_EQUAL(ocsp_request_parse(der, der_length, &request),
			OCSP_OK);
	CU_ASSERT_PTR_NOT_NULL_FATAL(request);
	CU_ASSERT_EQUAL(ocsp_request_query_count(request), 1);

	CU_ASSERT_EQUAL(ocsp_request_cert_id(request, 0, &cert_id), OCSP_OK);
	CU_ASSERT_EQUAL(cert_id.hash_nid, NID_sha1);
	CU_ASSERT_EQUAL(cert_id.issuer_name_hash_length, 20);
	CU_ASSERT_EQUAL(cert_id.issuer_key_hash_length, 20);

	CU_ASSERT_EQUAL(
		ocsp_request_serial(request, 0, &serial, &serial_length),
		OCSP_OK);
	CU_ASSERT_EQUAL(serial_length, 2);
	CU_ASSERT_EQUAL(serial[0], 0x12);
	CU_ASSERT_EQUAL(serial[1], 0x34);
	osal_free(serial);

	CU_ASSERT_EQUAL(ocsp_request_cert_id(request, 1, &cert_id),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(ocsp_request_cert_id(NULL, 0, &cert_id),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(ocsp_request_cert_id(request, 0, NULL),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(
		ocsp_request_serial(request, 1, &serial, &serial_length),
		OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(
		ocsp_request_serial(NULL, 0, &serial, &serial_length),
		OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(ocsp_request_serial(request, 0, NULL,
					    &serial_length),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(ocsp_request_query_count(NULL), 0);

	CU_ASSERT_EQUAL(ocsp_request_preferred_signature(
				request, supported,
				sizeof supported / sizeof supported[0]),
			OCSP_SIGNATURE_DEFAULT);
	CU_ASSERT_EQUAL(ocsp_request_preferred_signature(NULL, supported,
							 1),
			OCSP_SIGNATURE_DEFAULT);

	text = ocsp_request_to_string(der, der_length);
	CU_ASSERT_PTR_NOT_NULL(text);
	osal_free(text);

	CU_ASSERT_EQUAL(ocsp_get_signer_type(ca, &signer_type), OCSP_OK);
	CU_ASSERT_EQUAL(signer_type, OCSP_SIGNER_RSA);
	CU_ASSERT_EQUAL(ocsp_get_signer_type(NULL, &signer_type),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(ocsp_get_signer_type(ca, NULL),
			OCSP_ERR_ARGUMENT);

	{
		const unsigned char garbage[] = { 0x30, 0x00 };
		unsigned char *trailing = malloc(der_length + 1);

		CU_ASSERT_EQUAL(ocsp_request_parse(NULL, 0, &request),
				OCSP_ERR_ARGUMENT);
		CU_ASSERT_EQUAL(ocsp_request_parse(der, der_length, NULL),
				OCSP_ERR_ARGUMENT);
		CU_ASSERT_EQUAL(ocsp_request_parse(garbage,
						   sizeof garbage, &request),
				OCSP_ERR_REQUEST_DECODE);

		CU_ASSERT_PTR_NOT_NULL_FATAL(trailing);
		memcpy(trailing, der, der_length);
		trailing[der_length] = 0;
		CU_ASSERT_EQUAL(ocsp_request_parse(trailing,
						   der_length + 1, &request),
				OCSP_ERR_REQUEST_DECODE);
		free(trailing);
	}

	ocsp_request_free(request);
	ocsp_request_free(NULL);
	OPENSSL_free(der);
	X509_free(leaf);
	X509_free(ca);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(ca_key);
}

static void test_error_response(void)
{
	static const struct {
		ocsp_response_status_t status;
		unsigned char value;
	} cases[] = {
		{ OCSP_RESP_STATUS_MALFORMED_REQUEST, 1 },
		{ OCSP_RESP_STATUS_INTERNAL_ERROR, 2 },
		{ OCSP_RESP_STATUS_TRY_LATER, 3 },
		{ OCSP_RESP_STATUS_SIG_REQUIRED, 5 },
		{ OCSP_RESP_STATUS_UNAUTHORIZED, 6 },
	};
	unsigned char *response = (unsigned char *) 1;
	size_t response_size = 1;

	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		CU_ASSERT_EQUAL(ocsp_generate_error_response(
					cases[i].status, &response,
					&response_size),
				OCSP_OK);
		CU_ASSERT_PTR_NOT_NULL(response);
		CU_ASSERT_EQUAL(response_size, 5);
		CU_ASSERT_EQUAL(response[0], 0x30);
		CU_ASSERT_EQUAL(response[1], 0x03);
		CU_ASSERT_EQUAL(response[2], 0x0a);
		CU_ASSERT_EQUAL(response[3], 0x01);
		CU_ASSERT_EQUAL(response[4], cases[i].value);
		osal_free(response);
	}

	CU_ASSERT_EQUAL(ocsp_generate_error_response(
				OCSP_RESP_STATUS_SUCCESSFUL, &response,
				&response_size),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_PTR_NULL(response);
	CU_ASSERT_EQUAL(
		ocsp_generate_error_response(OCSP_RESP_STATUS_TRY_LATER,
					     NULL, &response_size),
		OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(
		ocsp_generate_error_response(OCSP_RESP_STATUS_TRY_LATER,
					     &response, NULL),
		OCSP_ERR_ARGUMENT);
}

static void test_generate_response(void)
{
	EVP_PKEY *ca_key = test_rsa_key();
	EVP_PKEY *leaf_key = test_rsa_key();
	X509 *ca;
	X509 *leaf;
	unsigned char *der;
	size_t der_length = 0;
	ocsp_request_t *request = NULL;
	ocsp_cert_status_info_t status = {
		.status = OCSP_CERT_STATUS_GOOD,
	};
	ocsp_response_params_t params = {
		.cert_statuses = &status,
		.cert_status_count = 1,
		.next_update_minutes = 5,
		.signature_algorithm = OCSP_SIGNATURE_DEFAULT,
		.sign = sign_callback,
	};
	unsigned char *response = NULL;
	size_t response_size = 0;
	const unsigned char *cursor;
	OCSP_RESPONSE *parsed;
	OCSP_BASICRESP *basic;
	OCSP_SINGLERESP *single;

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_key);
	ca = test_certificate(ca_key, NULL, NULL, 0x51, TEST_CERT_CA);
	leaf = test_certificate(leaf_key, ca, ca_key, 0x1235, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf);
	der = make_request(leaf, ca, &der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(der);
	CU_ASSERT_EQUAL(ocsp_request_parse(der, der_length, &request),
			OCSP_OK);
	CU_ASSERT_PTR_NOT_NULL_FATAL(request);

	params.signer_certificate = ca;
	params.sign_context = ca_key;
	CU_ASSERT_EQUAL(ocsp_generate_response(request, &params, &response,
					       &response_size),
			OCSP_OK);
	CU_ASSERT_PTR_NOT_NULL(response);
	CU_ASSERT_TRUE(response_size > 0);

	cursor = response;
	parsed = d2i_OCSP_RESPONSE(NULL, &cursor, (long) response_size);
	CU_ASSERT_PTR_NOT_NULL(parsed);
	if (parsed != NULL) {
		CU_ASSERT_EQUAL(OCSP_response_status(parsed),
				OCSP_RESPONSE_STATUS_SUCCESSFUL);
		basic = OCSP_response_get1_basic(parsed);
		CU_ASSERT_PTR_NOT_NULL(basic);
		if (basic != NULL) {
			CU_ASSERT_EQUAL(OCSP_resp_count(basic), 1);
			single = OCSP_resp_get0(basic, 0);
			CU_ASSERT_PTR_NOT_NULL(single);
			if (single != NULL) {
				CU_ASSERT_EQUAL(
					OCSP_single_get0_status(
						single, NULL, NULL, NULL,
						NULL),
					V_OCSP_CERTSTATUS_GOOD);
			}
			OCSP_BASICRESP_free(basic);
		}
		OCSP_RESPONSE_free(parsed);
	}
	osal_free(response);

	status.status = OCSP_CERT_STATUS_REVOKED;
	status.revoked_at = (int64_t) time(NULL) - 10;
	status.reason = 1;
	response = NULL;
	CU_ASSERT_EQUAL(ocsp_generate_response(request, &params, &response,
					       &response_size),
			OCSP_OK);
	CU_ASSERT_PTR_NOT_NULL(response);
	cursor = response;
	parsed = d2i_OCSP_RESPONSE(NULL, &cursor, (long) response_size);
	CU_ASSERT_PTR_NOT_NULL(parsed);
	if (parsed != NULL) {
		int reason = -1;

		basic = OCSP_response_get1_basic(parsed);
		CU_ASSERT_PTR_NOT_NULL(basic);
		if (basic != NULL) {
			single = OCSP_resp_get0(basic, 0);
			CU_ASSERT_PTR_NOT_NULL(single);
			if (single != NULL) {
				CU_ASSERT_EQUAL(
					OCSP_single_get0_status(
						single, &reason, NULL, NULL,
						NULL),
					V_OCSP_CERTSTATUS_REVOKED);
				CU_ASSERT_EQUAL(reason, 1);
			}
			OCSP_BASICRESP_free(basic);
		}
		OCSP_RESPONSE_free(parsed);
	}
	osal_free(response);

	CU_ASSERT_EQUAL(ocsp_generate_response(NULL, &params, &response,
					       &response_size),
			OCSP_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(ocsp_generate_response(request, NULL, &response,
					       &response_size),
			OCSP_ERR_ARGUMENT);

	ocsp_request_free(request);
	OPENSSL_free(der);
	X509_free(leaf);
	X509_free(ca);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(ca_key);
}

void test_ocsp_register(void)
{
	CU_pSuite suite = CU_add_suite("ocsp", NULL, NULL);

	CU_add_test(suite, "parse", test_parse);
	CU_add_test(suite, "error_response", test_error_response);
	CU_add_test(suite, "generate_response", test_generate_response);
}
