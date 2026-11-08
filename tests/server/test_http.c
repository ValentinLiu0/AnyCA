/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stddef.h>
#include <string.h>

#include <openssl/ocsp.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>

/*
 * White-box tests: including the implementation gives access to the static
 * URI, decoding and method helpers without exporting them from the server.
 */
#include "../../src/server/http_server.c"

#include "test_suites.h"

static void test_uri_prefix(void)
{
	CU_ASSERT_TRUE(_http_uri_has_prefix("/ocsp/ca", strlen("/ocsp/ca"),
					    ocsp_uri_prefix));
	CU_ASSERT_FALSE(_http_uri_has_prefix("/ocsp", strlen("/ocsp"),
					     ocsp_uri_prefix));
	CU_ASSERT_FALSE(_http_uri_has_prefix("/other", strlen("/other"),
					     ocsp_uri_prefix));
	CU_ASSERT_FALSE(_http_uri_has_prefix(NULL, 3, ocsp_uri_prefix));
}

static void test_split_ocsp_uri(void)
{
	const char *endpoint = NULL;
	const char *request = NULL;
	size_t endpoint_len = 0;
	size_t request_len = 0;
	const char uri[] = "/ocsp/root-ca/AAEC";

	CU_ASSERT_EQUAL(_http_split_ocsp_uri("/ocsp/root-ca",
					      strlen("/ocsp/root-ca"),
					      &endpoint, &endpoint_len,
					      &request, &request_len),
			HTTP_STATUS_OK);
	CU_ASSERT_EQUAL(endpoint_len, strlen("root-ca"));
	CU_ASSERT_EQUAL(memcmp(endpoint, "root-ca", endpoint_len), 0);
	CU_ASSERT_PTR_NULL(request);
	CU_ASSERT_EQUAL(request_len, 0);

	CU_ASSERT_EQUAL(_http_split_ocsp_uri(uri, strlen(uri), &endpoint,
					      &endpoint_len, &request,
					      &request_len),
			HTTP_STATUS_OK);
	CU_ASSERT_EQUAL(endpoint_len, strlen("root-ca"));
	CU_ASSERT_EQUAL(request_len, strlen("AAEC"));
	CU_ASSERT_EQUAL(memcmp(request, "AAEC", request_len), 0);

	/* An empty endpoint is malformed. */
	CU_ASSERT_EQUAL(_http_split_ocsp_uri("/ocsp/", strlen("/ocsp/"),
					      &endpoint, &endpoint_len,
					      &request, &request_len),
			HTTP_STATUS_BAD_REQUEST);

	/* A trailing slash means an empty (but present) request. */
	CU_ASSERT_EQUAL(_http_split_ocsp_uri("/ocsp/ca/", strlen("/ocsp/ca/"),
					      &endpoint, &endpoint_len,
					      &request, &request_len),
			HTTP_STATUS_OK);
	CU_ASSERT_PTR_NOT_NULL(request);
	CU_ASSERT_EQUAL(request_len, 0);
}

static void test_decode_ocsp_request(void)
{
	/* "+/8=" decodes to FB FF and exercises the '+' alphabet slot. */
	const char encoded[] = "+/8=";
	/* libwebsockets form-decodes '+' to a space before we see it. */
	const char spaced[] = " /8=";
	struct http_session_data data;

	memset(&data, 0, sizeof data);
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, encoded,
						  strlen(encoded)),
			HTTP_STATUS_OK);
	CU_ASSERT_EQUAL(data.size, 2);
	CU_ASSERT_EQUAL(data.data[LWS_PRE], 0xfb);
	CU_ASSERT_EQUAL(data.data[LWS_PRE + 1], 0xff);

	memset(&data, 0, sizeof data);
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, spaced,
						  strlen(spaced)),
			HTTP_STATUS_OK);
	CU_ASSERT_EQUAL(data.size, 2);
	CU_ASSERT_EQUAL(data.data[LWS_PRE], 0xfb);
	CU_ASSERT_EQUAL(data.data[LWS_PRE + 1], 0xff);

	memset(&data, 0, sizeof data);
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, "Zg==", 4),
			HTTP_STATUS_OK);
	CU_ASSERT_EQUAL(data.size, 1);
	CU_ASSERT_EQUAL(data.data[LWS_PRE], 'f');

	memset(&data, 0, sizeof data);
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, NULL, 0),
			HTTP_STATUS_BAD_REQUEST);
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, "", 0),
			HTTP_STATUS_BAD_REQUEST);
	/* Spaces elsewhere remain invalid. */
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, "Zg ==", 5),
			HTTP_STATUS_BAD_REQUEST);
	CU_ASSERT_EQUAL(_http_decode_ocsp_request(&data, "Zh==", 4),
			HTTP_STATUS_BAD_REQUEST);
}

static void test_method_names(void)
{
	CU_ASSERT_STRING_EQUAL(_http_method_to_string(LWSHUMETH_GET), "GET");
	CU_ASSERT_STRING_EQUAL(_http_method_to_string(LWSHUMETH_POST), "POST");
	CU_ASSERT_STRING_EQUAL(_http_method_to_string(LWSHUMETH_CONNECT),
			       "CONNECT");
	CU_ASSERT_STRING_EQUAL(_http_method_to_string(-1), "UNKNOWN");
}

static void check_error_response(ocsp_responder_wire_error_t wire,
				 int expected)
{
	unsigned char *response = NULL;
	size_t response_len = 0;
	const unsigned char *cursor;
	OCSP_RESPONSE *parsed;

	CU_ASSERT_EQUAL(ocsp_responder_generate_error(wire, &response,
						      &response_len),
			OCSP_RESPONDER_OK);
	CU_ASSERT_PTR_NOT_NULL_FATAL(response);
	CU_ASSERT_TRUE(response_len > 0);

	cursor = response;
	parsed = d2i_OCSP_RESPONSE(NULL, &cursor, (long) response_len);
	CU_ASSERT_PTR_NOT_NULL(parsed);
	if (parsed != NULL) {
		CU_ASSERT_EQUAL(OCSP_response_status(parsed), expected);
		OCSP_RESPONSE_free(parsed);
	}
	osal_free(response);
}

static void test_error_responses(void)
{
	check_error_response(OCSP_RESPONDER_WIRE_MALFORMED_REQUEST,
			     OCSP_RESPONSE_STATUS_MALFORMEDREQUEST);
	check_error_response(OCSP_RESPONDER_WIRE_INTERNAL_ERROR,
			     OCSP_RESPONSE_STATUS_INTERNALERROR);
	check_error_response(OCSP_RESPONDER_WIRE_UNAUTHORIZED,
			     OCSP_RESPONSE_STATUS_UNAUTHORIZED);

	{
		unsigned char *response = NULL;
		size_t response_len = 0;

		/* Unknown wire errors fall back to internalError. */
		CU_ASSERT_EQUAL(ocsp_responder_generate_error(
					(ocsp_responder_wire_error_t) 99,
					&response, &response_len),
				OCSP_RESPONDER_OK);
		CU_ASSERT_PTR_NOT_NULL(response);
		osal_free(response);

		CU_ASSERT_EQUAL(ocsp_responder_generate_error(
					OCSP_RESPONDER_WIRE_MALFORMED_REQUEST,
					NULL, &response_len),
				OCSP_RESPONDER_ERR_ARGUMENT);
	}
}

void test_http_register(void)
{
	CU_pSuite suite = CU_add_suite("http", NULL, NULL);

	CU_add_test(suite, "uri_prefix", test_uri_prefix);
	CU_add_test(suite, "split_ocsp_uri", test_split_ocsp_uri);
	CU_add_test(suite, "decode_ocsp_request", test_decode_ocsp_request);
	CU_add_test(suite, "method_names", test_method_names);
	CU_add_test(suite, "error_responses", test_error_responses);
}
