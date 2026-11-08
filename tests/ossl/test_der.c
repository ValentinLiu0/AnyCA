/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include <CUnit/Basic.h>

#include <anyca/ossl/asn1.h>
#include <anyca/ossl/der.h>

#include "test_suites.h"

static void test_append(void)
{
	ossl_der_buf_t buffer = { 0 };
	const unsigned char data[] = { 0x01, 0x02, 0x03 };

	CU_ASSERT_TRUE(ossl_der_buf_append(&buffer, data, sizeof data));
	CU_ASSERT_EQUAL(buffer.length, 3);
	CU_ASSERT_EQUAL(memcmp(buffer.data, data, sizeof data), 0);

	CU_ASSERT_TRUE(ossl_der_buf_append(&buffer, NULL, 0));
	CU_ASSERT_FALSE(ossl_der_buf_append(&buffer, NULL, 1));
	CU_ASSERT_FALSE(ossl_der_buf_append(NULL, data, 3));

	ossl_der_buf_release(&buffer);
	CU_ASSERT_PTR_NULL(buffer.data);
	CU_ASSERT_EQUAL(buffer.length, 0);
	CU_ASSERT_EQUAL(buffer.capacity, 0);
}

static void test_wrap(void)
{
	ossl_der_buf_t content = { 0 };
	ossl_der_buf_t wrapped = { 0 };
	const unsigned char integer[] = { 0x02, 0x01, 0x05 };
	const unsigned char expected[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };

	CU_ASSERT_TRUE(ossl_der_buf_append(&content, integer, sizeof integer));
	CU_ASSERT_TRUE(ossl_der_buf_wrap(&wrapped, 0x30, &content));
	CU_ASSERT_EQUAL(wrapped.length, sizeof expected);
	CU_ASSERT_EQUAL(memcmp(wrapped.data, expected, sizeof expected), 0);
	CU_ASSERT_FALSE(ossl_der_buf_wrap(&wrapped, 0x30, &wrapped));

	ossl_der_buf_release(&wrapped);
	ossl_der_buf_release(&content);

	{
		ossl_der_buf_t empty = { 0 };
		ossl_der_buf_t output = { 0 };
		const unsigned char empty_der[] = { 0x04, 0x00 };

		CU_ASSERT_TRUE(ossl_der_buf_wrap(&output, 0x04, &empty));
		CU_ASSERT_EQUAL(output.length, 2);
		CU_ASSERT_EQUAL(memcmp(output.data, empty_der, 2), 0);
		ossl_der_buf_release(&output);
	}

	{
		ossl_der_buf_t large = { 0 };
		ossl_der_buf_t output = { 0 };
		unsigned char bytes[200] = { 0 };

		CU_ASSERT_TRUE(ossl_der_buf_append(&large, bytes,
						   sizeof bytes));
		CU_ASSERT_TRUE(ossl_der_buf_wrap(&output, 0x04, &large));
		CU_ASSERT_EQUAL(output.length, 203);
		CU_ASSERT_EQUAL(output.data[0], 0x04);
		CU_ASSERT_EQUAL(output.data[1], 0x81);
		CU_ASSERT_EQUAL(output.data[2], 200);
		ossl_der_buf_release(&output);
		ossl_der_buf_release(&large);
	}
}

static void test_item(void)
{
	ASN1_INTEGER *integer = ossl_asn1_integer_from_uint64(0x1234);
	ossl_der_t der = { 0 };
	void *decoded = NULL;

	CU_ASSERT_PTR_NOT_NULL_FATAL(integer);
	CU_ASSERT_TRUE(ossl_der_encode_item(ASN1_ITEM_rptr(ASN1_INTEGER),
					    integer, &der));
	CU_ASSERT_EQUAL(der.length, 4);
	CU_ASSERT_TRUE(ossl_der_decode_item(ASN1_ITEM_rptr(ASN1_INTEGER),
					    der.data, der.length, &decoded));
	CU_ASSERT_PTR_NOT_NULL(decoded);
	CU_ASSERT_EQUAL(
		ASN1_INTEGER_cmp((ASN1_INTEGER *) decoded, integer), 0);

	{
		unsigned char *trailing = malloc(der.length + 1);

		CU_ASSERT_PTR_NOT_NULL_FATAL(trailing);
		memcpy(trailing, der.data, der.length);
		trailing[der.length] = 0;
		CU_ASSERT_FALSE(ossl_der_decode_item(
			ASN1_ITEM_rptr(ASN1_INTEGER), trailing,
			der.length + 1, &decoded));
		free(trailing);
	}

	ASN1_INTEGER_free((ASN1_INTEGER *) decoded);
	ASN1_INTEGER_free(integer);
	ossl_der_release(&der);
}

static void test_ecdsa_signature(void)
{
	unsigned char raw[64] = { 0 };
	const unsigned char expected[] = { 0x30, 0x06, 0x02, 0x01,
					   0x01, 0x02, 0x01, 0x01 };
	ossl_der_t der = { 0 };
	ossl_der_t invalid = { 0 };
	ECDSA_SIG *signature;
	const unsigned char *cursor;
	const BIGNUM *r;
	const BIGNUM *s;

	raw[31] = 1;
	raw[63] = 1;

	CU_ASSERT_TRUE(ossl_der_encode_ecdsa_signature(raw, sizeof raw,
							&der));
	CU_ASSERT_EQUAL(der.length, sizeof expected);
	CU_ASSERT_EQUAL(memcmp(der.data, expected, sizeof expected), 0);

	cursor = der.data;
	signature = d2i_ECDSA_SIG(NULL, &cursor, (long) der.length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(signature);
	ECDSA_SIG_get0(signature, &r, &s);
	CU_ASSERT_EQUAL(BN_get_word(r), 1);
	CU_ASSERT_EQUAL(BN_get_word(s), 1);
	ECDSA_SIG_free(signature);

	CU_ASSERT_FALSE(ossl_der_encode_ecdsa_signature(raw,
							sizeof raw - 1,
							&invalid));
	CU_ASSERT_FALSE(ossl_der_encode_ecdsa_signature(NULL, sizeof raw,
							&invalid));
	CU_ASSERT_FALSE(ossl_der_encode_ecdsa_signature(raw, 0, &invalid));

	ossl_der_release(&der);
}

void test_der_register(void)
{
	CU_pSuite suite = CU_add_suite("der", NULL, NULL);

	CU_add_test(suite, "append", test_append);
	CU_add_test(suite, "wrap", test_wrap);
	CU_add_test(suite, "item", test_item);
	CU_add_test(suite, "ecdsa_signature", test_ecdsa_signature);
}
