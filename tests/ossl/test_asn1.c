/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>
#include <anyca/ossl/asn1.h>

#include "test_suites.h"

static void test_read_tlv(void)
{
	const unsigned char der[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
	const unsigned char *cursor = der;
	ossl_asn1_tlv_t tlv;

	CU_ASSERT_TRUE(ossl_asn1_read_tlv(&cursor, (long) sizeof der, &tlv));
	CU_ASSERT_EQUAL(tlv.tag, V_ASN1_SEQUENCE);
	CU_ASSERT_EQUAL(tlv.xclass, V_ASN1_UNIVERSAL);
	CU_ASSERT_TRUE(tlv.constructed);
	CU_ASSERT_EQUAL(tlv.content_length, 3);
	CU_ASSERT_EQUAL(cursor, der + 2);

	CU_ASSERT_TRUE(ossl_asn1_expect_tlv(&cursor, 3, V_ASN1_INTEGER,
					    V_ASN1_UNIVERSAL, &tlv));
	CU_ASSERT_EQUAL(tlv.content_length, 1);
	CU_ASSERT_EQUAL(tlv.content[0], 0x05);
}

static void test_read_invalid(void)
{
	const unsigned char indefinite[] = { 0x30, 0x80 };
	const unsigned char truncated[] = { 0x30, 0x05, 0x00 };
	const unsigned char *cursor;
	ossl_asn1_tlv_t tlv;

	cursor = indefinite;
	CU_ASSERT_FALSE(ossl_asn1_read_tlv(&cursor, 2, &tlv));

	cursor = truncated;
	CU_ASSERT_FALSE(ossl_asn1_read_tlv(&cursor, 3, &tlv));

	cursor = truncated;
	CU_ASSERT_FALSE(ossl_asn1_read_tlv(&cursor, 0, &tlv));
	CU_ASSERT_FALSE(ossl_asn1_read_tlv(NULL, 3, &tlv));
	CU_ASSERT_FALSE(ossl_asn1_read_tlv(&cursor, 3, NULL));
}

static void test_integer_to_bytes(void)
{
	ASN1_INTEGER *integer = ASN1_INTEGER_new();
	unsigned char *data = NULL;
	size_t length = 0;
	bool negative = false;

	CU_ASSERT_PTR_NOT_NULL_FATAL(integer);

	CU_ASSERT_EQUAL(ASN1_INTEGER_set(integer, 0x1234), 1);
	CU_ASSERT_TRUE(ossl_asn1_integer_to_bytes(integer, &data, &length,
						  &negative));
	CU_ASSERT_FALSE(negative);
	CU_ASSERT_EQUAL(length, 2);
	CU_ASSERT_EQUAL(data[0], 0x12);
	CU_ASSERT_EQUAL(data[1], 0x34);
	osal_free(data);

	CU_ASSERT_EQUAL(ASN1_INTEGER_set(integer, 0), 1);
	CU_ASSERT_TRUE(ossl_asn1_integer_to_bytes(integer, &data, &length,
						  &negative));
	CU_ASSERT_EQUAL(length, 1);
	CU_ASSERT_EQUAL(data[0], 0x00);
	osal_free(data);

	CU_ASSERT_EQUAL(ASN1_INTEGER_set_int64(integer, -1), 1);
	data = (unsigned char *) 1;
	length = 1;
	CU_ASSERT_FALSE(ossl_asn1_integer_to_bytes(integer, &data, &length,
						   &negative));
	CU_ASSERT_TRUE(negative);
	CU_ASSERT_PTR_NULL(data);
	CU_ASSERT_EQUAL(length, 0);

	CU_ASSERT_FALSE(ossl_asn1_integer_to_bytes(NULL, &data, &length,
						   NULL));
	ASN1_INTEGER_free(integer);
}

static void test_integer_from_bytes(void)
{
	const unsigned char bytes[] = { 0x80, 0x01 };
	const unsigned char zero[] = { 0x00, 0x00 };
	ASN1_INTEGER *integer = ossl_asn1_integer_from_bytes(bytes,
							     sizeof bytes);
	char *text;

	CU_ASSERT_PTR_NOT_NULL_FATAL(integer);
	text = ossl_asn1_integer_to_hex(integer);
	CU_ASSERT_PTR_NOT_NULL(text);
	CU_ASSERT_STRING_EQUAL(text, "8001");
	osal_free(text);
	ASN1_INTEGER_free(integer);

	CU_ASSERT_PTR_NULL(ossl_asn1_integer_from_bytes(zero, sizeof zero));
	CU_ASSERT_PTR_NULL(ossl_asn1_integer_from_bytes(NULL, 1));
	CU_ASSERT_PTR_NULL(ossl_asn1_integer_from_bytes(bytes, 0));

	integer = ossl_asn1_integer_from_uint64(0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(integer);
	text = ossl_asn1_integer_to_hex(integer);
	CU_ASSERT_STRING_EQUAL(text, "0");
	osal_free(text);
	ASN1_INTEGER_free(integer);
}

static void test_time(void)
{
	ASN1_TIME *time = ossl_asn1_time_from_epoch(946684800);
	ASN1_GENERALIZEDTIME *generalized =
		ossl_asn1_generalized_time_from_epoch(946684800);
	int64_t epoch = 0;

	CU_ASSERT_PTR_NOT_NULL_FATAL(time);
	CU_ASSERT_TRUE(ossl_asn1_time_to_epoch(time, &epoch));
	CU_ASSERT_EQUAL(epoch, 946684800);

	epoch = 0;
	CU_ASSERT_PTR_NOT_NULL_FATAL(generalized);
	CU_ASSERT_TRUE(ossl_asn1_time_to_epoch((const ASN1_TIME *) generalized,
					       &epoch));
	CU_ASSERT_EQUAL(epoch, 946684800);

	CU_ASSERT_FALSE(ossl_asn1_time_to_epoch(NULL, &epoch));
	CU_ASSERT_FALSE(ossl_asn1_time_to_epoch(time, NULL));

	ASN1_TIME_free(time);
	ASN1_GENERALIZEDTIME_free(generalized);
}

static void test_time_edges(void)
{
	/* 9999-12-31T23:59:59Z is the last encodable ASN.1 time. */
	const int64_t max_epoch = 253402300799LL;
	ASN1_TIME *time;
	ASN1_GENERALIZEDTIME *generalized;
	ASN1_TIME *invalid;
	int64_t epoch = 0;

	time = ossl_asn1_time_from_epoch(-1);
	CU_ASSERT_PTR_NOT_NULL_FATAL(time);
	CU_ASSERT_TRUE(ossl_asn1_time_to_epoch(time, &epoch));
	CU_ASSERT_EQUAL(epoch, -1);
	ASN1_TIME_free(time);

	generalized = ossl_asn1_generalized_time_from_epoch(-1);
	CU_ASSERT_PTR_NOT_NULL_FATAL(generalized);
	CU_ASSERT_TRUE(ossl_asn1_time_to_epoch(
		(const ASN1_TIME *) generalized, &epoch));
	CU_ASSERT_EQUAL(epoch, -1);
	ASN1_GENERALIZEDTIME_free(generalized);

	CU_ASSERT_PTR_NULL(ossl_asn1_time_from_epoch(max_epoch + 1));
	CU_ASSERT_PTR_NULL(
		ossl_asn1_generalized_time_from_epoch(max_epoch + 1));

	/* A five-digit year cannot be represented by UTCTime/GeneralizedTime. */
	invalid = ASN1_TIME_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(invalid);
	CU_ASSERT_EQUAL(ASN1_STRING_set(invalid, "10000101000000Z", 15), 1);
	CU_ASSERT_FALSE(ossl_asn1_time_to_epoch(invalid, &epoch));
	ASN1_TIME_free(invalid);
}

static void test_bit_string(void)
{
	const unsigned char bits[] = { 0xa5, 0x00 };
	ASN1_BIT_STRING *string = ossl_asn1_bit_string_from_bytes(
		bits, sizeof bits);

	CU_ASSERT_PTR_NOT_NULL_FATAL(string);
	CU_ASSERT_EQUAL(ASN1_STRING_length(string), 2);
	CU_ASSERT_EQUAL(memcmp(ASN1_STRING_get0_data(string), bits, 2), 0);
	CU_ASSERT_TRUE((string->flags & ASN1_STRING_FLAG_BITS_LEFT) != 0);
	ASN1_BIT_STRING_free(string);

	CU_ASSERT_PTR_NULL(ossl_asn1_bit_string_from_bytes(NULL, 1));
	CU_ASSERT_PTR_NULL(ossl_asn1_bit_string_from_bytes(bits, 0));
}

void test_asn1_register(void)
{
	CU_pSuite suite = CU_add_suite("asn1", NULL, NULL);

	CU_add_test(suite, "read_tlv", test_read_tlv);
	CU_add_test(suite, "read_invalid", test_read_invalid);
	CU_add_test(suite, "integer_to_bytes", test_integer_to_bytes);
	CU_add_test(suite, "integer_from_bytes", test_integer_from_bytes);
	CU_add_test(suite, "time", test_time);
	CU_add_test(suite, "time_edges", test_time_edges);
	CU_add_test(suite, "bit_string", test_bit_string);
}
