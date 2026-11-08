/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>
#include <anyca/utils.h>

#include "test_suites.h"

static void test_roundtrip(void)
{
	const unsigned char input[] = { 0x00, 0x01, 0xfe, 0xff };
	char *encoded = NULL;
	size_t encoded_length = 0;
	unsigned char *decoded = NULL;
	size_t decoded_length = 0;

	CU_ASSERT_TRUE(utils_base64_encode(input, sizeof input, &encoded,
					    &encoded_length));
	CU_ASSERT_PTR_NOT_NULL(encoded);
	CU_ASSERT_STRING_EQUAL(encoded, "AAH+/w==");
	CU_ASSERT_EQUAL(encoded_length, 8);

	CU_ASSERT_TRUE(utils_base64_decode(encoded, encoded_length, &decoded,
					    &decoded_length));
	CU_ASSERT_EQUAL(decoded_length, sizeof input);
	CU_ASSERT_EQUAL(memcmp(decoded, input, sizeof input), 0);

	osal_free(encoded);
	osal_free(decoded);
}

static void test_invalid(void)
{
	char *encoded = NULL;
	size_t length = 0;
	unsigned char *decoded = NULL;

	CU_ASSERT_FALSE(utils_base64_encode(NULL, 1, &encoded, &length));
	CU_ASSERT_FALSE(utils_base64_decode("abc", 3, &decoded, &length));
	CU_ASSERT_FALSE(utils_base64_decode("Zm9v\n", 5, &decoded, &length));
}

void test_utils_register(void)
{
	CU_pSuite suite = CU_add_suite("utils", NULL, NULL);

	CU_add_test(suite, "roundtrip", test_roundtrip);
	CU_add_test(suite, "invalid", test_invalid);
}
