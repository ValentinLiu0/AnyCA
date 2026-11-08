/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdlib.h>
#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>
#include <anyca/ossl/base64.h>

#include "test_suites.h"

static const struct {
	const char *plain;
	const char *encoded;
} vectors[] = {
	{ "", "" },
	{ "f", "Zg==" },
	{ "fo", "Zm8=" },
	{ "foo", "Zm9v" },
	{ "foob", "Zm9vYg==" },
	{ "fooba", "Zm9vYmE=" },
	{ "foobar", "Zm9vYmFy" },
};

static void test_encode(void)
{
	for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
		char *encoded = NULL;
		size_t length = 0;

		CU_ASSERT_TRUE(ossl_base64_encode(
			(const unsigned char *) vectors[i].plain,
			strlen(vectors[i].plain), &encoded, &length));
		CU_ASSERT_PTR_NOT_NULL(encoded);
		CU_ASSERT_EQUAL(length, strlen(vectors[i].encoded));
		CU_ASSERT_STRING_EQUAL(encoded, vectors[i].encoded);
		osal_free(encoded);
	}
}

static void test_decode(void)
{
	for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
		unsigned char *decoded = NULL;
		size_t length = 0;

		CU_ASSERT_TRUE(ossl_base64_decode(
			vectors[i].encoded, strlen(vectors[i].encoded),
			&decoded, &length));
		CU_ASSERT_PTR_NOT_NULL(decoded);
		CU_ASSERT_EQUAL(length, strlen(vectors[i].plain));
		CU_ASSERT_EQUAL(memcmp(decoded, vectors[i].plain, length), 0);
		osal_free(decoded);
	}
}

static void test_binary(void)
{
	const unsigned char input[] = { 0x00, 0x01, 0xfe, 0xff };
	char *encoded = NULL;
	size_t encoded_length = 0;
	unsigned char *decoded = NULL;
	size_t decoded_length = 0;

	CU_ASSERT_TRUE(ossl_base64_encode(input, sizeof input, &encoded,
					  &encoded_length));
	CU_ASSERT_STRING_EQUAL(encoded, "AAH+/w==");
	CU_ASSERT_TRUE(ossl_base64_decode(encoded, encoded_length, &decoded,
					  &decoded_length));
	CU_ASSERT_EQUAL(decoded_length, sizeof input);
	CU_ASSERT_EQUAL(memcmp(decoded, input, sizeof input), 0);

	osal_free(encoded);
	osal_free(decoded);
}

static void test_alphabet(void)
{
	unsigned char *decoded = NULL;
	size_t length = 0;

	/* '+' and '/' are valid standard-alphabet characters. */
	CU_ASSERT_TRUE(ossl_base64_decode("+/8=", 4, &decoded, &length));
	CU_ASSERT_EQUAL(length, 2);
	CU_ASSERT_EQUAL(decoded[0], 0xfb);
	CU_ASSERT_EQUAL(decoded[1], 0xff);
	osal_free(decoded);
}

static void test_invalid(void)
{
	unsigned char *decoded = (unsigned char *) 1;
	size_t length = 1;
	char *encoded = (char *) 1;

	CU_ASSERT_FALSE(ossl_base64_decode("abc", 3, &decoded, &length));
	CU_ASSERT_PTR_NULL(decoded);

	CU_ASSERT_FALSE(ossl_base64_decode("a=bc", 4, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("!!!!", 4, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("Zm9v\n", 5, &decoded, &length));
	/* Whitespace is not part of the alphabet, at either end or inside. */
	CU_ASSERT_FALSE(ossl_base64_decode(" Zg==", 5, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("Zg== ", 5, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("Zg\t==", 5, &decoded, &length));
	/* URL-safe characters must be rejected. */
	CU_ASSERT_FALSE(ossl_base64_decode("-_8=", 4, &decoded, &length));
	/* Non-canonical trailing bits must be rejected. */
	CU_ASSERT_FALSE(ossl_base64_decode("Zh==", 4, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("Zm9=", 4, &decoded, &length));
	/* Wrong padding. */
	CU_ASSERT_FALSE(ossl_base64_decode("Zg=", 3, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("Zg===", 5, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode(NULL, 4, &decoded, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("", 0, NULL, &length));
	CU_ASSERT_FALSE(ossl_base64_decode("", 0, &decoded, NULL));

	CU_ASSERT_FALSE(ossl_base64_encode(NULL, 1, &encoded, &length));
	CU_ASSERT_FALSE(ossl_base64_encode(NULL, 0, NULL, &length));
	CU_ASSERT_FALSE(ossl_base64_encode(NULL, 0, &encoded, NULL));
}

void test_base64_register(void)
{
	CU_pSuite suite = CU_add_suite("base64", NULL, NULL);

	CU_add_test(suite, "encode", test_encode);
	CU_add_test(suite, "decode", test_decode);
	CU_add_test(suite, "binary", test_binary);
	CU_add_test(suite, "alphabet", test_alphabet);
	CU_add_test(suite, "invalid", test_invalid);
}
