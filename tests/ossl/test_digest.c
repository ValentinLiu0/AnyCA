/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <openssl/evp.h>

#include <CUnit/Basic.h>

#include <anyca/ossl/digest.h>

#include "test_suites.h"

static void hex(const unsigned char *data, size_t length, char *output)
{
	static const char digits[] = "0123456789abcdef";

	for (size_t i = 0; i < length; i++) {
		output[2 * i] = digits[data[i] >> 4];
		output[2 * i + 1] = digits[data[i] & 0x0f];
	}
	output[2 * length] = '\0';
}

static void test_sha256(void)
{
	unsigned char digest[32];
	char text[65];
	size_t length = 0;

	CU_ASSERT_TRUE(ossl_digest(EVP_sha256(), "abc", 3, digest,
				   sizeof digest, &length));
	CU_ASSERT_EQUAL(length, 32);
	hex(digest, length, text);
	CU_ASSERT_STRING_EQUAL(
		text,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	CU_ASSERT_TRUE(ossl_digest(EVP_sha256(), NULL, 0, digest,
				   sizeof digest, &length));
	hex(digest, length, text);
	CU_ASSERT_STRING_EQUAL(
		text,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_sha1(void)
{
	unsigned char digest[20];
	char text[41];
	size_t length = 0;

	CU_ASSERT_TRUE(ossl_digest(EVP_sha1(), "abc", 3, digest,
				   sizeof digest, &length));
	CU_ASSERT_EQUAL(length, 20);
	hex(digest, length, text);
	CU_ASSERT_STRING_EQUAL(text, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

static void test_invalid(void)
{
	unsigned char digest[32];
	size_t length = 0;

	CU_ASSERT_FALSE(ossl_digest(NULL, "abc", 3, digest, sizeof digest,
				    &length));
	CU_ASSERT_FALSE(ossl_digest(EVP_sha256(), NULL, 1, digest,
				    sizeof digest, &length));
	CU_ASSERT_FALSE(ossl_digest(EVP_sha256(), "abc", 3, NULL,
				    sizeof digest, &length));
	CU_ASSERT_FALSE(ossl_digest(EVP_sha256(), "abc", 3, digest,
				    sizeof digest, NULL));
	CU_ASSERT_FALSE(ossl_digest(EVP_sha256(), "abc", 3, digest, 8,
				    &length));
}

void test_digest_register(void)
{
	CU_pSuite suite = CU_add_suite("digest", NULL, NULL);

	CU_add_test(suite, "sha256", test_sha256);
	CU_add_test(suite, "sha1", test_sha1);
	CU_add_test(suite, "invalid", test_invalid);
}
