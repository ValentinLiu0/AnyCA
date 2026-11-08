/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include <CUnit/Basic.h>

#include <anyca/ossl/pkey.h>

#include "../test_support.h"
#include "test_suites.h"

static void test_rsa(void)
{
	EVP_PKEY *key = test_rsa_key();
	EVP_PKEY *built = NULL;
	BIGNUM *modulus = NULL;
	BIGNUM *exponent = NULL;
	unsigned char *modulus_bytes = NULL;
	unsigned char *exponent_bytes = NULL;
	int modulus_length;
	int exponent_length;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	CU_ASSERT_EQUAL(
		EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &modulus),
		1);
	CU_ASSERT_EQUAL(
		EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent),
		1);
	CU_ASSERT_PTR_NOT_NULL_FATAL(modulus);
	CU_ASSERT_PTR_NOT_NULL_FATAL(exponent);

	modulus_length = BN_num_bytes(modulus);
	exponent_length = BN_num_bytes(exponent);
	modulus_bytes = malloc((size_t) modulus_length);
	exponent_bytes = malloc((size_t) exponent_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(modulus_bytes);
	CU_ASSERT_PTR_NOT_NULL_FATAL(exponent_bytes);
	BN_bn2bin(modulus, modulus_bytes);
	BN_bn2bin(exponent, exponent_bytes);

	built = ossl_pkey_from_rsa_public(modulus_bytes,
					  (size_t) modulus_length,
					  exponent_bytes,
					  (size_t) exponent_length);
	CU_ASSERT_PTR_NOT_NULL(built);
	CU_ASSERT_TRUE(ossl_pkey_equal(key, built));

	free(modulus_bytes);
	free(exponent_bytes);
	BN_free(modulus);
	BN_free(exponent);
	EVP_PKEY_free(built);
	EVP_PKEY_free(key);
}

static void test_ec(void)
{
	EVP_PKEY *key = test_ec_key();
	EVP_PKEY *built = NULL;
	char group[64] = { 0 };
	size_t group_length = 0;
	unsigned char point[256];
	size_t point_length = 0;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	CU_ASSERT_EQUAL(EVP_PKEY_get_utf8_string_param(
				key, OSSL_PKEY_PARAM_GROUP_NAME, group,
				sizeof group, &group_length),
			1);
	CU_ASSERT_EQUAL(EVP_PKEY_get_octet_string_param(
				key, OSSL_PKEY_PARAM_PUB_KEY, point,
				sizeof point, &point_length),
			1);
	CU_ASSERT_TRUE(point_length > 0);

	built = ossl_pkey_from_ec_public(group, point, point_length);
	CU_ASSERT_PTR_NOT_NULL(built);
	CU_ASSERT_TRUE(ossl_pkey_equal(key, built));

	EVP_PKEY_free(built);
	EVP_PKEY_free(key);
}

static void test_invalid(void)
{
	const unsigned char value[] = { 0x01 };

	CU_ASSERT_PTR_NULL(ossl_pkey_from_rsa_public(NULL, 1, value, 1));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_rsa_public(value, 0, value, 1));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_rsa_public(value, 1, NULL, 1));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_ec_public(NULL, value, 1));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_ec_public("prime256v1", NULL, 1));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_ec_public("prime256v1", value, 0));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_ml_dsa_public(NULL, value, 1));
	CU_ASSERT_PTR_NULL(ossl_pkey_from_ml_dsa_public("ML-DSA-44", NULL, 1));
	CU_ASSERT_FALSE(ossl_pkey_equal(NULL, NULL));
}

void test_pkey_register(void)
{
	CU_pSuite suite = CU_add_suite("pkey", NULL, NULL);

	CU_add_test(suite, "rsa", test_rsa);
	CU_add_test(suite, "ec", test_ec);
	CU_add_test(suite, "invalid", test_invalid);
}
