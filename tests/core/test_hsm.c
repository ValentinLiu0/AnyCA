/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/hsm.h>

#include "../test_support.h"
#include "test_suites.h"

static void test_softhsm_sign(void)
{
	char directory[PATH_MAX];
	char conf_path[PATH_MAX];
	char data[] = "anyca SoftHSM signing test";
	unsigned char signature[512];
	size_t signature_length = 0;
	struct hsm_config config = {
		.module_path = TEST_SOFTHSM_MODULE,
		.max_sessions_per_token = 4,
	};
	hsm_module_t *module = NULL;
	hsm_token_t *token = NULL;
	struct hsm_module_info info;
	struct hsm_token_info token_info;

	if (!test_softhsm_available()) {
		fprintf(stderr, "SoftHSM not available; skipping\n");
		return;
	}
	if (!test_softhsm_init_token(directory, sizeof directory, conf_path,
				 sizeof conf_path)) {
		CU_FAIL("cannot initialise a SoftHSM token");
		return;
	}

	CU_ASSERT_EQUAL_FATAL(hsm_module_open(&config, &module), HSM_OK);
	CU_ASSERT_TRUE(hsm_module_is_open(module));
	CU_ASSERT_EQUAL(hsm_module_get_info(module, &info), HSM_OK);
	CU_ASSERT_TRUE(info.description[0] != '\0');

	CU_ASSERT_EQUAL_FATAL(
		hsm_token_open(module, TEST_SOFTHSM_TOKEN_LABEL, &token), HSM_OK);
	CU_ASSERT_EQUAL(hsm_get_token_info(token, &token_info), HSM_OK);
	CU_ASSERT_STRING_EQUAL(token_info.label, TEST_SOFTHSM_TOKEN_LABEL);

	/* Private-key operations require a login. */
	CU_ASSERT_EQUAL(hsm_sign(token, HSM_SIGN_RSA_PKCS1_SHA256, "sign-key",
				 data, strlen(data), signature,
				 sizeof signature, &signature_length),
			HSM_ERR_TOKEN_NOT_LOGGED_IN);

	CU_ASSERT_EQUAL(hsm_token_login(token, TEST_SOFTHSM_PIN), HSM_OK);
	CU_ASSERT_EQUAL(hsm_generate_rsa_key_pair(token, 2048, "sign-key"),
			HSM_OK);

	/* NULL output queries the required size. */
	CU_ASSERT_EQUAL(hsm_sign(token, HSM_SIGN_RSA_PKCS1_SHA256, "sign-key",
				 data, strlen(data), NULL, 0,
				 &signature_length),
			HSM_OK);
	CU_ASSERT_TRUE(signature_length > 0);
	CU_ASSERT_TRUE(signature_length <= sizeof signature);

	CU_ASSERT_EQUAL(hsm_sign(token, HSM_SIGN_RSA_PKCS1_SHA256, "sign-key",
				 data, strlen(data), signature,
				 sizeof signature, &signature_length),
			HSM_OK);
	CU_ASSERT_EQUAL(hsm_verify(token, HSM_SIGN_RSA_PKCS1_SHA256, "sign-key",
				   data, strlen(data), signature,
				   signature_length),
			HSM_OK);

	/* A corrupted signature must be reported as a verification failure. */
	signature[0] ^= 0xff;
	CU_ASSERT_EQUAL(hsm_verify(token, HSM_SIGN_RSA_PKCS1_SHA256, "sign-key",
				   data, strlen(data), signature,
				   signature_length),
			HSM_ERR_VERIFY);

	CU_ASSERT_EQUAL(hsm_token_set_pin(token, TEST_SOFTHSM_PIN, "5678"), HSM_OK);
	CU_ASSERT_EQUAL(hsm_token_logout(token), HSM_OK);
	CU_ASSERT_EQUAL(hsm_token_login(token, TEST_SOFTHSM_PIN),
			HSM_ERR_PIN_INCORRECT);
	CU_ASSERT_EQUAL(hsm_token_login(token, "5678"), HSM_OK);
	CU_ASSERT_EQUAL(hsm_token_logout(token), HSM_OK);

	hsm_token_close(token);
	CU_ASSERT_EQUAL(hsm_module_close(module), HSM_OK);

	test_remove_tree(directory);
}

/*
 * Two wrappers on the same provider share the process-wide C_Initialize();
 * closing the first must not finalize it while the second is still open.
 */
static void test_softhsm_shared_provider(void)
{
	char directory[PATH_MAX];
	char conf_path[PATH_MAX];
	struct hsm_config config = {
		.module_path = TEST_SOFTHSM_MODULE,
		.max_sessions_per_token = 2,
	};
	hsm_module_t *first = NULL;
	hsm_module_t *second = NULL;
	hsm_token_t *token = NULL;
	struct hsm_module_info info;

	if (!test_softhsm_available()) {
		fprintf(stderr, "SoftHSM not available; skipping\n");
		return;
	}
	if (!test_softhsm_init_token(directory, sizeof directory, conf_path,
				 sizeof conf_path)) {
		CU_FAIL("cannot initialise a SoftHSM token");
		return;
	}

	CU_ASSERT_EQUAL_FATAL(hsm_module_open(&config, &first), HSM_OK);
	CU_ASSERT_EQUAL_FATAL(hsm_module_open(&config, &second), HSM_OK);
	CU_ASSERT_EQUAL_FATAL(
		hsm_token_open(second, TEST_SOFTHSM_TOKEN_LABEL, &token), HSM_OK);

	CU_ASSERT_EQUAL(hsm_module_close(first), HSM_OK);
	CU_ASSERT_FALSE(hsm_module_is_open(first));
	CU_ASSERT_TRUE(hsm_module_is_open(second));
	CU_ASSERT_EQUAL(hsm_module_get_info(second, &info), HSM_OK);

	/* Closing with a token still open must fail without finalizing. */
	CU_ASSERT_EQUAL(hsm_module_close(second), HSM_ERR_BUSY);
	CU_ASSERT_TRUE(hsm_module_is_open(second));

	hsm_token_close(token);
	CU_ASSERT_EQUAL(hsm_module_close(second), HSM_OK);

	test_remove_tree(directory);
}

static void test_digest_size(void)
{
	CU_ASSERT_EQUAL(hsm_get_digest_size(HSM_DIGEST_SHA1), 20);
	CU_ASSERT_EQUAL(hsm_get_digest_size(HSM_DIGEST_SHA224), 28);
	CU_ASSERT_EQUAL(hsm_get_digest_size(HSM_DIGEST_SHA256), 32);
	CU_ASSERT_EQUAL(hsm_get_digest_size(HSM_DIGEST_SHA384), 48);
	CU_ASSERT_EQUAL(hsm_get_digest_size(HSM_DIGEST_SHA512), 64);
	CU_ASSERT_EQUAL(hsm_get_digest_size((hsm_digest_alg_t) 99), 0);
}

static void test_status(void)
{
	CU_ASSERT_STRING_EQUAL(hsm_status_to_string(HSM_OK), "HSM_OK");
	CU_ASSERT_STRING_EQUAL(hsm_status_to_string(HSM_ERR_ARGUMENT),
			       "HSM_ERR_ARGUMENT");
	CU_ASSERT_STRING_EQUAL(hsm_status_to_string(HSM_ERR_PIN_INCORRECT),
			       "HSM_ERR_PIN_INCORRECT");
	CU_ASSERT_STRING_EQUAL(hsm_status_to_string(HSM_ERR_DUPLICATE),
			       "HSM_ERR_DUPLICATE");
	CU_ASSERT_STRING_EQUAL(hsm_status_to_string((hsm_status_t) 99),
			       "HSM_ERR_UNKNOWN");
}

static void test_errors(void)
{
	struct hsm_config config = { .module_path = "libc.so.6" };
	struct hsm_config empty = { 0 };
	hsm_module_t *module = (hsm_module_t *) 1;
	struct hsm_module_info info;
	hsm_token_t *token = NULL;
	unsigned char digest[32];
	size_t digest_length = 0;
	hsm_public_key_t key = { 0 };
	const struct hsm_error *error;

	CU_ASSERT_EQUAL(hsm_module_open(NULL, &module), HSM_ERR_ARGUMENT);
	CU_ASSERT_PTR_NULL(module);
	CU_ASSERT_EQUAL(hsm_module_open(&config, NULL), HSM_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(hsm_module_open(&empty, &module),
			HSM_ERR_ARGUMENT);
	CU_ASSERT_PTR_NULL(module);
	CU_ASSERT_EQUAL(hsm_module_open(&config, &module),
			HSM_ERR_MODULE_LOAD);
	CU_ASSERT_PTR_NULL(module);

	CU_ASSERT_EQUAL(hsm_module_close(NULL), HSM_OK);
	CU_ASSERT_FALSE(hsm_module_is_open(NULL));
	CU_ASSERT_EQUAL(hsm_module_get_info(NULL, &info),
			HSM_ERR_ARGUMENT);

	CU_ASSERT_EQUAL(hsm_token_open(NULL, "token", &token),
			HSM_ERR_ARGUMENT);
	CU_ASSERT_PTR_NULL(token);
	CU_ASSERT_EQUAL(hsm_token_open(NULL, "token", NULL),
			HSM_ERR_ARGUMENT);
	hsm_token_close(NULL);
	CU_ASSERT_EQUAL(hsm_token_login(NULL, "1234"),
			HSM_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(hsm_token_logout(NULL), HSM_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(hsm_token_set_pin(NULL, "a", "b"),
			HSM_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(hsm_random(NULL, digest, sizeof digest),
			HSM_ERR_ARGUMENT);

	CU_ASSERT_EQUAL(hsm_digest(NULL, HSM_DIGEST_SHA256, "abc", 3,
				   digest, sizeof digest, &digest_length),
			HSM_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(hsm_digest(NULL, HSM_DIGEST_SHA256, "abc", 3,
				   digest, sizeof digest, NULL),
			HSM_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(hsm_digest(NULL, HSM_DIGEST_SHA256, NULL, 3,
				   digest, sizeof digest, &digest_length),
			HSM_ERR_ARGUMENT);

	hsm_public_key_free(&key);
	hsm_public_key_free(NULL);
	hsm_key_object_list_free(NULL, 0);
	(void) hsm_get_last_error();
	error = hsm_get_last_error();
	CU_ASSERT_PTR_NOT_NULL(error);
	CU_ASSERT_TRUE(error->message[0] != '\0');
}

void test_hsm_register(void)
{
	CU_pSuite suite = CU_add_suite("hsm", NULL, NULL);

	CU_add_test(suite, "digest_size", test_digest_size);
	CU_add_test(suite, "status", test_status);
	CU_add_test(suite, "errors", test_errors);
	CU_add_test(suite, "softhsm_sign", test_softhsm_sign);
	CU_add_test(suite, "softhsm_shared_provider",
		    test_softhsm_shared_provider);
}
