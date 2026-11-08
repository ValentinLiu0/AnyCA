/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/store.h>

#include "../test_support.h"
#include "test_suites.h"

static char *g_directory;
static char g_path[PATH_MAX];

static int suite_init(void)
{
	g_directory = test_temp_dir();
	if (g_directory == NULL)
		return -1;
	snprintf(g_path, sizeof g_path, "%s/store.db", g_directory);
	return store_init(g_path) ? 0 : -1;
}

static int suite_cleanup(void)
{
	store_fini();
	if (g_directory != NULL) {
		test_remove_tree(g_directory);
		free(g_directory);
		g_directory = NULL;
	}
	return 0;
}

static void fill_config(store_ca_config_t *config, const char *name,
			const char *endpoint)
{
	static unsigned char certificate[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
	static unsigned char signer[] = { 0x30, 0x03, 0x02, 0x01, 0x02 };

	memset(config, 0, sizeof *config);
	config->name = (char *) name;
	config->hsm_provider = (char *) "provider";
	config->token_label = (char *) "token";
	config->pin = (char *) "1234";
	config->key_label = (char *) "key";
	config->ca_cert = certificate;
	config->ca_cert_length = sizeof certificate;
	config->ocsp_signer_token_label = (char *) "token";
	config->ocsp_signer_pin = (char *) "1234";
	config->ocsp_signer_key_label = (char *) "ocsp";
	config->ocsp_signer_cert = signer;
	config->ocsp_signer_cert_length = sizeof signer;
	config->ocsp_signer_digest = (char *) "sha256";
	config->crl_publish_period_min = 60;
	config->ocsp_update_period_min = 10;
	config->ocsp_responder_endpoint = (char *) endpoint;
}

static void test_open(void)
{
	uint64_t version = 0;

	CU_ASSERT_FALSE(store_init(g_path));
	CU_ASSERT_FALSE(store_init(NULL));
	CU_ASSERT_FALSE(store_init(""));
	CU_ASSERT_EQUAL(store_data_version(&version), STORE_OK);
	CU_ASSERT_EQUAL(store_data_version(NULL), STORE_ERR_ARGUMENT);
}

static void test_register_ca(void)
{
	unsigned char hash[STORE_CA_KEY_HASH_SIZE];
	store_ca_id_t first = 0;
	store_ca_id_t repeat = 0;
	store_ca_id_t rotated = 0;
	store_ca_record_t *records = NULL;
	size_t count = 0;
	bool found_first = false;
	bool found_rotated = false;

	memset(hash, 0x11, sizeof hash);
	CU_ASSERT_EQUAL(store_ca_register("ca-a", hash, sizeof hash, &first),
			STORE_OK);
	CU_ASSERT_TRUE(first > 0);
	CU_ASSERT_EQUAL(
		store_ca_register("ca-a", hash, sizeof hash, &repeat),
		STORE_OK);
	CU_ASSERT_EQUAL(first, repeat);

	hash[0] = 0x22;
	CU_ASSERT_EQUAL(
		store_ca_register("ca-a", hash, sizeof hash, &rotated),
		STORE_OK);
	CU_ASSERT_TRUE(rotated > 0);
	CU_ASSERT_TRUE(rotated != first);

	CU_ASSERT_EQUAL(store_ca_register(NULL, hash, sizeof hash, &repeat),
			STORE_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(store_ca_register("ca-b", hash, sizeof hash - 1,
					  &repeat),
			STORE_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(store_ca_register("ca-b", hash, sizeof hash, NULL),
			STORE_ERR_ARGUMENT);

	CU_ASSERT_EQUAL(store_ca_list(&records, &count), STORE_OK);
	CU_ASSERT_PTR_NOT_NULL(records);
	for (size_t i = 0; i < count; i++) {
		if (records[i].id == first)
			found_first = true;
		if (records[i].id == rotated)
			found_rotated = true;
	}
	CU_ASSERT_TRUE(found_first);
	CU_ASSERT_TRUE(found_rotated);
	store_ca_list_free(records, count);
}

static void test_config_crud(void)
{
	store_ca_config_t config;
	store_ca_config_t loaded;
	store_ca_config_t *list = NULL;
	size_t count = 0;
	bool found = false;

	fill_config(&config, "cfg-a", "endpoint-a");
	CU_ASSERT_EQUAL(store_ca_config_add(&config), STORE_OK);
	CU_ASSERT_EQUAL(store_ca_config_add(&config), STORE_ERR_DUPLICATE);

	CU_ASSERT_EQUAL(store_ca_config_get("cfg-a", &loaded), STORE_OK);
	CU_ASSERT_STRING_EQUAL(loaded.name, "cfg-a");
	CU_ASSERT_STRING_EQUAL(loaded.hsm_provider, "provider");
	CU_ASSERT_STRING_EQUAL(loaded.token_label, "token");
	CU_ASSERT_STRING_EQUAL(loaded.ocsp_responder_endpoint, "endpoint-a");
	CU_ASSERT_STRING_EQUAL(loaded.ocsp_signer_digest, "sha256");
	CU_ASSERT_EQUAL(loaded.crl_publish_period_min, 60);
	CU_ASSERT_EQUAL(loaded.ocsp_update_period_min, 10);
	store_ca_config_free(&loaded);

	CU_ASSERT_EQUAL(store_ca_config_get("missing", &loaded),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_ca_config_get(NULL, &loaded),
			STORE_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(store_ca_config_get("cfg-a", NULL),
			STORE_ERR_ARGUMENT);

	CU_ASSERT_EQUAL(store_ca_config_list(&list, &count), STORE_OK);
	CU_ASSERT_PTR_NOT_NULL(list);
	for (size_t i = 0; i < count; i++) {
		if (strcmp(list[i].name, "cfg-a") == 0)
			found = true;
	}
	CU_ASSERT_TRUE(found);
	store_ca_config_list_free(list, count);

	config.ocsp_responder_endpoint = (char *) "endpoint-b";
	config.crl_publish_period_min = 30;
	CU_ASSERT_EQUAL(store_ca_config_update(&config), STORE_OK);
	CU_ASSERT_EQUAL(store_ca_config_get("cfg-a", &loaded), STORE_OK);
	CU_ASSERT_STRING_EQUAL(loaded.ocsp_responder_endpoint, "endpoint-b");
	CU_ASSERT_EQUAL(loaded.crl_publish_period_min, 30);
	store_ca_config_free(&loaded);

	config.name = (char *) "missing";
	CU_ASSERT_EQUAL(store_ca_config_update(&config), STORE_ERR_NOT_FOUND);

	fill_config(&config, NULL, "endpoint-c");
	CU_ASSERT_EQUAL(store_ca_config_add(&config), STORE_ERR_ARGUMENT);
	fill_config(&config, "cfg-d", "endpoint-d");
	config.ca_cert = NULL;
	CU_ASSERT_EQUAL(store_ca_config_add(&config), STORE_ERR_ARGUMENT);
	fill_config(&config, "cfg-d", "endpoint-d");
	config.crl_number = (uint64_t) INT64_MAX + 1;
	CU_ASSERT_EQUAL(store_ca_config_add(&config), STORE_ERR_ARGUMENT);

	CU_ASSERT_EQUAL(store_ca_config_delete("cfg-a"), STORE_OK);
	CU_ASSERT_EQUAL(store_ca_config_get("cfg-a", &loaded),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_ca_config_delete("cfg-a"),
			STORE_ERR_NOT_FOUND);
}

static void test_certificate_crud(void)
{
	unsigned char hash[STORE_CA_KEY_HASH_SIZE];
	unsigned char first_serial[] = { 0x01 };
	unsigned char second_serial[] = { 0x02 };
	store_ca_id_t ca_id = 0;
	store_certificate_t certificate;
	store_certificate_t loaded;
	store_certificate_t *list = NULL;
	size_t count = 0;

	memset(hash, 0x33, sizeof hash);
	CU_ASSERT_EQUAL(store_ca_register("cert-ca", hash, sizeof hash,
					  &ca_id),
			STORE_OK);

	certificate.serial = first_serial;
	certificate.serial_length = sizeof first_serial;
	certificate.not_after = 1000;
	CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate), STORE_OK);
	CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
			STORE_ERR_DUPLICATE);
	CU_ASSERT_EQUAL(store_certificate_exists(ca_id, first_serial,
						 sizeof first_serial),
			STORE_OK);

	CU_ASSERT_EQUAL(store_certificate_get(ca_id, first_serial,
					      sizeof first_serial, &loaded),
			STORE_OK);
	CU_ASSERT_EQUAL(loaded.serial_length, sizeof first_serial);
	CU_ASSERT_EQUAL(memcmp(loaded.serial, first_serial,
			       sizeof first_serial),
			0);
	CU_ASSERT_EQUAL(loaded.not_after, 1000);
	store_certificate_free(&loaded);

	certificate.serial = second_serial;
	certificate.serial_length = sizeof second_serial;
	certificate.not_after = 2000;
	CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate), STORE_OK);

	CU_ASSERT_EQUAL(store_certificate_list(ca_id, 0, &list, &count),
			STORE_OK);
	CU_ASSERT_EQUAL(count, 2);
	CU_ASSERT_EQUAL(list[0].serial[0], 0x02);
	CU_ASSERT_EQUAL(list[1].serial[0], 0x01);
	store_certificate_list_free(list, count);

	CU_ASSERT_EQUAL(store_certificate_list(ca_id, 1, &list, &count),
			STORE_OK);
	CU_ASSERT_EQUAL(count, 1);
	store_certificate_list_free(list, count);

	certificate.serial = first_serial;
	certificate.serial_length = sizeof first_serial;
	certificate.not_after = 3000;
	CU_ASSERT_EQUAL(store_certificate_update(ca_id, &certificate),
			STORE_OK);
	CU_ASSERT_EQUAL(store_certificate_get(ca_id, first_serial,
					      sizeof first_serial, &loaded),
			STORE_OK);
	CU_ASSERT_EQUAL(loaded.not_after, 3000);
	store_certificate_free(&loaded);

	CU_ASSERT_EQUAL(store_certificate_delete(ca_id, first_serial,
						 sizeof first_serial),
			STORE_OK);
	CU_ASSERT_EQUAL(store_certificate_exists(ca_id, first_serial,
						 sizeof first_serial),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_certificate_delete(ca_id, first_serial,
						 sizeof first_serial),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_certificate_get(ca_id, first_serial,
					      sizeof first_serial, &loaded),
			STORE_ERR_NOT_FOUND);

	CU_ASSERT_EQUAL(store_certificate_add(0, &certificate),
			STORE_ERR_ARGUMENT);
	certificate.serial = NULL;
	CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
			STORE_ERR_ARGUMENT);

	{
		unsigned char zero_serial[] = { 0x00, 0x00 };
		unsigned char high_bit_serial[20];
		unsigned char too_long_serial[21] = { 0x01 };
		unsigned char max_serial[20];

		memset(high_bit_serial, 0x01, sizeof high_bit_serial);
		high_bit_serial[0] = 0x80;
		memset(max_serial, 0x11, sizeof max_serial);
		max_serial[0] = 0x7f;

		certificate.serial = zero_serial;
		certificate.serial_length = sizeof zero_serial;
		CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
				STORE_ERR_ARGUMENT);
		certificate.serial = high_bit_serial;
		certificate.serial_length = sizeof high_bit_serial;
		CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
				STORE_ERR_ARGUMENT);
		certificate.serial = too_long_serial;
		certificate.serial_length = sizeof too_long_serial;
		CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
				STORE_ERR_ARGUMENT);
		certificate.serial = max_serial;
		certificate.serial_length = 0;
		CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
				STORE_ERR_ARGUMENT);
		certificate.serial_length = sizeof max_serial;
		CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate),
				STORE_OK);
	}

	CU_ASSERT_EQUAL(store_certificate_list(999999, 0, &list, &count),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_certificate_list(ca_id, 0, NULL, &count),
			STORE_ERR_ARGUMENT);
}

static void test_revocation_crud(void)
{
	unsigned char hash[STORE_CA_KEY_HASH_SIZE];
	unsigned char serial[] = { 0x05 };
	unsigned char absent[] = { 0x06 };
	store_ca_id_t ca_id = 0;
	store_certificate_t certificate;
	store_revocation_t revocation;
	store_revocation_t loaded;
	store_revocation_t *list = NULL;
	size_t count = 0;

	memset(hash, 0x44, sizeof hash);
	CU_ASSERT_EQUAL(store_ca_register("revocation-ca", hash, sizeof hash,
					  &ca_id),
			STORE_OK);

	certificate.serial = serial;
	certificate.serial_length = sizeof serial;
	certificate.not_after = 100;
	CU_ASSERT_EQUAL(store_certificate_add(ca_id, &certificate), STORE_OK);

	revocation.serial = absent;
	revocation.serial_length = sizeof absent;
	revocation.revoked_at = 1000;
	revocation.reason = 1;
	CU_ASSERT_EQUAL(store_revocation_add(ca_id, &revocation),
			STORE_ERR_NOT_FOUND);

	revocation.serial = serial;
	revocation.serial_length = sizeof serial;
	revocation.revoked_at = 0;
	CU_ASSERT_EQUAL(store_revocation_add(ca_id, &revocation),
			STORE_ERR_ARGUMENT);
	revocation.revoked_at = -1;
	CU_ASSERT_EQUAL(store_revocation_add(ca_id, &revocation),
			STORE_ERR_ARGUMENT);
	revocation.revoked_at = (int64_t) 253402300800LL;
	CU_ASSERT_EQUAL(store_revocation_add(ca_id, &revocation),
			STORE_ERR_ARGUMENT);
	revocation.revoked_at = 1000;
	CU_ASSERT_EQUAL(store_revocation_add(ca_id, &revocation), STORE_OK);
	CU_ASSERT_EQUAL(store_revocation_add(ca_id, &revocation),
			STORE_ERR_DUPLICATE);

	CU_ASSERT_EQUAL(store_revocation_get(ca_id, serial, sizeof serial,
					     &loaded),
			STORE_OK);
	CU_ASSERT_EQUAL(loaded.revoked_at, 1000);
	CU_ASSERT_EQUAL(loaded.reason, 1);
	store_revocation_free(&loaded);

	CU_ASSERT_EQUAL(store_revocation_list(ca_id, 0, &list, &count),
			STORE_OK);
	CU_ASSERT_EQUAL(count, 1);
	store_revocation_list_free(list, count);

	revocation.revoked_at = 2000;
	revocation.reason = 4;
	CU_ASSERT_EQUAL(store_revocation_update(ca_id, &revocation),
			STORE_OK);
	CU_ASSERT_EQUAL(store_revocation_get(ca_id, serial, sizeof serial,
					     &loaded),
			STORE_OK);
	CU_ASSERT_EQUAL(loaded.revoked_at, 2000);
	CU_ASSERT_EQUAL(loaded.reason, 4);
	store_revocation_free(&loaded);

	CU_ASSERT_EQUAL(store_certificate_delete(ca_id, serial,
						 sizeof serial),
			STORE_ERR_CONFLICT);
	CU_ASSERT_EQUAL(store_revocation_delete(ca_id, serial,
						sizeof serial),
			STORE_OK);
	CU_ASSERT_EQUAL(store_revocation_get(ca_id, serial, sizeof serial,
					     &loaded),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_certificate_delete(ca_id, serial,
						 sizeof serial),
			STORE_OK);
	CU_ASSERT_EQUAL(store_revocation_delete(ca_id, serial,
						sizeof serial),
			STORE_ERR_NOT_FOUND);

	CU_ASSERT_EQUAL(store_revocation_add(0, &revocation),
			STORE_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(store_revocation_get(ca_id, NULL, 1, &loaded),
			STORE_ERR_ARGUMENT);
}

static void test_crl_number(void)
{
	unsigned char hash[STORE_CA_KEY_HASH_SIZE];
	store_ca_id_t ca_id = 0;
	uint64_t first = 0;
	uint64_t second = 0;
	store_ca_config_t config;
	store_ca_config_t loaded;

	memset(hash, 0x55, sizeof hash);
	CU_ASSERT_EQUAL(store_ca_register("crl-ca", hash, sizeof hash,
					  &ca_id),
			STORE_OK);

	CU_ASSERT_EQUAL(store_crl_number_reserve(ca_id, &first), STORE_OK);
	CU_ASSERT_TRUE(first > 0);
	CU_ASSERT_EQUAL(store_crl_number_reserve(ca_id, &second), STORE_OK);
	CU_ASSERT_TRUE(second > first);
	CU_ASSERT_EQUAL(store_crl_number_reserve(999999, &second),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_crl_number_reserve(ca_id, NULL),
			STORE_ERR_ARGUMENT);

	fill_config(&config, "crl-config", "crl-endpoint");
	config.crl_number = 7;
	CU_ASSERT_EQUAL(store_ca_config_add(&config), STORE_OK);
	CU_ASSERT_EQUAL(store_ca_config_get("crl-config", &loaded), STORE_OK);
	CU_ASSERT_EQUAL(loaded.crl_number, 7);
	store_ca_config_free(&loaded);

	CU_ASSERT_EQUAL(store_ca_config_set_crl_number("crl-config", 42),
			STORE_OK);
	CU_ASSERT_EQUAL(store_ca_config_get("crl-config", &loaded), STORE_OK);
	CU_ASSERT_EQUAL(loaded.crl_number, 42);
	store_ca_config_free(&loaded);
	CU_ASSERT_EQUAL(store_ca_config_set_crl_number("missing", 1),
			STORE_ERR_NOT_FOUND);
	CU_ASSERT_EQUAL(store_ca_config_set_crl_number(NULL, 1),
			STORE_ERR_ARGUMENT);
}

void test_store_register(void)
{
	CU_pSuite suite = CU_add_suite("store", suite_init, suite_cleanup);

	CU_add_test(suite, "open", test_open);
	CU_add_test(suite, "ca_register", test_register_ca);
	CU_add_test(suite, "config_crud", test_config_crud);
	CU_add_test(suite, "certificate_crud", test_certificate_crud);
	CU_add_test(suite, "revocation_crud", test_revocation_crud);
	CU_add_test(suite, "crl_number", test_crl_number);
}
