/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <CUnit/Basic.h>

#include <anyca/config.h>
#include <anyca/core.h>
#include <anyca/ossl/x509.h>

#include "../test_support.h"
#include "test_suites.h"

static config_t *test_config(const char *directory)
{
	char yaml[PATH_MAX * 2];
	char path[PATH_MAX];
	config_t *config = NULL;

	snprintf(yaml, sizeof yaml,
		 "store:\n"
		 "  path: \"%s/store.db\"\n"
		 "http:\n"
		 "  address: \"127.0.0.1\"\n"
		 "  port: 8080\n"
		 "hsm_providers:\n"
		 "  - name: \"unused\"\n"
		 "    library: \"/nonexistent/provider.so\"\n",
		 directory);
	snprintf(path, sizeof path, "%s/anyca.yaml", directory);
	if (!test_write_file(path, yaml, strlen(yaml)))
		return NULL;
	if (config_load(path, &config) != CONFIG_OK)
		return NULL;
	return config;
}

/* Configuration for a complete CA backed by a SoftHSM token. */
static config_t *test_publish_config(const char *directory)
{
	char yaml[PATH_MAX * 4];
	char path[PATH_MAX];
	config_t *config = NULL;

	snprintf(yaml, sizeof yaml,
		 "store:\n"
		 "  path: \"%s/store.db\"\n"
		 "http:\n"
		 "  address: \"127.0.0.1\"\n"
		 "  port: 8080\n"
		 "crl_publish_path: \"%s/crl\"\n"
		 "cacerts_publish_path: \"%s/cacerts\"\n"
		 "hsm_providers:\n"
		 "  - name: \"soft\"\n"
		 "    library: \"%s\"\n",
		 directory, directory, directory, TEST_SOFTHSM_MODULE);
	snprintf(path, sizeof path, "%s/anyca.yaml", directory);
	if (!test_write_file(path, yaml, strlen(yaml)))
		return NULL;
	if (config_load(path, &config) != CONFIG_OK)
		return NULL;
	return config;
}

static void fill_broken_ca(store_ca_config_t *config)
{
	static unsigned char certificate[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };

	memset(config, 0, sizeof *config);
	config->name = (char *) "broken-ca";
	config->hsm_provider = (char *) "missing-provider";
	config->token_label = (char *) "token";
	config->pin = (char *) "1234";
	config->key_label = (char *) "key";
	config->ca_cert = certificate;
	config->ca_cert_length = sizeof certificate;
	config->ocsp_signer_token_label = (char *) "token";
	config->ocsp_signer_pin = (char *) "1234";
	config->ocsp_signer_key_label = (char *) "ocsp";
	config->ocsp_signer_cert = certificate;
	config->ocsp_signer_cert_length = sizeof certificate;
	config->ocsp_responder_endpoint = (char *) "broken";
}


static void test_uninitialized(void)
{
	core_fini();

	CU_ASSERT_EQUAL(core_ca_count(), 0);
	CU_ASSERT_PTR_NULL(core_ca_at(0));
	CU_ASSERT_PTR_NULL(core_ca_by_name(NULL));
	CU_ASSERT_PTR_NULL(core_ca_by_name("missing"));
	CU_ASSERT_PTR_NULL(core_ca_by_ocsp_endpoint(NULL));
	CU_ASSERT_PTR_NULL(core_ca_by_ocsp_endpoint("missing"));
	CU_ASSERT_PTR_NULL(core_ca_token(NULL));
	CU_ASSERT_PTR_NULL(core_ca_ocsp_signer_token(NULL));
	CU_ASSERT_EQUAL(core_ca_store_id(NULL), 0);
	CU_ASSERT_PTR_NULL(core_crl_publish_path());
	CU_ASSERT_PTR_NULL(core_cacerts_publish_path());

	core_session_begin();
	core_session_end();

	CU_ASSERT_FALSE(core_init(NULL));
	core_fini();
}

/*
 * Change the CA configuration from a second process.  PRAGMA data_version
 * only changes on commits made by another connection, so an in-process write
 * would not trigger the core's reload path.
 */
static int store_writer(const char *store_path, bool add)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		store_ca_config_t broken;

		/* The child must not reuse the inherited connection. */
		store_fini();
		if (!store_init(store_path))
			_exit(2);
		if (add) {
			fill_broken_ca(&broken);
			if (store_ca_config_add(&broken) != STORE_OK)
				_exit(3);
		} else if (store_ca_config_delete("broken-ca") != STORE_OK) {
			_exit(4);
		}
		store_fini();
		_exit(0);
	}

	if (waitpid(pid, &status, 0) != pid)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status) == 0 ? 0 : -1;
}

static void test_init_and_reload(void)
{
	char *directory = test_temp_dir();
	char store_path[PATH_MAX];
	config_t *config;
	store_ca_config_t broken;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(store_path, sizeof store_path, "%s/store.db", directory);

	/* Load a broken CA at start-up so the skip path runs during init. */
	CU_ASSERT_TRUE_FATAL(store_init(store_path));
	fill_broken_ca(&broken);
	CU_ASSERT_EQUAL_FATAL(store_ca_config_add(&broken), STORE_OK);
	store_fini();

	config = test_config(directory);
	CU_ASSERT_PTR_NOT_NULL_FATAL(config);

	CU_ASSERT_TRUE_FATAL(core_init(config));
	CU_ASSERT_EQUAL(core_ca_count(), 0);
	CU_ASSERT_PTR_NULL(core_ca_at(0));
	CU_ASSERT_PTR_NULL(core_ca_by_name("broken-ca"));

	/* A second init while initialized must be rejected without side effects. */
	CU_ASSERT_FALSE(core_init(config));

	/* Another process removes the broken CA: the session reloads it away. */
	CU_ASSERT_EQUAL(store_writer(store_path, false), 0);
	core_session_begin();
	CU_ASSERT_EQUAL(core_ca_count(), 0);
	core_session_end();

	/*
	 * Another process adds it back.  The reload fails to load that CA but
	 * must keep serving; because the rebuild was incomplete it must not
	 * record the new store version, so the following delete is still seen.
	 */
	CU_ASSERT_EQUAL(store_writer(store_path, true), 0);
	core_session_begin();
	CU_ASSERT_EQUAL(core_ca_count(), 0);
	CU_ASSERT_PTR_NULL(core_ca_by_name("broken-ca"));
	CU_ASSERT_PTR_NULL(core_ca_by_ocsp_endpoint("broken"));
	core_session_end();

	CU_ASSERT_EQUAL(store_writer(store_path, false), 0);
	core_session_begin();
	CU_ASSERT_EQUAL(core_ca_count(), 0);
	core_session_end();

	core_fini();
	config_free(config);
	test_remove_tree(directory);
	free(directory);
}

static void test_publish_crl(void)
{
	char *directory = test_temp_dir();
	char token_dir[PATH_MAX];
	char conf_path[PATH_MAX];
	char store_path[PATH_MAX];
	char pem_path[PATH_MAX];
	char crl_path[PATH_MAX];
	char crt_path[PATH_MAX];
	config_t *config = NULL;
	EVP_PKEY *key = NULL;
	X509 *certificate = NULL;
	unsigned char *der = NULL;
	size_t der_length = 0;
	FILE *file = NULL;
	store_ca_config_t ca_config;
	store_ca_config_t loaded;
	ca_t *ca = NULL;
	X509_CRL *crl = NULL;
	X509 *published = NULL;
	uint64_t crl_number = 0;

	if (!test_softhsm_available()) {
		fprintf(stderr, "SoftHSM not available; skipping\n");
		free(directory);
		return;
	}
	if (directory == NULL)
		return;
	if (!test_softhsm_init_token(token_dir, sizeof token_dir, conf_path,
				     sizeof conf_path)) {
		CU_FAIL("cannot initialise a SoftHSM token");
		goto done;
	}

	key = test_rsa_key();
	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	certificate = test_certificate(key, NULL, NULL, 0x77, TEST_CERT_CA);
	CU_ASSERT_PTR_NOT_NULL_FATAL(certificate);
	der = test_cert_der(certificate, &der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(der);

	/* Import a key generated outside the token so the CA certificate and
	 * the PKCS #11 private key share the same key pair. */
	snprintf(pem_path, sizeof pem_path, "%s/ca-key.pem", directory);
	file = fopen(pem_path, "wb");
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);
	CU_ASSERT_TRUE_FATAL(PEM_write_PrivateKey(file, key, NULL, NULL, 0,
						  NULL, NULL));
	fclose(file);
	file = NULL;
	CU_ASSERT_TRUE_FATAL(
		test_softhsm_import_key(pem_path, "ca-key", "01"));

	snprintf(store_path, sizeof store_path, "%s/store.db", directory);
	CU_ASSERT_TRUE_FATAL(store_init(store_path));
	memset(&ca_config, 0, sizeof ca_config);
	ca_config.name = (char *) "publish-ca";
	ca_config.hsm_provider = (char *) "soft";
	ca_config.token_label = (char *) TEST_SOFTHSM_TOKEN_LABEL;
	ca_config.pin = (char *) TEST_SOFTHSM_PIN;
	ca_config.key_label = (char *) "ca-key";
	ca_config.ca_cert = der;
	ca_config.ca_cert_length = der_length;
	ca_config.ocsp_signer_token_label =
		(char *) TEST_SOFTHSM_TOKEN_LABEL;
	ca_config.ocsp_signer_pin = (char *) TEST_SOFTHSM_PIN;
	ca_config.ocsp_signer_key_label = (char *) "ca-key";
	ca_config.ocsp_signer_cert = der;
	ca_config.ocsp_signer_cert_length = der_length;
	ca_config.crl_publish_period_min = 60;
	ca_config.ocsp_update_period_min = 10;
	ca_config.ocsp_responder_endpoint = (char *) "publish";
	CU_ASSERT_EQUAL_FATAL(store_ca_config_add(&ca_config), STORE_OK);
	store_fini();

	config = test_publish_config(directory);
	CU_ASSERT_PTR_NOT_NULL_FATAL(config);
	CU_ASSERT_TRUE_FATAL(core_init(config));

	core_session_begin();
	ca = core_ca_by_name("publish-ca");
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	CU_ASSERT_TRUE(core_publish_crl(ca));
	CU_ASSERT_TRUE(core_publish_ca_certificate(ca));
	crl_number = ca->crl_number;
	core_session_end();

	snprintf(crl_path, sizeof crl_path, "%s/crl/publish-ca/publish-ca.crl",
		 directory);
	file = fopen(crl_path, "rb");
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);
	crl = d2i_X509_CRL_fp(file, NULL);
	fclose(file);
	file = NULL;
	CU_ASSERT_PTR_NOT_NULL(crl);
	if (crl != NULL) {
		CU_ASSERT_TRUE(ossl_x509_crl_issued_by(crl, certificate));
		CU_ASSERT_PTR_NOT_NULL(X509_CRL_get0_nextUpdate(crl));
	}

	snprintf(crt_path, sizeof crt_path, "%s/cacerts/publish-ca.crt",
		 directory);
	file = fopen(crt_path, "rb");
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);
	published = d2i_X509_fp(file, NULL);
	fclose(file);
	file = NULL;
	CU_ASSERT_PTR_NOT_NULL(published);
	if (published != NULL)
		CU_ASSERT_EQUAL(X509_cmp(published, certificate), 0);

	CU_ASSERT_TRUE(crl_number > 0);
	CU_ASSERT_EQUAL(store_ca_config_get("publish-ca", &loaded), STORE_OK);
	CU_ASSERT_EQUAL(loaded.crl_number, crl_number);
	store_ca_config_free(&loaded);

	core_fini();

done:
	if (file != NULL)
		fclose(file);
	X509_CRL_free(crl);
	X509_free(published);
	OPENSSL_free(der);
	X509_free(certificate);
	EVP_PKEY_free(key);
	if (config != NULL)
		config_free(config);
	test_remove_tree(directory);
	free(directory);
}

struct session_concurrency {
	mtx_t lock;
	cnd_t condition;
	int holder_ready;
	int release_holder;
	int second_done;
};

/* Wait on the condition until *flag is set, with a bounded timeout. */
static bool wait_flag(struct session_concurrency *state, int *flag,
		      int seconds)
{
	struct timespec deadline;

	timespec_get(&deadline, TIME_UTC);
	deadline.tv_sec += seconds;
	while (*flag == 0) {
		int result = cnd_timedwait(&state->condition, &state->lock,
					   &deadline);

		if (result != thrd_success)
			return false;
	}
	return true;
}

/*
 * One session held by a thread while another thread opens and closes a
 * session.  With a shared reader lock both run concurrently; a single global
 * mutex would make the second one wait for the first to finish.
 */
static int hold_session_thread(void *argument)
{
	struct session_concurrency *state = argument;

	core_session_begin();
	mtx_lock(&state->lock);
	state->holder_ready = 1;
	cnd_broadcast(&state->condition);
	while (!state->release_holder)
		(void) cnd_wait(&state->condition, &state->lock);
	mtx_unlock(&state->lock);
	core_session_end();
	return 0;
}

static int second_session_thread(void *argument)
{
	struct session_concurrency *state = argument;

	core_session_begin();
	core_session_end();
	mtx_lock(&state->lock);
	state->second_done = 1;
	cnd_broadcast(&state->condition);
	mtx_unlock(&state->lock);
	return 0;
}

static void test_session_concurrency(void)
{
	char *directory = test_temp_dir();
	config_t *config;
	struct session_concurrency state = { 0 };
	thrd_t holder;
	thrd_t second;
	bool created_holder = false;
	bool created_second = false;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	config = test_config(directory);
	CU_ASSERT_PTR_NOT_NULL_FATAL(config);
	CU_ASSERT_TRUE_FATAL(core_init(config));

	CU_ASSERT_EQUAL_FATAL(mtx_init(&state.lock, mtx_plain), thrd_success);
	CU_ASSERT_EQUAL_FATAL(cnd_init(&state.condition), thrd_success);

	created_holder = thrd_create(&holder, hold_session_thread, &state)
		== thrd_success;
	mtx_lock(&state.lock);
	if (!created_holder
	    || !wait_flag(&state, &state.holder_ready, 5)) {
		mtx_unlock(&state.lock);
		CU_FAIL("the first session did not start");
		goto done;
	}
	mtx_unlock(&state.lock);

	created_second = thrd_create(&second, second_session_thread, &state)
		== thrd_success;
	if (!created_second) {
		CU_FAIL("cannot create the second session thread");
		goto done;
	}

	mtx_lock(&state.lock);
	CU_ASSERT_TRUE(wait_flag(&state, &state.second_done, 5));
	mtx_unlock(&state.lock);

done:
	mtx_lock(&state.lock);
	state.release_holder = 1;
	cnd_broadcast(&state.condition);
	mtx_unlock(&state.lock);
	if (created_second)
		(void) thrd_join(second, NULL);
	if (created_holder)
		(void) thrd_join(holder, NULL);
	cnd_destroy(&state.condition);
	mtx_destroy(&state.lock);
	core_fini();
	config_free(config);
	test_remove_tree(directory);
	free(directory);
}

void test_core_register(void)
{
	CU_pSuite suite = CU_add_suite("core", NULL, NULL);

	CU_add_test(suite, "uninitialized", test_uninitialized);
	CU_add_test(suite, "session_concurrency", test_session_concurrency);
	CU_add_test(suite, "init_and_reload", test_init_and_reload);
	CU_add_test(suite, "publish_crl", test_publish_crl);
}
