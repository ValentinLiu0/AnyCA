/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/objects.h>

#include <CUnit/Basic.h>

#include <anyca/ca.h>
#include <anyca/osal/memory.h>

#include "../test_support.h"
#include "test_suites.h"

static void set_blob(ca_blob_t *blob, const unsigned char *data,
		     size_t length)
{
	blob->data = malloc(length);
	if (blob->data != NULL) {
		memcpy(blob->data, data, length);
		blob->length = length;
	}
}

static void test_new(void)
{
	ca_t *ca = ca_new();

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	CU_ASSERT_PTR_NULL(ca->name);
	CU_ASSERT_PTR_NULL(ca->certificate);
	CU_ASSERT_PTR_NULL(ca->ocsp_signer_certificate);
	CU_ASSERT_EQUAL(ca->ca_cert_der.length, 0);
	ca_free(ca);
	ca_free(NULL);
}

static void test_names(void)
{
	CU_ASSERT_TRUE(ca_name_is_valid("root-ca"));
	CU_ASSERT_TRUE(ca_name_is_valid("a b"));
	CU_ASSERT_TRUE(ca_name_is_valid("\xe4\xb8\xad\xe6\x96\x87"));
	CU_ASSERT_FALSE(ca_name_is_valid(NULL));
	CU_ASSERT_FALSE(ca_name_is_valid(""));
	CU_ASSERT_FALSE(ca_name_is_valid("."));
	CU_ASSERT_FALSE(ca_name_is_valid(".."));
	CU_ASSERT_FALSE(ca_name_is_valid("a/b"));
	CU_ASSERT_FALSE(ca_name_is_valid("a\\b"));
	CU_ASSERT_FALSE(ca_name_is_valid("a:b"));
	CU_ASSERT_FALSE(ca_name_is_valid("a\tb"));
	CU_ASSERT_FALSE(ca_name_is_valid("a\x7f"));

	CU_ASSERT_TRUE(ca_ocsp_responder_endpoint_is_valid("root-ca"));
	CU_ASSERT_TRUE(ca_ocsp_responder_endpoint_is_valid("a b"));
	CU_ASSERT_FALSE(ca_ocsp_responder_endpoint_is_valid(NULL));
	CU_ASSERT_FALSE(ca_ocsp_responder_endpoint_is_valid(""));
	CU_ASSERT_FALSE(ca_ocsp_responder_endpoint_is_valid("a/b"));
	CU_ASSERT_FALSE(ca_ocsp_responder_endpoint_is_valid("a?b"));
	CU_ASSERT_FALSE(ca_ocsp_responder_endpoint_is_valid("a#b"));
	CU_ASSERT_FALSE(ca_ocsp_responder_endpoint_is_valid("a\tb"));
}

static void test_load(void)
{
	EVP_PKEY *ca_key = test_rsa_key();
	EVP_PKEY *leaf_key = test_rsa_key();
	X509 *certificate;
	X509 *leaf;
	X509 *other;
	X509 *signer;
	unsigned char *der;
	unsigned char *leaf_der;
	unsigned char *signer_der;
	size_t der_length = 0;
	size_t leaf_der_length = 0;
	size_t signer_der_length = 0;
	ca_t *ca;
	unsigned char *serial = NULL;
	size_t serial_length = 0;
	int64_t not_after = 0;
	unsigned char name_hash[CA_MAX_HASH_SIZE];
	unsigned char key_hash[CA_MAX_HASH_SIZE];
	char *directory;
	char path[PATH_MAX];

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_key);
	certificate = test_certificate(ca_key, NULL, NULL, 0x20,
				       TEST_CERT_CA);
	leaf = test_certificate(leaf_key, certificate, ca_key, 0x21, 0);
	other = test_certificate(leaf_key, NULL, NULL, 0x22, TEST_CERT_CA);
	signer = test_certificate(leaf_key, certificate, ca_key, 0x23,
				  TEST_CERT_OCSP_SIGNER);
	CU_ASSERT_PTR_NOT_NULL_FATAL(certificate);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf);
	CU_ASSERT_PTR_NOT_NULL_FATAL(other);
	CU_ASSERT_PTR_NOT_NULL_FATAL(signer);
	der = test_cert_der(certificate, &der_length);
	leaf_der = test_cert_der(leaf, &leaf_der_length);
	signer_der = test_cert_der(signer, &signer_der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(der);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_der);
	CU_ASSERT_PTR_NOT_NULL_FATAL(signer_der);

	ca = ca_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	set_blob(&ca->ca_cert_der, der, der_length);
	CU_ASSERT_TRUE(ca_load_certificate(ca));
	CU_ASSERT_PTR_NOT_NULL(ca->certificate);
	CU_ASSERT_TRUE(ca->issuer_name.length > 0);
	CU_ASSERT_TRUE(ca->issuer_key.length > 0);
	CU_ASSERT_EQUAL(ca->issuer_name_hash_sha1.length, 20);
	CU_ASSERT_EQUAL(ca->issuer_key_hash_sha1.length, 20);
	CU_ASSERT_EQUAL(ca->issuer_name_hash_sha256.length, 32);
	CU_ASSERT_EQUAL(ca->issuer_key_hash_sha256.length, 32);
	CU_ASSERT_EQUAL(ca->spki_hash_sha256.length, 32);

	CU_ASSERT_TRUE(ca_issuer_matches(
		ca, NID_sha1, ca->issuer_name_hash_sha1.data,
		ca->issuer_name_hash_sha1.length,
		ca->issuer_key_hash_sha1.data,
		ca->issuer_key_hash_sha1.length));
	CU_ASSERT_TRUE(ca_issuer_matches(
		ca, NID_sha256, ca->issuer_name_hash_sha256.data,
		ca->issuer_name_hash_sha256.length,
		ca->issuer_key_hash_sha256.data,
		ca->issuer_key_hash_sha256.length));

	memcpy(name_hash, ca->issuer_name_hash_sha1.data,
	       ca->issuer_name_hash_sha1.length);
	memcpy(key_hash, ca->issuer_key_hash_sha1.data,
	       ca->issuer_key_hash_sha1.length);
	name_hash[0] ^= 0xff;
	CU_ASSERT_FALSE(ca_issuer_matches(ca, NID_sha1, name_hash,
					  ca->issuer_name_hash_sha1.length,
					  key_hash,
					  ca->issuer_key_hash_sha1.length));
	CU_ASSERT_FALSE(ca_issuer_matches(ca, NID_md5, name_hash,
					  ca->issuer_name_hash_sha1.length,
					  key_hash,
					  ca->issuer_key_hash_sha1.length));
	CU_ASSERT_FALSE(ca_issuer_matches(ca, NID_sha1, NULL, 0, key_hash,
					  ca->issuer_key_hash_sha1.length));

	CU_ASSERT_TRUE(ca_certificate_serial(ca->certificate, &serial,
					     &serial_length));
	CU_ASSERT_EQUAL(serial_length, 1);
	CU_ASSERT_EQUAL(serial[0], 0x20);
	osal_free(serial);
	CU_ASSERT_TRUE(ca_certificate_not_after(ca->certificate, &not_after));
	CU_ASSERT_TRUE(not_after > (int64_t) time(NULL));

	CU_ASSERT_TRUE(ca_issued_certificate(ca, leaf));
	CU_ASSERT_FALSE(ca_issued_certificate(ca, other));
	CU_ASSERT_FALSE(ca_issued_certificate(NULL, leaf));

	set_blob(&ca->ocsp_signer_cert_der, signer_der, signer_der_length);
	CU_ASSERT_TRUE(ca_load_certificate(ca));
	CU_ASSERT_TRUE(ca_ocsp_signer_authorized(ca));

	free(ca->ocsp_signer_cert_der.data);
	set_blob(&ca->ocsp_signer_cert_der, der, der_length);
	CU_ASSERT_TRUE(ca_load_certificate(ca));
	CU_ASSERT_TRUE(ca_ocsp_signer_authorized(ca));

	/*
	 * An end-entity certificate issued by the CA but without the OCSP
	 * Signing extended key usage must not be accepted as a signer.
	 */
	free(ca->ocsp_signer_cert_der.data);
	set_blob(&ca->ocsp_signer_cert_der, leaf_der, leaf_der_length);
	CU_ASSERT_FALSE(ca_load_certificate(ca));

	directory = test_temp_dir();
	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(path, sizeof path, "%s/ca.der", directory);
	CU_ASSERT_TRUE(test_write_file(path, der, der_length));
	ca_certificate_free(ca_certificate_load(path));
	CU_ASSERT_PTR_NULL(ca_certificate_load(NULL));

	X509 *loaded = ca_certificate_load_der(der, der_length);
	CU_ASSERT_PTR_NOT_NULL(loaded);
	ca_certificate_free(loaded);
	CU_ASSERT_PTR_NULL(ca_certificate_load_der(NULL, 0));
	CU_ASSERT_PTR_NULL(ca_certificate_load_der(der, 0));

	free(ca->ca_cert_der.data);
	set_blob(&ca->ca_cert_der, (const unsigned char *) "bad", 3);
	CU_ASSERT_FALSE(ca_load_certificate(ca));
	CU_ASSERT_PTR_NOT_NULL(ca->certificate);

	{
		X509 *not_ca = test_certificate(leaf_key, NULL, NULL, 0x24, 0);
		unsigned char *not_ca_der;
		size_t not_ca_length = 0;
		ca_t *invalid = ca_new();

		CU_ASSERT_PTR_NOT_NULL_FATAL(not_ca);
		not_ca_der = test_cert_der(not_ca, &not_ca_length);
		CU_ASSERT_PTR_NOT_NULL_FATAL(not_ca_der);
		set_blob(&invalid->ca_cert_der, not_ca_der, not_ca_length);
		CU_ASSERT_FALSE(ca_load_certificate(invalid));
		ca_free(invalid);
		OPENSSL_free(not_ca_der);
		X509_free(not_ca);
	}

	CU_ASSERT_FALSE(ca_load_certificate(NULL));
	ca_free(ca);

	test_remove_tree(directory);
	free(directory);
	OPENSSL_free(signer_der);
	OPENSSL_free(leaf_der);
	OPENSSL_free(der);
	X509_free(signer);
	X509_free(other);
	X509_free(leaf);
	X509_free(certificate);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(ca_key);
}

void test_ca_register(void)
{
	CU_pSuite suite = CU_add_suite("ca", NULL, NULL);

	CU_add_test(suite, "new", test_new);
	CU_add_test(suite, "names", test_names);
	CU_add_test(suite, "load", test_load);
}
