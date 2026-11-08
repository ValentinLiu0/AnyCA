/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <CUnit/Basic.h>

#include <anyca/cert.h>
#include <anyca/ossl/x509.h>

#include "../test_support.h"
#include "test_suites.h"

static void check_subject_cn(X509 *certificate, const char *expected)
{
	char text[128] = { 0 };
	int length = X509_NAME_get_text_by_NID(
		X509_get_subject_name(certificate), NID_commonName, text,
		sizeof text);

	CU_ASSERT_TRUE(length > 0);
	CU_ASSERT_STRING_EQUAL(text, expected);
}

static void test_setters(void)
{
	cert_builder_t *builder = cert_builder_new();
	unsigned char zeros[] = { 0x00, 0x00 };
	unsigned char long_serial[21] = { 0x01 };

	CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
	CU_ASSERT_TRUE(cert_builder_set_serial(builder, NULL, 0));
	CU_ASSERT_FALSE(cert_builder_set_serial(builder, NULL, 1));
	CU_ASSERT_FALSE(cert_builder_set_serial(builder, zeros,
						sizeof zeros));
	CU_ASSERT_FALSE(cert_builder_set_serial(builder, long_serial,
						sizeof long_serial));
	CU_ASSERT_TRUE(cert_builder_set_subject(
		builder, "CN=Test,O=AnyCA,C=CN"));
	CU_ASSERT_FALSE(cert_builder_set_subject(builder, NULL));
	CU_ASSERT_TRUE(cert_builder_set_validity(builder, 0, 30));
	CU_ASSERT_FALSE(cert_builder_add_key_usage(builder, 0));
	CU_ASSERT_FALSE(cert_builder_add_key_usage(builder, 0x400));
	CU_ASSERT_FALSE(cert_builder_add_basic_constraints(builder, false,
							   true, 1));
	CU_ASSERT_FALSE(cert_builder_add_extended_key_usage(builder, NULL,
							    0));
	CU_ASSERT_FALSE(cert_builder_add_subject_key_identifier(builder));
	CU_ASSERT_FALSE(cert_builder_add_authority_key_identifier(builder));
	CU_ASSERT_FALSE(cert_builder_add_extension(builder, NULL, false,
						   NULL, 0));
	CU_ASSERT_FALSE(cert_builder_add_extension(builder, "2.5.29.19",
						   false, NULL, 1));
	cert_builder_free(builder);
	cert_builder_free(NULL);
}

static void test_build_self_signed(void)
{
	EVP_PKEY *key = test_rsa_key();
	cert_builder_t *builder;
	cert_blob_t tbs = { 0 };
	cert_blob_t certificate = { 0 };
	unsigned char serial[] = { 0x01, 0x02 };
	unsigned char *spki;
	size_t spki_length = 0;
	unsigned char *signature = NULL;
	size_t signature_length = 0;
	X509 *parsed;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	builder = cert_builder_new();
	spki = test_spki_der(key, &spki_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
	CU_ASSERT_PTR_NOT_NULL_FATAL(spki);

	CU_ASSERT_TRUE(cert_builder_set_subject(
		builder, "CN=Builder Test,O=AnyCA,C=CN"));
	CU_ASSERT_TRUE(cert_builder_set_public_key_der(builder, spki,
						       spki_length));
	CU_ASSERT_TRUE(cert_builder_set_serial(builder, serial,
					       sizeof serial));
	CU_ASSERT_TRUE(cert_builder_set_validity(builder, 0, 1));
	CU_ASSERT_TRUE(cert_builder_add_basic_constraints(builder, true,
							  false, 0));
	CU_ASSERT_TRUE(cert_builder_add_key_usage(
		builder,
		CERT_KU_DIGITAL_SIGNATURE | CERT_KU_KEY_CERT_SIGN));
	CU_ASSERT_TRUE(cert_builder_add_subject_key_identifier(builder));

	CU_ASSERT_TRUE(cert_builder_tbs(builder, CERT_SIGNATURE_RSA,
					CERT_DIGEST_SHA256, &tbs));
	CU_ASSERT_TRUE(test_sign(key, tbs.data, tbs.length, &signature,
				 &signature_length));
	CU_ASSERT_TRUE(cert_builder_assemble(
		builder, CERT_SIGNATURE_RSA, CERT_DIGEST_SHA256, tbs.data,
		tbs.length, signature, signature_length, &certificate));

	parsed = ossl_x509_load_der(certificate.data, certificate.length);
	CU_ASSERT_PTR_NOT_NULL(parsed);
	if (parsed != NULL) {
		check_subject_cn(parsed, "Builder Test");
		CU_ASSERT_EQUAL(
			ASN1_INTEGER_get(X509_get_serialNumber(parsed)),
			0x0102);
		CU_ASSERT_TRUE(X509_check_ca(parsed) > 0);
		CU_ASSERT_TRUE(ossl_x509_verify_self_signature(parsed));
		X509_free(parsed);
	}

	{
		cert_builder_t *empty = cert_builder_new();
		cert_blob_t missing = { 0 };

		CU_ASSERT_FALSE(cert_builder_tbs(empty, CERT_SIGNATURE_RSA,
						 CERT_DIGEST_SHA256,
						 &missing));
		cert_builder_free(empty);
	}
	CU_ASSERT_FALSE(cert_builder_tbs(NULL, CERT_SIGNATURE_RSA,
					 CERT_DIGEST_SHA256, &tbs));
	CU_ASSERT_FALSE(cert_builder_assemble(
		builder, CERT_SIGNATURE_RSA, CERT_DIGEST_SHA256, tbs.data,
		tbs.length, signature, 0, &certificate));

	cert_blob_free(&certificate);
	cert_blob_free(&tbs);
	OPENSSL_free(signature);
	OPENSSL_free(spki);
	cert_builder_free(builder);
	EVP_PKEY_free(key);
}

static void test_build_issued(void)
{
	EVP_PKEY *ca_key = test_rsa_key();
	EVP_PKEY *leaf_key = test_rsa_key();
	X509 *ca;
	unsigned char *ca_der;
	size_t ca_der_length = 0;
	unsigned char *leaf_spki;
	size_t leaf_spki_length = 0;
	cert_builder_t *builder;
	cert_blob_t tbs = { 0 };
	cert_blob_t certificate = { 0 };
	unsigned char *signature = NULL;
	size_t signature_length = 0;
	X509 *parsed;

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_key);
	ca = test_certificate(ca_key, NULL, NULL, 0x30, TEST_CERT_CA);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	ca_der = test_cert_der(ca, &ca_der_length);
	leaf_spki = test_spki_der(leaf_key, &leaf_spki_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_der);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_spki);

	builder = cert_builder_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
	CU_ASSERT_TRUE(cert_builder_set_subject(builder, "CN=Leaf"));
	CU_ASSERT_TRUE(cert_builder_set_issuer_certificate(
		builder, ca_der, ca_der_length));
	CU_ASSERT_TRUE(cert_builder_set_public_key_der(builder, leaf_spki,
						       leaf_spki_length));
	CU_ASSERT_TRUE(cert_builder_set_validity(builder, 0, 1));
	CU_ASSERT_TRUE(cert_builder_add_key_usage(
		builder, CERT_KU_DIGITAL_SIGNATURE));
	CU_ASSERT_TRUE(cert_builder_add_authority_key_identifier(builder));

	CU_ASSERT_TRUE(cert_builder_tbs(builder, CERT_SIGNATURE_RSA,
					CERT_DIGEST_SHA256, &tbs));
	CU_ASSERT_TRUE(test_sign(ca_key, tbs.data, tbs.length, &signature,
				 &signature_length));
	CU_ASSERT_TRUE(cert_builder_assemble(
		builder, CERT_SIGNATURE_RSA, CERT_DIGEST_SHA256, tbs.data,
		tbs.length, signature, signature_length, &certificate));

	parsed = ossl_x509_load_der(certificate.data, certificate.length);
	CU_ASSERT_PTR_NOT_NULL(parsed);
	if (parsed != NULL) {
		check_subject_cn(parsed, "Leaf");
		CU_ASSERT_TRUE(ossl_x509_issued_by(parsed, ca));
		X509_free(parsed);
	}

	cert_blob_free(&certificate);
	cert_blob_free(&tbs);
	OPENSSL_free(signature);
	OPENSSL_free(leaf_spki);
	OPENSSL_free(ca_der);
	cert_builder_free(builder);
	X509_free(ca);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(ca_key);
}

static void test_request(void)
{
	EVP_PKEY *key = test_rsa_key();
	X509_REQ *request;
	X509_NAME *name;
	cert_request_t *loaded;
	cert_builder_t *builder;
	char *directory;
	char path[PATH_MAX];
	FILE *file;
	bool present = true;
	bool is_ca = true;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	request = X509_REQ_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(request);
	CU_ASSERT_EQUAL(X509_REQ_set_version(request, 0), 1);
	name = X509_REQ_get_subject_name(request);
	CU_ASSERT_PTR_NOT_NULL_FATAL(name);
	CU_ASSERT_EQUAL(
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					   (const unsigned char *) "CSR Test",
					   -1, -1, 0),
		1);
	CU_ASSERT_EQUAL(X509_REQ_set_pubkey(request, key), 1);
	CU_ASSERT_TRUE(X509_REQ_sign(request, key, EVP_sha256()) > 0);

	directory = test_temp_dir();
	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(path, sizeof path, "%s/request.pem", directory);
	file = fopen(path, "wb");
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);
	CU_ASSERT_TRUE(PEM_write_X509_REQ(file, request));
	CU_ASSERT_EQUAL(fclose(file), 0);

	loaded = cert_request_load_file(path);
	CU_ASSERT_PTR_NOT_NULL(loaded);
	if (loaded != NULL) {
		CU_ASSERT_EQUAL(cert_request_extension_count(loaded), 0);
		CU_ASSERT_TRUE(cert_request_is_ca(loaded, &present, &is_ca));
		CU_ASSERT_FALSE(present);
		CU_ASSERT_FALSE(is_ca);

		{
			const char *oid = NULL;
			bool critical = false;
			const unsigned char *value = NULL;
			size_t value_length = 0;

			CU_ASSERT_FALSE(cert_request_extension(
				loaded, 0, &oid, &critical, &value,
				&value_length));
		}

		builder = cert_builder_new();
		CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
		CU_ASSERT_TRUE(cert_request_set_subject(loaded, builder));
		CU_ASSERT_TRUE(cert_request_set_public_key(loaded, builder));
		cert_builder_free(builder);
		cert_request_free(loaded);
	}

	CU_ASSERT_PTR_NULL(cert_request_load_file(NULL));
	CU_ASSERT_PTR_NULL(
		cert_request_load_file("/nonexistent/anyca-request.pem"));
	cert_request_free(NULL);

	test_remove_tree(directory);
	free(directory);
	X509_REQ_free(request);
	EVP_PKEY_free(key);
}

void test_cert_register(void)
{
	CU_pSuite suite = CU_add_suite("cert", NULL, NULL);

	CU_add_test(suite, "setters", test_setters);
	CU_add_test(suite, "build_self_signed", test_build_self_signed);
	CU_add_test(suite, "build_issued", test_build_issued);
	CU_add_test(suite, "request", test_request);
}
