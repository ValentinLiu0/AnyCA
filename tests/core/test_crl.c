/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdlib.h>
#include <time.h>

#include <openssl/x509.h>

#include <CUnit/Basic.h>

#include <anyca/crl.h>
#include <anyca/ossl/asn1.h>
#include <anyca/ossl/x509.h>

#include "../test_support.h"
#include "test_suites.h"

static void test_build(void)
{
	EVP_PKEY *ca_key = test_rsa_key();
	EVP_PKEY *leaf_key = test_rsa_key();
	X509 *ca;
	X509 *leaf;
	unsigned char *ca_der;
	unsigned char *leaf_der;
	size_t ca_der_length = 0;
	size_t leaf_der_length = 0;
	crl_builder_t *builder;
	crl_blob_t tbs = { 0 };
	crl_blob_t crl = { 0 };
	unsigned char serial[] = { 0x01, 0x02 };
	unsigned char *signature = NULL;
	size_t signature_length = 0;
	X509_CRL *parsed;
	int64_t now = (int64_t) time(NULL);
	int64_t this_update = 0;
	ASN1_INTEGER *number;
	ASN1_ENUMERATED *reason;
	const X509_REVOKED *revoked;
	const STACK_OF(X509_REVOKED) *revoked_list;

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_key);
	ca = test_certificate(ca_key, NULL, NULL, 0x40, TEST_CERT_CA);
	leaf = test_certificate(leaf_key, ca, ca_key, 0x41, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf);
	ca_der = test_cert_der(ca, &ca_der_length);
	leaf_der = test_cert_der(leaf, &leaf_der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_der);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_der);

	builder = crl_builder_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
	CU_ASSERT_TRUE(crl_builder_set_issuer_certificate(
		builder, ca_der, ca_der_length));
	CU_ASSERT_TRUE(
		crl_builder_set_update_times(builder, now - 60, now + 3600));
	CU_ASSERT_TRUE(crl_builder_add_revoked_certificate(
		builder, serial, sizeof serial, now - 10, 1));
	CU_ASSERT_TRUE(crl_builder_add_crl_number(builder, 5));
	CU_ASSERT_TRUE(crl_builder_add_authority_key_identifier(builder));

	CU_ASSERT_TRUE(crl_builder_tbs(builder, CRL_SIGNATURE_RSA,
				       CRL_DIGEST_SHA256, &tbs));
	CU_ASSERT_TRUE(test_sign(ca_key, tbs.data, tbs.length, &signature,
				 &signature_length));
	CU_ASSERT_TRUE(crl_builder_assemble(
		builder, CRL_SIGNATURE_RSA, CRL_DIGEST_SHA256, tbs.data,
		tbs.length, signature, signature_length, &crl));

	parsed = ossl_x509_crl_load_der(crl.data, crl.length);
	CU_ASSERT_PTR_NOT_NULL(parsed);
	if (parsed != NULL) {
		CU_ASSERT_TRUE(ossl_x509_crl_issued_by(parsed, ca));
		CU_ASSERT_TRUE(ossl_asn1_time_to_epoch(
			X509_CRL_get0_lastUpdate(parsed), &this_update));
		CU_ASSERT_TRUE(this_update >= now - 120);

		revoked_list = X509_CRL_get_REVOKED(parsed);
		CU_ASSERT_EQUAL(sk_X509_REVOKED_num(revoked_list), 1);
		revoked = sk_X509_REVOKED_value(revoked_list, 0);
		CU_ASSERT_PTR_NOT_NULL(revoked);
		if (revoked != NULL) {
			const ASN1_INTEGER *entry_serial =
				X509_REVOKED_get0_serialNumber(revoked);

			CU_ASSERT_EQUAL(ASN1_INTEGER_get(entry_serial), 0x0102);
			reason = X509_REVOKED_get_ext_d2i(
				revoked, NID_crl_reason, NULL, NULL);
			CU_ASSERT_PTR_NOT_NULL(reason);
			if (reason != NULL) {
				CU_ASSERT_EQUAL(ASN1_ENUMERATED_get(reason),
						1);
				ASN1_ENUMERATED_free(reason);
			}
		}

		number = X509_CRL_get_ext_d2i(parsed, NID_crl_number, NULL,
					      NULL);
		CU_ASSERT_PTR_NOT_NULL(number);
		if (number != NULL) {
			CU_ASSERT_EQUAL(ASN1_INTEGER_get(number), 5);
			ASN1_INTEGER_free(number);
		}
		X509_CRL_free(parsed);
	}

	CU_ASSERT_FALSE(crl_builder_set_issuer_certificate(
		builder, leaf_der, leaf_der_length));
	CU_ASSERT_FALSE(crl_builder_set_update_times(builder, now, now - 1));
	CU_ASSERT_FALSE(crl_builder_set_update_times(builder, now, now));
	CU_ASSERT_FALSE(crl_builder_set_update_times(builder, now, 0));
	CU_ASSERT_FALSE(crl_builder_set_update_times(builder, 0, now - 60));
	CU_ASSERT_FALSE(crl_builder_set_update_times(
		builder, now, (int64_t) 253402300800LL));
	CU_ASSERT_FALSE(crl_builder_add_revoked_certificate(
		builder, NULL, 1, now, 0));
	CU_ASSERT_FALSE(crl_builder_add_revoked_certificate(
		builder, serial, 0, now, 0));
	CU_ASSERT_FALSE(crl_builder_add_revoked_certificate(
		builder, serial, sizeof serial, now, 7));
	CU_ASSERT_FALSE(crl_builder_add_revoked_certificate(
		builder, serial, sizeof serial, now, 11));

	{
		crl_builder_t *empty = crl_builder_new();
		crl_blob_t output = { 0 };

		CU_ASSERT_FALSE(crl_builder_tbs(NULL, CRL_SIGNATURE_RSA,
						CRL_DIGEST_SHA256, &output));
		CU_ASSERT_FALSE(crl_builder_assemble(
			empty, CRL_SIGNATURE_RSA, CRL_DIGEST_SHA256, NULL, 0,
			NULL, 0, &output));
		crl_builder_free(empty);
	}

	crl_blob_free(&crl);
	crl_blob_free(&tbs);
	crl_blob_free(NULL);
	crl_builder_free(builder);
	crl_builder_free(NULL);
	OPENSSL_free(signature);
	OPENSSL_free(leaf_der);
	OPENSSL_free(ca_der);
	X509_free(leaf);
	X509_free(ca);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(ca_key);
}

void test_crl_register(void)
{
	CU_pSuite suite = CU_add_suite("crl", NULL, NULL);

	CU_add_test(suite, "build", test_build);
}
