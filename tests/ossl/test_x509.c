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

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>
#include <anyca/ossl/x509.h>

#include "../test_support.h"
#include "test_suites.h"

static void test_load_and_properties(void)
{
	EVP_PKEY *key = test_rsa_key();
	X509 *certificate;
	X509 *loaded;
	unsigned char *der;
	size_t der_length = 0;
	unsigned char *serial = NULL;
	size_t serial_length = 0;
	int64_t not_after = 0;
	char *directory;
	char path[PATH_MAX];

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	certificate = test_certificate(key, NULL, NULL, 0x10, TEST_CERT_CA);
	CU_ASSERT_PTR_NOT_NULL_FATAL(certificate);
	der = test_cert_der(certificate, &der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(der);

	loaded = ossl_x509_load_der(der, der_length);
	CU_ASSERT_PTR_NOT_NULL(loaded);
	CU_ASSERT_EQUAL(X509_cmp(loaded, certificate), 0);
	X509_free(loaded);

	CU_ASSERT_PTR_NULL(ossl_x509_load_der(der, der_length - 1));
	CU_ASSERT_PTR_NULL(ossl_x509_load_der(NULL, 0));

	CU_ASSERT_TRUE(ossl_x509_serial(certificate, &serial,
					&serial_length));
	CU_ASSERT_EQUAL(serial_length, 1);
	CU_ASSERT_EQUAL(serial[0], 0x10);
	osal_free(serial);

	CU_ASSERT_TRUE(ossl_x509_not_after(certificate, &not_after));
	CU_ASSERT_TRUE(not_after > (int64_t) time(NULL));
	CU_ASSERT_TRUE(ossl_x509_valid_now(certificate));

	directory = test_temp_dir();
	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(path, sizeof path, "%s/certificate.der", directory);
	CU_ASSERT_TRUE(test_write_file(path, der, der_length));
	loaded = ossl_x509_load_der_file(path);
	CU_ASSERT_PTR_NOT_NULL(loaded);
	CU_ASSERT_EQUAL(X509_cmp(loaded, certificate), 0);
	X509_free(loaded);
	CU_ASSERT_PTR_NULL(ossl_x509_load_der_file(NULL));

	test_remove_tree(directory);
	free(directory);
	OPENSSL_free(der);
	X509_free(certificate);
	EVP_PKEY_free(key);
}

static void test_name(void)
{
	EVP_PKEY *key = test_rsa_key();
	X509 *certificate;
	X509_NAME *name;
	X509_NAME *decoded = NULL;
	ossl_der_t der = { 0 };
	unsigned char *trailing;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	certificate = test_certificate(key, NULL, NULL, 1, TEST_CERT_CA);
	CU_ASSERT_PTR_NOT_NULL_FATAL(certificate);
	name = X509_get_subject_name(certificate);

	CU_ASSERT_TRUE(ossl_x509_name_encode(name, &der));
	CU_ASSERT_TRUE(ossl_x509_name_decode(der.data, der.length, &decoded));
	CU_ASSERT_PTR_NOT_NULL(decoded);
	CU_ASSERT_EQUAL(X509_NAME_cmp(name, decoded), 0);
	X509_NAME_free(decoded);

	trailing = malloc(der.length + 1);
	CU_ASSERT_PTR_NOT_NULL_FATAL(trailing);
	memcpy(trailing, der.data, der.length);
	trailing[der.length] = 0;
	CU_ASSERT_FALSE(ossl_x509_name_decode(trailing, der.length + 1,
					     &decoded));
	free(trailing);

	CU_ASSERT_FALSE(ossl_x509_name_decode(NULL, 0, &decoded));
	CU_ASSERT_FALSE(ossl_x509_name_decode(der.data, der.length, NULL));

	ossl_der_release(&der);
	X509_free(certificate);
	EVP_PKEY_free(key);
}

static void test_public_key(void)
{
	EVP_PKEY *key = test_rsa_key();
	X509 *certificate;
	X509_PUBKEY *pubkey;
	X509_PUBKEY *decoded_pubkey = NULL;
	EVP_PKEY *public_key;
	EVP_PKEY *from_der;
	const unsigned char *bits;
	size_t bits_length = 0;
	unsigned char *cert_der;
	size_t cert_der_length = 0;
	ossl_der_t der = { 0 };
	ossl_der_t spki = { 0 };
	const unsigned char *cursor;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	certificate = test_certificate(key, NULL, NULL, 2, TEST_CERT_CA);
	CU_ASSERT_PTR_NOT_NULL_FATAL(certificate);
	pubkey = X509_get_X509_PUBKEY(certificate);
	public_key = X509_get_pubkey(certificate);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pubkey);
	CU_ASSERT_PTR_NOT_NULL_FATAL(public_key);

	CU_ASSERT_TRUE(ossl_x509_public_key_bits(certificate, &bits,
						 &bits_length));
	CU_ASSERT_TRUE(bits_length > 0);

	CU_ASSERT_TRUE(ossl_x509_pubkey_encode(pubkey, &der));
	CU_ASSERT_TRUE(ossl_x509_pubkey_decode(der.data, der.length,
					       &decoded_pubkey));
	CU_ASSERT_PTR_NOT_NULL(decoded_pubkey);
	CU_ASSERT_EQUAL(X509_PUBKEY_eq(pubkey, decoded_pubkey), 1);

	CU_ASSERT_TRUE(ossl_x509_spki_encode(public_key, &spki));
	cursor = spki.data;
	from_der = d2i_PUBKEY(NULL, &cursor, (long) spki.length);
	CU_ASSERT_PTR_NOT_NULL(from_der);
	CU_ASSERT_EQUAL(EVP_PKEY_eq(public_key, from_der), 1);

	cert_der = test_cert_der(certificate, &cert_der_length);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cert_der);
	EVP_PKEY_free(from_der);
	from_der = ossl_x509_load_public_key(cert_der, cert_der_length);
	CU_ASSERT_PTR_NOT_NULL(from_der);
	CU_ASSERT_EQUAL(EVP_PKEY_eq(public_key, from_der), 1);

	OPENSSL_free(cert_der);
	EVP_PKEY_free(from_der);
	X509_PUBKEY_free(decoded_pubkey);
	EVP_PKEY_free(public_key);
	ossl_der_release(&der);
	ossl_der_release(&spki);
	X509_free(certificate);
	EVP_PKEY_free(key);
}

static void test_extensions(void)
{
	EVP_PKEY *key = test_rsa_key();
	X509 *certificate;
	X509_EXTENSION *extension;
	X509_EXTENSION *copy;
	STACK_OF(X509_EXTENSION) *stack = NULL;
	STACK_OF(X509_EXTENSION) *duplicated = NULL;
	const unsigned char value[] = { 0x30, 0x00 };
	const unsigned char *data;
	size_t length = 0;
	bool critical = false;
	char *oid;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	certificate = test_certificate(key, NULL, NULL, 3, TEST_CERT_CA);
	CU_ASSERT_PTR_NOT_NULL_FATAL(certificate);

	extension = ossl_x509_subject_key_identifier(
		X509_get_X509_PUBKEY(certificate));
	CU_ASSERT_PTR_NOT_NULL(extension);
	CU_ASSERT_EQUAL(OBJ_obj2nid(X509_EXTENSION_get_object(extension)),
			NID_subject_key_identifier);
	X509_EXTENSION_free(extension);

	extension = ossl_x509_authority_key_identifier(certificate);
	CU_ASSERT_PTR_NOT_NULL(extension);
	CU_ASSERT_EQUAL(OBJ_obj2nid(X509_EXTENSION_get_object(extension)),
			NID_authority_key_identifier);
	X509_EXTENSION_free(extension);

	extension = ossl_x509_extension_new_der("2.5.29.19", true, value,
						sizeof value);
	CU_ASSERT_PTR_NOT_NULL_FATAL(extension);
	oid = ossl_x509_extension_oid(extension);
	CU_ASSERT_PTR_NOT_NULL(oid);
	CU_ASSERT_STRING_EQUAL(oid, "2.5.29.19");
	osal_free(oid);
	CU_ASSERT_TRUE(ossl_x509_extension_data(extension, &critical,
						&data, &length));
	CU_ASSERT_TRUE(critical);
	CU_ASSERT_EQUAL(length, sizeof value);
	CU_ASSERT_EQUAL(memcmp(data, value, sizeof value), 0);

	CU_ASSERT_TRUE(ossl_x509_extension_push(&stack, extension));
	CU_ASSERT_EQUAL(sk_X509_EXTENSION_num(stack), 1);
	duplicated = ossl_x509_extension_copy_stack(stack);
	CU_ASSERT_PTR_NOT_NULL(duplicated);
	CU_ASSERT_EQUAL(sk_X509_EXTENSION_num(duplicated), 1);
	copy = sk_X509_EXTENSION_value(duplicated, 0);
	CU_ASSERT_PTR_NOT_NULL(copy);

	sk_X509_EXTENSION_pop_free(duplicated, X509_EXTENSION_free);
	sk_X509_EXTENSION_pop_free(stack, X509_EXTENSION_free);
	X509_free(certificate);
	EVP_PKEY_free(key);
}

static void test_signatures(void)
{
	EVP_PKEY *ca_key = test_rsa_key();
	EVP_PKEY *leaf_key = test_rsa_key();
	X509 *ca;
	X509 *leaf;
	X509 *signer;
	X509_ALGOR *algorithm;
	const ASN1_OBJECT *object;
	const void *parameters;
	int parameter_type;
	const unsigned char data[] = "signed data";
	unsigned char *signature = NULL;
	size_t signature_length = 0;

	CU_ASSERT_PTR_NOT_NULL_FATAL(ca_key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf_key);
	ca = test_certificate(ca_key, NULL, NULL, 4, TEST_CERT_CA);
	leaf = test_certificate(leaf_key, ca, ca_key, 5, 0);
	signer = test_certificate(leaf_key, ca, ca_key, 6,
				  TEST_CERT_OCSP_SIGNER);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ca);
	CU_ASSERT_PTR_NOT_NULL_FATAL(leaf);
	CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

	CU_ASSERT_TRUE(ossl_x509_issued_by(leaf, ca));
	CU_ASSERT_FALSE(ossl_x509_issued_by(ca, leaf));
	CU_ASSERT_TRUE(ossl_x509_verify_self_signature(ca));
	CU_ASSERT_FALSE(ossl_x509_verify_self_signature(leaf));

	CU_ASSERT_TRUE(ossl_x509_has_eku(signer, NID_OCSP_sign));
	CU_ASSERT_FALSE(ossl_x509_has_eku(ca, NID_OCSP_sign));

	CU_ASSERT_TRUE(test_sign(ca_key, data, sizeof data - 1, &signature,
				 &signature_length));
	CU_ASSERT_TRUE(ossl_x509_verify_data(ca, data, sizeof data - 1,
					     signature, signature_length));
	CU_ASSERT_FALSE(ossl_x509_verify_data(ca, "other", 5, signature,
					      signature_length));
	CU_ASSERT_FALSE(ossl_x509_verify_data(ca, data, sizeof data - 1,
					      signature,
					      signature_length - 1));

	algorithm = ossl_x509_signature_algorithm_new(
		NID_sha256WithRSAEncryption);
	CU_ASSERT_PTR_NOT_NULL(algorithm);
	X509_ALGOR_get0(&object, &parameter_type, &parameters, algorithm);
	CU_ASSERT_EQUAL(OBJ_obj2nid(object),
			NID_sha256WithRSAEncryption);
	CU_ASSERT_EQUAL(parameter_type, V_ASN1_NULL);
	X509_ALGOR_free(algorithm);

	OPENSSL_free(signature);
	X509_free(signer);
	X509_free(leaf);
	X509_free(ca);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(ca_key);
}

static void test_request(void)
{
	EVP_PKEY *key = test_rsa_key();
	X509 *issuer = test_certificate(key, NULL, NULL, 7, TEST_CERT_CA);
	X509_REQ *request;
	X509_REQ *loaded;
	char *directory;
	char path[PATH_MAX];
	FILE *file;

	CU_ASSERT_PTR_NOT_NULL_FATAL(key);
	CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);
	request = X509_REQ_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(request);
	CU_ASSERT_EQUAL(X509_REQ_set_version(request, 0), 1);
	CU_ASSERT_EQUAL(X509_REQ_set_subject_name(
				request, X509_get_subject_name(issuer)),
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

	loaded = ossl_x509_req_load_file(path);
	CU_ASSERT_PTR_NOT_NULL(loaded);
	CU_ASSERT_TRUE(ossl_x509_req_verify_self(loaded));
	CU_ASSERT_PTR_NULL(ossl_x509_req_load_file("/nonexistent/req.pem"));

	X509_REQ_free(loaded);
	test_remove_tree(directory);
	free(directory);
	X509_REQ_free(request);
	X509_free(issuer);
	EVP_PKEY_free(key);
}

void test_x509_register(void)
{
	CU_pSuite suite = CU_add_suite("x509", NULL, NULL);

	CU_add_test(suite, "load_and_properties", test_load_and_properties);
	CU_add_test(suite, "name", test_name);
	CU_add_test(suite, "public_key", test_public_key);
	CU_add_test(suite, "extensions", test_extensions);
	CU_add_test(suite, "signatures", test_signatures);
	CU_add_test(suite, "request", test_request);
}
