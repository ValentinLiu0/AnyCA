/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_TEST_SUPPORT_H
#define ANYCA_TEST_SUPPORT_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#define TEST_CERT_CA 0x1u
#define TEST_CERT_OCSP_SIGNER 0x2u

EVP_PKEY *test_rsa_key(void);
EVP_PKEY *test_ec_key(void);

/* issuer NULL makes a self-signed certificate. */
X509 *test_certificate(EVP_PKEY *subject_key, X509 *issuer,
		       EVP_PKEY *issuer_key, long serial, unsigned flags);

unsigned char *test_cert_der(X509 *certificate, size_t *length);
unsigned char *test_spki_der(EVP_PKEY *key, size_t *length);

bool test_sign(EVP_PKEY *key, const unsigned char *data, size_t length,
	       unsigned char **signature, size_t *signature_length);

char *test_temp_dir(void);
void test_remove_tree(const char *path);
bool test_write_file(const char *path, const void *data, size_t length);

/* SoftHSM integration helpers; the tests skip when it is unavailable. */
#define TEST_SOFTHSM_MODULE "/usr/lib/softhsm/libsofthsm2.so"
#define TEST_SOFTHSM_TOKEN_LABEL "anyca-test"
#define TEST_SOFTHSM_PIN "1234"

bool test_softhsm_available(void);

/*
 * Create an isolated token directory and SOFTHSM2_CONF for this process.
 * directory and conf_path receive NUL-terminated paths.
 */
bool test_softhsm_init_token(char *directory, size_t directory_size,
			     char *conf_path, size_t conf_path_size);

/* Import a PEM private key into the test token under label and id. */
bool test_softhsm_import_key(const char *pem_path, const char *label,
			     const char *id);

#endif // ANYCA_TEST_SUPPORT_H
