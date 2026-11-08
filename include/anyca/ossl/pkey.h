/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSSL_PKEY_H
#define ANYCA_OSSL_PKEY_H

/**
 * @file pkey.h
 * @brief OpenSSL public-key construction and comparison helpers.
 */

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build an RSA public key from a big-endian modulus and exponent; release
 * with EVP_PKEY_free().
 */
EVP_PKEY *ossl_pkey_from_rsa_public(
	const unsigned char *modulus, size_t modulus_length,
	const unsigned char *exponent, size_t exponent_length);

/**
 * Build an EC public key from an OpenSSL group name (e.g. "prime256v1") and an
 * encoded point, normally uncompressed.  Release with EVP_PKEY_free().
 */
EVP_PKEY *ossl_pkey_from_ec_public(const char *group,
						 const unsigned char *point,
						 size_t point_length);

/**
 * Build an ML-DSA public key from the raw public key bytes exported by a
 * token.  The algorithm is "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".  Release
 * with EVP_PKEY_free().
 */
EVP_PKEY *ossl_pkey_from_ml_dsa_public(
	const char *algorithm, const unsigned char *key_data,
	size_t key_length);

/** Compare the public parts of two keys; false when either is NULL. */
bool ossl_pkey_equal(const EVP_PKEY *left,
				   const EVP_PKEY *right);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSSL_PKEY_H
