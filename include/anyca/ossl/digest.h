/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSSL_DIGEST_H
#define ANYCA_OSSL_DIGEST_H

/**
 * @file digest.h
 * @brief EVP digest helpers.
 */

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hash a buffer with an EVP digest.  digest_capacity must hold the full
 * digest; data may be NULL when length is zero.
 */
bool ossl_digest(const EVP_MD *md, const void *data,
			       size_t length, unsigned char *digest,
			       size_t digest_capacity, size_t *digest_length);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSSL_DIGEST_H
