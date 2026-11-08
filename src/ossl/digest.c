/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <openssl/evp.h>

#include <anyca/ossl/digest.h>

bool ossl_digest(const EVP_MD *md, const void *data, size_t length,
		 unsigned char *digest, size_t digest_capacity,
		 size_t *digest_length)
{
	unsigned int written = 0;
	int size;

	if (md == nullptr || digest == nullptr || digest_length == nullptr
	    || (data == nullptr && length != 0))
		return false;

	size = EVP_MD_get_size(md);
	if (size <= 0 || (size_t) size > digest_capacity)
		return false;

	if (EVP_Digest(data, length, digest, &written, md, nullptr) != 1
	    || (size_t) written > digest_capacity)
		return false;

	*digest_length = (size_t) written;
	return true;
}
