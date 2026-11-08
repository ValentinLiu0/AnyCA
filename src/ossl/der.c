/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include <anyca/osal/memory.h>

#include <anyca/ossl/der.h>

static bool _ossl_der_buf_reserve(ossl_der_buf_t *buf, size_t additional)
{
	size_t required;
	size_t capacity;
	unsigned char *grown;

	if (additional > SIZE_MAX - buf->length)
		return false;
	required = buf->length + additional;
	if (required <= buf->capacity)
		return true;

	capacity = buf->capacity != 0 ? buf->capacity : 256;
	while (capacity < required) {
		if (capacity > SIZE_MAX / 2) {
			capacity = required;
			break;
		}
		capacity *= 2;
	}

	grown = osal_realloc(buf->data, capacity);
	if (grown == nullptr)
		return false;
	buf->data = grown;
	buf->capacity = capacity;
	return true;
}

bool ossl_der_buf_append(ossl_der_buf_t *buf, const void *data, size_t length)
{
	if (buf == nullptr)
		return false;
	if (length == 0)
		return true;
	if (data == nullptr || !_ossl_der_buf_reserve(buf, length))
		return false;

	memcpy(buf->data + buf->length, data, length);
	buf->length += length;
	return true;
}

/* Encode a definite length.  Returns the number of bytes written. */
static size_t _ossl_der_buf_length(size_t length, unsigned char *output)
{
	size_t bytes = 0;
	size_t value = length;

	if (length < 0x80) {
		output[0] = (unsigned char) length;
		return 1;
	}

	while (value != 0) {
		value >>= 8;
		bytes++;
	}
	output[0] = (unsigned char) (0x80 | bytes);
	for (size_t i = 0; i < bytes; i++)
		output[1 + i] =
			(unsigned char) (length >> (8 * (bytes - 1 - i)));
	return 1 + bytes;
}

bool ossl_der_buf_wrap(ossl_der_buf_t *out, unsigned char tag,
		       const ossl_der_buf_t *content)
{
	unsigned char length_bytes[sizeof(size_t) + 1];
	size_t length_length;
	size_t total;

	if (out == nullptr || content == nullptr || out == content
	    || (content->length != 0 && content->data == nullptr))
		return false;

	length_length = _ossl_der_buf_length(content->length, length_bytes);
	if (content->length > SIZE_MAX - length_length - 1)
		return false;
	total = 1 + length_length + content->length;
	if (!_ossl_der_buf_reserve(out, total))
		return false;

	out->data[out->length] = tag;
	memcpy(out->data + out->length + 1, length_bytes, length_length);
	if (content->length != 0)
		memcpy(out->data + out->length + 1 + length_length,
		       content->data, content->length);
	out->length += total;
	return true;
}

void ossl_der_buf_release(ossl_der_buf_t *buf)
{
	if (buf == nullptr)
		return;

	osal_free(buf->data);
	buf->data = nullptr;
	buf->length = 0;
	buf->capacity = 0;
}

bool ossl_der_encode_item(const ASN1_ITEM *item, const void *object,
			  ossl_der_t *der)
{
	unsigned char *encoded;
	unsigned char *cursor;
	int length;

	if (der == nullptr)
		return false;
	der->data = nullptr;
	der->length = 0;

	if (item == nullptr || object == nullptr)
		return false;

	length = ASN1_item_i2d((const ASN1_VALUE *) object, nullptr, item);
	if (length <= 0)
		return false;

	encoded = osal_malloc((size_t) length);
	if (encoded == nullptr)
		return false;

	cursor = encoded;
	if (ASN1_item_i2d((const ASN1_VALUE *) object, &cursor, item)
	    != length) {
		osal_free(encoded);
		return false;
	}

	der->data = encoded;
	der->length = (size_t) length;
	return true;
}

bool ossl_der_decode_item(const ASN1_ITEM *item, const unsigned char *der,
			  size_t length, void **object)
{
	const unsigned char *cursor;
	ASN1_VALUE *value;

	if (object == nullptr)
		return false;
	*object = nullptr;

	if (item == nullptr || der == nullptr || length == 0
	    || length > (size_t) LONG_MAX)
		return false;

	cursor = der;
	value = ASN1_item_d2i(nullptr, &cursor, (long) length, item);
	if (value == nullptr)
		return false;
	if (cursor != der + length) {
		ASN1_item_free(value, item);
		return false;
	}

	*object = value;
	return true;
}

bool ossl_der_encode_ecdsa_signature(const unsigned char *raw,
				     size_t raw_length, ossl_der_t *der)
{
	ECDSA_SIG *signature = nullptr;
	BIGNUM *r = nullptr;
	BIGNUM *s = nullptr;
	unsigned char *encoded;
	unsigned char *cursor;
	size_t half;
	int length;
	bool ok = false;

	if (der == nullptr)
		return false;
	der->data = nullptr;
	der->length = 0;

	if (raw == nullptr || raw_length == 0 || raw_length % 2 != 0
	    || raw_length / 2 > INT_MAX)
		return false;

	half = raw_length / 2;
	signature = ECDSA_SIG_new();
	r = BN_bin2bn(raw, (int) half, nullptr);
	s = BN_bin2bn(raw + half, (int) half, nullptr);
	if (signature == nullptr || r == nullptr || s == nullptr)
		goto done;
	if (ECDSA_SIG_set0(signature, r, s) != 1)
		goto done;
	r = nullptr;
	s = nullptr;

	length = i2d_ECDSA_SIG(signature, nullptr);
	if (length <= 0)
		goto done;

	encoded = osal_malloc((size_t) length);
	if (encoded == nullptr)
		goto done;

	cursor = encoded;
	if (i2d_ECDSA_SIG(signature, &cursor) != length) {
		osal_free(encoded);
		goto done;
	}

	der->data = encoded;
	der->length = (size_t) length;
	ok = true;

done:
	BN_free(r);
	BN_free(s);
	ECDSA_SIG_free(signature);
	return ok;
}

void ossl_der_release(ossl_der_t *der)
{
	if (der == nullptr)
		return;

	osal_free(der->data);
	der->data = nullptr;
	der->length = 0;
}
