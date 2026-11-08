/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdint.h>

#include <openssl/evp.h>

#include <anyca/osal/memory.h>

#include <anyca/ossl/base64.h>

/*
 * Return the trailing '=' padding count, or SIZE_MAX when '=' appears
 * anywhere else.
 */
static size_t _ossl_base64_padding(const char *input, size_t length)
{
	size_t padding = 0;

	if (length >= 1 && input[length - 1] == '=')
		padding++;
	if (length >= 2 && input[length - 2] == '=')
		padding++;

	for (size_t i = 0; i + padding < length; i++) {
		if (input[i] == '=')
			return SIZE_MAX;
	}
	return padding;
}

/* Value of one standard Base64 character, or -1 when it is not one. */
static int _ossl_base64_value(char character)
{
	if (character >= 'A' && character <= 'Z')
		return character - 'A';
	if (character >= 'a' && character <= 'z')
		return character - 'a' + 26;
	if (character >= '0' && character <= '9')
		return character - '0' + 52;
	if (character == '+')
		return 62;
	if (character == '/')
		return 63;
	return -1;
}

/*
 * Reject input the header contract excludes: whitespace, URL-safe characters
 * and non-canonical trailing bits (RFC 4648 section 3.5).  EVP_DecodeBlock()
 * is lenient about all three.
 */
static bool _ossl_base64_characters_valid(const char *input, size_t length,
					  size_t padding)
{
	if (length == 0)
		return true;

	for (size_t i = 0; i + padding < length; i++) {
		if (_ossl_base64_value(input[i]) < 0)
			return false;
	}

	if (padding == 2) {
		int last = _ossl_base64_value(input[length - 3]);

		return last >= 0 && (last & 0x0f) == 0;
	}
	if (padding == 1) {
		int last = _ossl_base64_value(input[length - 2]);

		return last >= 0 && (last & 0x03) == 0;
	}
	return true;
}

bool ossl_base64_encode(const unsigned char *input, size_t input_length,
			char **output, size_t *output_length)
{
	unsigned char *encoded;
	size_t encoded_length;
	int written;

	if (output == nullptr || output_length == nullptr)
		return false;
	*output = nullptr;
	*output_length = 0;

	if (input == nullptr && input_length != 0)
		return false;
	if (input_length > INT_MAX)
		return false;

	encoded_length = 4 * ((input_length + 2) / 3);
	encoded = osal_malloc(encoded_length + 1);
	if (encoded == nullptr)
		return false;

	written = EVP_EncodeBlock(
		encoded,
		input != nullptr ? input : (const unsigned char *)"",
		(int) input_length);
	if (written < 0 || (size_t) written != encoded_length) {
		osal_free(encoded);
		return false;
	}

	/* EVP_EncodeBlock() NUL-terminates the output. */
	*output = (char *) encoded;
	*output_length = encoded_length;
	return true;
}

bool ossl_base64_decode(const char *input, size_t input_length,
			unsigned char **output, size_t *output_length)
{
	unsigned char *decoded;
	size_t capacity;
	size_t padding;
	int written;

	if (output == nullptr || output_length == nullptr)
		return false;
	*output = nullptr;
	*output_length = 0;

	if (input == nullptr && input_length != 0)
		return false;
	if (input_length % 4 != 0 || input_length > INT_MAX)
		return false;
	if (input == nullptr)
		input = "";

	padding = _ossl_base64_padding(input, input_length);
	if (padding == SIZE_MAX
	    || !_ossl_base64_characters_valid(input, input_length, padding))
		return false;

	capacity = input_length / 4 * 3;
	decoded = osal_malloc(capacity != 0 ? capacity : 1);
	if (decoded == nullptr)
		return false;

	written = EVP_DecodeBlock(decoded, (const unsigned char *) input,
				  (int) input_length);
	if (written < 0 || (size_t) written < padding) {
		osal_free(decoded);
		return false;
	}

	/*
	 * EVP_DecodeBlock() counts bytes covered by '=' padding; subtract
	 * them from the reported length.
	 */
	*output = decoded;
	*output_length = (size_t) written - padding;
	return true;
}
