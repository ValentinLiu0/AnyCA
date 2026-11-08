/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <anyca/ossl/base64.h>

#include <anyca/utils.h>

bool utils_base64_encode(const unsigned char *input, size_t input_length,
			 char **output, size_t *output_length)
{
	return ossl_base64_encode(input, input_length, output,
				  output_length);
}

bool utils_base64_decode(const char *input, size_t input_length,
			 unsigned char **output, size_t *output_length)
{
	return ossl_base64_decode(input, input_length, output,
				  output_length);
}
