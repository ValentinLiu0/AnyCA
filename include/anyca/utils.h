/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_UTILS_H
#define ANYCA_UTILS_H

/**
 * @file utils.h
 * @brief Small shared utilities.
 */

#include <stdbool.h>
#include <stddef.h>

/**
 * Encode binary data as standard Base64 (RFC 4648).
 *
 * output is an osal_malloc()ed NUL-terminated string; release with
 * osal_free().  *output_length excludes the terminating NUL.
 */
bool utils_base64_encode(const unsigned char *input,
				 size_t input_length, char **output,
				 size_t *output_length);

/**
 * Decode standard Base64 (RFC 4648).
 *
 * input_length must be a multiple of four with correct padding; whitespace and
 * URL-safe input are rejected.  output is osal_malloc()ed; release with
 * osal_free().  Zero-length input yields an empty allocation.
 */
bool utils_base64_decode(const char *input, size_t input_length,
				 unsigned char **output,
				 size_t *output_length);

#endif // ANYCA_UTILS_H
