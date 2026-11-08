/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_MEMORY_H
#define ANYCA_OSAL_MEMORY_H

/**
 * @file memory.h
 * @brief Heap allocation and secure memory.
 *
 * The osal_* wrappers mirror malloc()/calloc()/realloc()/free().  Secure
 * allocations are zero-initialized, page-aligned, locked in RAM, excluded
 * from core dumps where supported and wiped before release; allocation fails
 * when the pages cannot be locked.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Allocate size bytes; equivalent to malloc(). */
void *osal_malloc(size_t size);

/** Allocate count * size zeroed bytes; equivalent to calloc(). */
void *osal_calloc(size_t count, size_t size);

/** Resize an allocation; equivalent to realloc(). */
void *osal_realloc(void *pointer, size_t size);

/** Release memory obtained from osal_malloc(), osal_calloc() or
 *  osal_realloc().  Passing NULL is a no-op. */
void osal_free(void *pointer);

/**
 * Allocate zero-initialized, page-aligned secure memory, locked in RAM.  The
 * size is remembered internally; size must be nonzero.
 */
void *osal_secure_malloc(size_t size);

/**
 * Wipe and release memory obtained from osal_secure_malloc().  The pointer
 * must be the value returned by that function.  NULL is a no-op.
 */
void osal_secure_free(void *pointer);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_MEMORY_H
