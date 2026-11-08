/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_DYNLIB_H
#define ANYCA_OSAL_DYNLIB_H

/**
 * @file dynlib.h
 * @brief Portable dynamic library loading.
 *
 * Wraps dlopen()/dlsym()/dlclose() on POSIX and the LoadLibraryA() family on
 * Windows.  Paths use the native convention.  Error text is thread-local.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque dynamic library handle. */
typedef struct osal_dynlib osal_dynlib_t;

/**
 * Open a shared library (.so, .dylib, .dll, ...); osal_dynlib_error()
 * describes a failure.
 */
osal_dynlib_t *osal_dynlib_open(const char *path);

/**
 * Resolve a symbol in an opened library.
 *
 * On Windows only exported functions resolve, because GetProcAddress() has no
 * data-symbol support.
 */
void *osal_dynlib_symbol(osal_dynlib_t *library,
					const char *name);

/**
 * Text for the last failed open or symbol lookup in the calling thread;
 * "no error" when none was recorded.
 */
const char *osal_dynlib_error(void);

/** Close a library.  Passing NULL is a no-op. */
void osal_dynlib_close(osal_dynlib_t *library);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_DYNLIB_H
