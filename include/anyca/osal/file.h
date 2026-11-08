/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_FILE_H
#define ANYCA_OSAL_FILE_H

/**
 * @file file.h
 * @brief Cross-platform file and directory helpers.
 */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a directory and every missing parent.
 *
 * Existing directories are accepted.  Both '/' and, on Windows, '\' are
 * separators.  osal_file_error() describes a failure.
 */
bool osal_file_make_dirs(const char *path);

/**
 * Create an empty file with owner-only permissions unless it exists.
 *
 * An existing file is left untouched and counts as success, so the call
 * ensures that path exists without truncating it.  A new file is created with
 * mode 0600 on POSIX.  On Windows access is inherited from the parent
 * directory's ACL.
 *
 * osal_file_error() describes a failure.
 */
bool osal_file_create_private(const char *path);

/**
 * Write data to path atomically, creating missing parent directories.
 *
 * The data goes to a temporary file in the same directory, is flushed to
 * stable storage and renamed over path, so readers see either the old or the
 * new contents.  On POSIX the containing directory is synchronized too.
 * mode applies to a newly created file; 0 selects 0644.  Windows ignores
 * mode and inherits access from the parent directory's ACL.
 */
bool osal_file_write_atomic(const char *path, const void *data,
					  size_t length, unsigned int mode);

/** Opaque advisory file lock held by one process. */
typedef struct osal_file_lock osal_file_lock_t;

/**
 * Acquire an exclusive advisory lock on path, creating the file when needed.
 *
 * Blocks until another process releases the lock.  The lock is advisory:
 * every process that needs mutual exclusion must use this API.  Release with
 * osal_file_lock_release().
 *
 * @return the lock, or NULL on failure (osal_file_error() describes it).
 */
osal_file_lock_t *osal_file_lock_acquire(const char *path);

/** Release a lock returned by osal_file_lock_acquire().  NULL is a no-op. */
void osal_file_lock_release(osal_file_lock_t *lock);

/**
 * Description of the last file operation failure in the calling thread.
 *
 * The pointer is valid until the next file operation in that thread.
 */
const char *osal_file_error(void);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_FILE_H
