/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_SIGNAL_H
#define ANYCA_OSAL_SIGNAL_H

/**
 * @file signal.h
 * @brief Cross-platform process signal handling.
 *
 * Installs handlers with sigaction() on POSIX and signal() on Windows.  The
 * handler runs asynchronously, so it may only perform async-signal-safe work
 * such as setting a volatile sig_atomic_t flag.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Handler invoked when a signal is delivered. */
typedef void (*osal_signal_handler_t)(int signal_number);

/**
 * Install @p handler for @p signal_number.
 *
 * Replaces any handler installed earlier.  osal_signal_error() describes a
 * failure.
 *
 * @return false when the handler cannot be installed.
 */
bool osal_signal_install(int signal_number, osal_signal_handler_t handler);

/**
 * Text for the last signal operation failure in the calling thread; "no
 * error" when none was recorded.
 */
const char *osal_signal_error(void);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_SIGNAL_H
