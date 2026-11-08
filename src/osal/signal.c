/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <anyca/osal/signal.h>
#include <anyca/osal/thread.h>

#define OSAL_SIGNAL_ERROR_MAX 256

static OSAL_THREAD_LOCAL char g_error[OSAL_SIGNAL_ERROR_MAX];

static void _clear_error(void)
{
	g_error[0] = '\0';
}

static void _set_error(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	vsnprintf(g_error, sizeof g_error, format, arguments);
	va_end(arguments);
}

const char *osal_signal_error(void)
{
	return g_error[0] != '\0' ? g_error : "no error";
}

bool osal_signal_install(int signal_number, osal_signal_handler_t handler)
{
	_clear_error();
	if (handler == nullptr) {
		_set_error("signal handler must not be NULL");
		return false;
	}

#if defined(_WIN32)
	if (signal(signal_number, handler) == SIG_ERR) {
		_set_error("cannot install handler for signal %d: %s",
			   signal_number, strerror(errno));
		return false;
	}
#else
	struct sigaction action = { 0 };

	action.sa_handler = handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(signal_number, &action, nullptr) != 0) {
		_set_error("cannot install handler for signal %d: %s",
			   signal_number, strerror(errno));
		return false;
	}
#endif

	return true;
}
