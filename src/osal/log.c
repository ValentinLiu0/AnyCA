/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include <anyca/osal/log.h>

static _Atomic osal_log_level_t g_log_level = OSAL_LOG_VERBOSE;

void osal_log_set_level(osal_log_level_t level)
{
	atomic_store(&g_log_level, level);
}

osal_log_level_t osal_log_get_level(void)
{
	return atomic_load(&g_log_level);
}

/* Basename of a file path, for log locations. */
static const char *_log_basename(const char *path)
{
	const char *name = path;

	if (path == nullptr)
		return "?";

	for (const char *cursor = path; *cursor != '\0'; cursor++) {
		if (*cursor == '/' || *cursor == '\\')
			name = cursor + 1;
	}
	return name;
}

void _log_write(osal_log_level_t level, const char *tag, const char *file,
		int line, const char *function, const char *format, ...)
{
	char stack_buffer[512];
	char *message = stack_buffer;
	va_list arguments;
	int needed;

	if (level < atomic_load(&g_log_level))
		return;
	if (format == nullptr)
		format = "(null)";

	va_start(arguments, format);
	needed = vsnprintf(stack_buffer, sizeof stack_buffer, format,
			   arguments);
	va_end(arguments);

	if (needed < 0) {
		message = nullptr;
	} else if ((size_t) needed >= sizeof stack_buffer) {
		char *heap = malloc((size_t) needed + 1);

		if (heap != nullptr) {
			va_start(arguments, format);
			(void) vsnprintf(heap, (size_t) needed + 1, format,
					 arguments);
			va_end(arguments);
			message = heap;
		}
	}

	if (message == nullptr) {
		fprintf(stderr, "%s%s:%d | %s: <message unavailable>\n", tag,
			_log_basename(file), line, function);
	} else {
		fprintf(stderr, "%s%s:%d | %s: %s\n", tag, _log_basename(file),
			line, function, message);
	}

	if (message != nullptr && message != stack_buffer)
		free(message);
}
