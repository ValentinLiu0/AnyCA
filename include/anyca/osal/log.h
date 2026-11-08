/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_LOG_H
#define ANYCA_OSAL_LOG_H

/**
 * @file osal/log.h
 * @brief printf-style logging macros.
 *
 * Each macro writes one newline-terminated line to stderr:
 *
 *     [LEVEL] file.c:42 | function: message
 *
 * The message uses printf syntax and must not end with a newline.  Levels:
 * LOGV, LOGD, LOGI, LOGW, LOGE, LOGF.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Log severity, from most to least verbose. */
typedef enum osal_log_level {
	OSAL_LOG_VERBOSE = 0,
	OSAL_LOG_DEBUG,
	OSAL_LOG_INFO,
	OSAL_LOG_WARN,
	OSAL_LOG_ERROR,
	OSAL_LOG_FATAL,
} osal_log_level_t;

/** Set the minimum level written to stderr. */
void osal_log_set_level(osal_log_level_t level);

/** Current minimum level. */
osal_log_level_t osal_log_get_level(void);

/**
 * Write one log line to stderr.  The line is emitted with a single
 * fprintf(), so concurrent writes do not interleave.  Use the macros.
 */
void _log_write(osal_log_level_t level, const char *tag, const char *file,
		int line, const char *function, const char *format, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 6, 7)))
#endif
	;

#define LOG_WRITE(level, tag, ...)                                    \
	_log_write(level, tag, __FILE__, __LINE__, __func__, __VA_ARGS__)

/* Level tags are padded to 10 columns so that file names line up. */
#define LOGV(...) LOG_WRITE(OSAL_LOG_VERBOSE, "[VERBOSE] ", __VA_ARGS__)
#define LOGD(...) LOG_WRITE(OSAL_LOG_DEBUG, "[DEBUG]   ", __VA_ARGS__)
#define LOGI(...) LOG_WRITE(OSAL_LOG_INFO, "[INFO]    ", __VA_ARGS__)
#define LOGW(...) LOG_WRITE(OSAL_LOG_WARN, "[WARN]    ", __VA_ARGS__)
#define LOGE(...) LOG_WRITE(OSAL_LOG_ERROR, "[ERROR]   ", __VA_ARGS__)
#define LOGF(...) LOG_WRITE(OSAL_LOG_FATAL, "[FATAL]   ", __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_LOG_H
