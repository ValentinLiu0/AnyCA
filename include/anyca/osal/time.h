/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_TIME_H
#define ANYCA_OSAL_TIME_H

/**
 * @file time.h
 * @brief Cross-platform calendar time conversions.
 */

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Convert a broken-down UTC time to Unix time, like POSIX timegm().
 *
 * The fields in @p broken_down are interpreted as UTC, so the result does not
 * depend on the local time zone.
 *
 * @return seconds since the Unix epoch, or (time_t)-1 when the value cannot
 *         be represented.
 */
time_t osal_timegm(struct tm *broken_down);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_TIME_H
