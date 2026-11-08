/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif

#include <time.h>

#include <anyca/osal/time.h>

time_t osal_timegm(struct tm *broken_down)
{
	if (broken_down == nullptr)
		return (time_t) -1;

#if defined(_WIN32)
	return _mkgmtime(broken_down);
#else
	return timegm(broken_down);
#endif
}
