/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_COMPAT_H
#define ANYCA_OSAL_COMPAT_H

/*
 * Compiler and C library compatibility definitions.
 *
 * The project is built as C23 with GCC and Clang.  MSVC has no /std:c23 and
 * implements C17, so it needs nullptr and static_assert as macros.  It also
 * spells the case-insensitive string comparisons differently.  For MSVC
 * frontends the build force-includes this header into every translation unit.
 */

#include <stdbool.h>
#include <stddef.h>

#if defined(_MSC_VER)
#include <string.h>

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#else
#include <strings.h>
#endif

#if defined(_MSC_VER) && !defined(__cplusplus) && \
	(!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
#ifndef nullptr
#define nullptr NULL
#endif
#ifndef static_assert
#define static_assert _Static_assert
#endif
#endif

#endif /* ANYCA_OSAL_COMPAT_H */
