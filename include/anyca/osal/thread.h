/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_THREAD_H
#define ANYCA_OSAL_THREAD_H

/**
 * @file thread.h
 * @brief Compiler-portable thread-local storage.
 *
 * GCC and Clang provide the C11 _Thread_local keyword; MSVC spells it
 * __declspec(thread).  Use OSAL_THREAD_LOCAL for file-scope state that must
 * have one instance per thread.
 */

#if defined(_MSC_VER)
#define OSAL_THREAD_LOCAL __declspec(thread)
#else
#define OSAL_THREAD_LOCAL _Thread_local
#endif

#endif // ANYCA_OSAL_THREAD_H
