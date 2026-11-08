/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <signal.h>

#include <CUnit/Basic.h>

#include <anyca/osal/signal.h>

#include "test_suites.h"

static volatile sig_atomic_t g_received;

static void handler(int signal_number)
{
	(void) signal_number;
	g_received = 1;
}

static void test_install(void)
{
	g_received = 0;

	CU_ASSERT_TRUE(osal_signal_install(SIGUSR1, handler));
	CU_ASSERT_STRING_EQUAL(osal_signal_error(), "no error");
	CU_ASSERT_EQUAL(raise(SIGUSR1), 0);
	CU_ASSERT_EQUAL(g_received, 1);
	CU_ASSERT_TRUE(signal(SIGUSR1, SIG_DFL) != SIG_ERR);
}

static void test_errors(void)
{
	CU_ASSERT_FALSE(osal_signal_install(SIGUSR1, NULL));
	CU_ASSERT_STRING_NOT_EQUAL(osal_signal_error(), "no error");

	CU_ASSERT_FALSE(osal_signal_install(-1, handler));
	CU_ASSERT_STRING_NOT_EQUAL(osal_signal_error(), "no error");
}

void test_signal_register(void)
{
	CU_pSuite suite = CU_add_suite("signal", NULL, NULL);

	CU_add_test(suite, "install", test_install);
	CU_add_test(suite, "errors", test_errors);
}
