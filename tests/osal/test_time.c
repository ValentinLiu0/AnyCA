/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <time.h>

#include <CUnit/Basic.h>

#include <anyca/osal/time.h>

#include "test_suites.h"

static void test_epoch(void)
{
	struct tm broken_down = { 0 };

	broken_down.tm_year = 70;
	broken_down.tm_mon = 0;
	broken_down.tm_mday = 1;
	CU_ASSERT_EQUAL(osal_timegm(&broken_down), (time_t) 0);

	broken_down.tm_year = 100;
	CU_ASSERT_EQUAL(osal_timegm(&broken_down), (time_t) 946684800);
}

static void test_null(void)
{
	CU_ASSERT_EQUAL(osal_timegm(NULL), (time_t) -1);
}

void test_time_register(void)
{
	CU_pSuite suite = CU_add_suite("time", NULL, NULL);

	CU_add_test(suite, "epoch", test_epoch);
	CU_add_test(suite, "null", test_null);
}
