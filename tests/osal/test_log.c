/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <CUnit/Basic.h>

#include <anyca/osal/log.h>

#include "test_suites.h"

static void test_level(void)
{
	osal_log_set_level(OSAL_LOG_WARN);
	CU_ASSERT_EQUAL(osal_log_get_level(), OSAL_LOG_WARN);

	osal_log_set_level(OSAL_LOG_ERROR);
	CU_ASSERT_EQUAL(osal_log_get_level(), OSAL_LOG_ERROR);

	osal_log_set_level(OSAL_LOG_VERBOSE);
	CU_ASSERT_EQUAL(osal_log_get_level(), OSAL_LOG_VERBOSE);
}

void test_log_register(void)
{
	CU_pSuite suite = CU_add_suite("log", NULL, NULL);

	CU_add_test(suite, "level", test_level);
}
