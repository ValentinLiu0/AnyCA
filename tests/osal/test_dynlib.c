/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <CUnit/Basic.h>

#include <anyca/osal/dynlib.h>

#include "test_suites.h"

static void test_open_symbol(void)
{
	osal_dynlib_t *library = osal_dynlib_open("libc.so.6");

	CU_ASSERT_PTR_NOT_NULL_FATAL(library);
	CU_ASSERT_STRING_EQUAL(osal_dynlib_error(), "no error");
	CU_ASSERT_PTR_NOT_NULL(osal_dynlib_symbol(library, "malloc"));
	osal_dynlib_close(library);
}

static void test_errors(void)
{
	CU_ASSERT_PTR_NULL(osal_dynlib_open(NULL));
	CU_ASSERT_STRING_NOT_EQUAL(osal_dynlib_error(), "no error");

	CU_ASSERT_PTR_NULL(osal_dynlib_open("/nonexistent/anyca-test.so"));
	CU_ASSERT_STRING_NOT_EQUAL(osal_dynlib_error(), "no error");

	CU_ASSERT_PTR_NULL(osal_dynlib_symbol(NULL, "malloc"));
	CU_ASSERT_STRING_NOT_EQUAL(osal_dynlib_error(), "no error");

	CU_ASSERT_PTR_NULL(osal_dynlib_symbol(NULL, NULL));
	CU_ASSERT_STRING_NOT_EQUAL(osal_dynlib_error(), "no error");

	osal_dynlib_close(NULL);
}

void test_dynlib_register(void)
{
	CU_pSuite suite = CU_add_suite("dynlib", NULL, NULL);

	CU_add_test(suite, "open_symbol", test_open_symbol);
	CU_add_test(suite, "errors", test_errors);
}
