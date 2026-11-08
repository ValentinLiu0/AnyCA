/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/osal/memory.h>

#include "test_suites.h"

static void test_heap(void)
{
	unsigned char *memory = osal_malloc(32);

	CU_ASSERT_PTR_NOT_NULL(memory);
	if (memory != NULL) {
		memset(memory, 0xab, 32);
		CU_ASSERT_EQUAL(memory[0], 0xab);
		CU_ASSERT_EQUAL(memory[31], 0xab);
		osal_free(memory);
	}

	memory = osal_calloc(8, 4);
	CU_ASSERT_PTR_NOT_NULL(memory);
	if (memory != NULL) {
		for (size_t i = 0; i < 32; i++)
			CU_ASSERT_EQUAL(memory[i], 0);
		osal_free(memory);
	}

	osal_free(NULL);
}

static void test_realloc(void)
{
	char *memory = osal_malloc(4);

	CU_ASSERT_PTR_NOT_NULL(memory);
	if (memory == NULL)
		return;
	memcpy(memory, "abc", 4);
	memory = osal_realloc(memory, 128);
	CU_ASSERT_PTR_NOT_NULL(memory);
	if (memory == NULL)
		return;
	CU_ASSERT_STRING_EQUAL(memory, "abc");
	osal_free(memory);
}

static void test_secure(void)
{
	unsigned char *memory = osal_secure_malloc(64);

	CU_ASSERT_PTR_NOT_NULL(memory);
	if (memory != NULL) {
		for (size_t i = 0; i < 64; i++)
			CU_ASSERT_EQUAL(memory[i], 0);
		memset(memory, 0x5a, 64);
		osal_secure_free(memory);
	}

	CU_ASSERT_PTR_NULL(osal_secure_malloc(0));
	osal_secure_free(NULL);
}

void test_memory_register(void)
{
	CU_pSuite suite = CU_add_suite("memory", NULL, NULL);

	CU_add_test(suite, "heap", test_heap);
	CU_add_test(suite, "realloc", test_realloc);
	CU_add_test(suite, "secure", test_secure);
}
