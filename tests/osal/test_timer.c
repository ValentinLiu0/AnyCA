/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdatomic.h>
#include <time.h>

#include <CUnit/Basic.h>

#include <anyca/osal/timer.h>

#include "test_suites.h"

static atomic_int g_count;

static void callback(osal_timer_t *timer, void *context)
{
	(void) timer;
	(void) context;
	atomic_fetch_add(&g_count, 1);
}

static void sleep_ms(long milliseconds)
{
	struct timespec duration = { milliseconds / 1000,
				     (milliseconds % 1000) * 1000000L };

	nanosleep(&duration, NULL);
}

static bool wait_for_count(int target)
{
	for (int i = 0; i < 200; i++) {
		if (atomic_load(&g_count) >= target)
			return true;
		sleep_ms(10);
	}
	return false;
}

static void test_one_shot(void)
{
	osal_timer_t *timer;

	atomic_store(&g_count, 0);
	timer = osal_timer_create(callback, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(timer);
	CU_ASSERT_TRUE(osal_timer_start(timer, 20, 0));
	CU_ASSERT_TRUE(wait_for_count(1));
	osal_timer_stop(timer);
	sleep_ms(50);
	CU_ASSERT_EQUAL(atomic_load(&g_count), 1);
	osal_timer_destroy(timer);
}

static void test_periodic(void)
{
	osal_timer_t *timer;
	int count;

	atomic_store(&g_count, 0);
	timer = osal_timer_create(callback, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(timer);
	CU_ASSERT_TRUE(osal_timer_start(timer, 10, 10));
	CU_ASSERT_TRUE(wait_for_count(3));
	osal_timer_stop(timer);
	count = atomic_load(&g_count);
	sleep_ms(50);
	CU_ASSERT_EQUAL(atomic_load(&g_count), count);
	osal_timer_destroy(timer);
}

static void test_errors(void)
{
	CU_ASSERT_PTR_NULL(osal_timer_create(NULL, NULL));
	CU_ASSERT_STRING_NOT_EQUAL(osal_timer_error(), "no error");
	CU_ASSERT_FALSE(osal_timer_start(NULL, 10, 0));
	CU_ASSERT_STRING_NOT_EQUAL(osal_timer_error(), "no error");
	osal_timer_stop(NULL);
	osal_timer_destroy(NULL);
}

void test_timer_register(void)
{
	CU_pSuite suite = CU_add_suite("timer", NULL, NULL);

	CU_add_test(suite, "one_shot", test_one_shot);
	CU_add_test(suite, "periodic", test_periodic);
	CU_add_test(suite, "errors", test_errors);
}
