/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdint.h>

#include <CUnit/Basic.h>

#include <anyca/core.h>

#include "crl_service.h"
#include "test_suites.h"

static void test_due(void)
{
	const int64_t now = 1000000;

	/* Never published. */
	CU_ASSERT_TRUE(crl_service_is_due(0, now, 60));
	/* A zero period disables periodic publication. */
	CU_ASSERT_FALSE(crl_service_is_due(now, now, 0));
	CU_ASSERT_FALSE(crl_service_is_due(now - 86400, now, 0));
	/* Period not yet elapsed. */
	CU_ASSERT_FALSE(crl_service_is_due(now - 3599, now, 60));
	/* Exactly at the period boundary. */
	CU_ASSERT_TRUE(crl_service_is_due(now - 3600, now, 60));
	/* The clock moved backwards: publish rather than stall forever. */
	CU_ASSERT_TRUE(crl_service_is_due(now + 1, now, 60));
}

static void test_start_without_config(void)
{
	core_fini();

	/* No store, no CAs, no crl_publish_path: starting is a no-op. */
	CU_ASSERT_TRUE(crl_service_start());
	crl_service_stop();
	/* Stopping twice is safe. */
	crl_service_stop();
}

void test_crl_service_register(void)
{
	CU_pSuite suite = CU_add_suite("crl_service", NULL, NULL);

	CU_add_test(suite, "due", test_due);
	CU_add_test(suite, "start_without_config",
		    test_start_without_config);
}
