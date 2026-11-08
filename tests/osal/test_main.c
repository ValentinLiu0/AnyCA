/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <CUnit/Basic.h>

#include "test_suites.h"

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS)
		return 1;

	test_memory_register();
	test_time_register();
	test_log_register();
	test_file_register();
	test_dynlib_register();
	test_signal_register();
	test_timer_register();

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	unsigned failures = CU_get_number_of_failures();
	CU_cleanup_registry();
	return failures == 0 ? 0 : 1;
}
