/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CUnit/Basic.h>

#include <anyca/osal/file.h>

#include "test_suites.h"

static char *make_temp_dir(void)
{
	char template[] = "/tmp/anyca_osal_file_XXXXXX";
	char *directory = mkdtemp(template);

	return directory != NULL ? strdup(directory) : NULL;
}

static size_t file_size(const char *path)
{
	struct stat status;

	if (stat(path, &status) != 0)
		return SIZE_MAX;
	return (size_t) status.st_size;
}

static void test_make_dirs(void)
{
	char *directory = make_temp_dir();
	char path[PATH_MAX];
	struct stat status;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(path, sizeof path, "%s/a/b", directory);

	CU_ASSERT_TRUE(osal_file_make_dirs(path));
	CU_ASSERT_EQUAL(stat(path, &status), 0);
	CU_ASSERT_TRUE(S_ISDIR(status.st_mode));
	CU_ASSERT_TRUE(osal_file_make_dirs(path));
	CU_ASSERT_STRING_EQUAL(osal_file_error(), "no error");

	CU_ASSERT_FALSE(osal_file_make_dirs(NULL));
	CU_ASSERT_STRING_NOT_EQUAL(osal_file_error(), "no error");

	snprintf(path, sizeof path, "%s/a/b", directory);
	rmdir(path);
	snprintf(path, sizeof path, "%s/a", directory);
	rmdir(path);
	rmdir(directory);
	free(directory);
}

static void test_create_private(void)
{
	char *directory = make_temp_dir();
	char path[PATH_MAX];
	struct stat status;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(path, sizeof path, "%s/key.pem", directory);

	CU_ASSERT_TRUE(osal_file_create_private(path));
	CU_ASSERT_EQUAL(stat(path, &status), 0);
	CU_ASSERT_EQUAL(status.st_mode & 0777, 0600);
	CU_ASSERT_TRUE(osal_file_create_private(path));

	CU_ASSERT_FALSE(osal_file_create_private(NULL));
	CU_ASSERT_STRING_NOT_EQUAL(osal_file_error(), "no error");

	unlink(path);
	rmdir(directory);
	free(directory);
}

static void test_write_atomic(void)
{
	char *directory = make_temp_dir();
	char path[PATH_MAX];
	char buffer[16] = { 0 };
	FILE *file;
	struct stat status;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	snprintf(path, sizeof path, "%s/nested/deep/out.bin", directory);

	CU_ASSERT_TRUE(osal_file_write_atomic(path, "hello", 5, 0600));
	file = fopen(path, "rb");
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);
	CU_ASSERT_EQUAL(fread(buffer, 1, sizeof buffer, file), 5);
	fclose(file);
	CU_ASSERT_STRING_EQUAL(buffer, "hello");
	CU_ASSERT_EQUAL(stat(path, &status), 0);
	CU_ASSERT_EQUAL(status.st_mode & 0777, 0600);

	CU_ASSERT_TRUE(osal_file_write_atomic(path, "bye", 3, 0));
	CU_ASSERT_EQUAL(file_size(path), 3);
	CU_ASSERT_TRUE(osal_file_write_atomic(path, NULL, 0, 0));
	CU_ASSERT_EQUAL(file_size(path), 0);

	CU_ASSERT_FALSE(osal_file_write_atomic(NULL, "x", 1, 0));
	CU_ASSERT_STRING_NOT_EQUAL(osal_file_error(), "no error");
	CU_ASSERT_FALSE(osal_file_write_atomic(path, NULL, 1, 0));

	unlink(path);
	snprintf(path, sizeof path, "%s/nested/deep", directory);
	rmdir(path);
	snprintf(path, sizeof path, "%s/nested", directory);
	rmdir(path);
	rmdir(directory);
	free(directory);
}

void test_file_register(void)
{
	CU_pSuite suite = CU_add_suite("file", NULL, NULL);

	CU_add_test(suite, "make_dirs", test_make_dirs);
	CU_add_test(suite, "create_private", test_create_private);
	CU_add_test(suite, "write_atomic", test_write_atomic);
}
