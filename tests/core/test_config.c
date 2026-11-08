/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/Basic.h>

#include <anyca/config.h>

#include "../test_support.h"
#include "test_suites.h"

static const char valid_yaml[] =
	"store:\n"
	"  path: \"test.db\"\n"
	"http:\n"
	"  address: \"127.0.0.1\"\n"
	"  port: 8443\n"
	"  max_connections: 64\n"
	"crl_publish_path: \"crl\"\n"
	"cacerts_publish_path: \"cacerts\"\n"
	"hsm_providers:\n"
	"  - name: \"soft\"\n"
	"    library: \"/usr/lib/libsoft.so\"\n"
	"    model: \"SoftHSM v2\"\n"
	"    serial: \"abc\"\n"
	"certificate_templates:\n"
	"  - name: \"tpl\"\n"
	"    aia:\n"
	"      issuer_uris:\n"
	"        - \"http://ca/ca.crt\"\n"
	"      ocsp_uris:\n"
	"        - \"http://ca/ocsp\"\n"
	"    crl_uris:\n"
	"      - \"http://ca/ca.crl\"\n"
	"certificate_policies:\n"
	"  - name: \"policy\"\n"
	"    cps:\n"
	"      - oid: \"2.23.140.1.4.1\"\n"
	"        uri: \"http://ca/cps\"\n"
	"certificate_usages:\n"
	"  - name: \"ca\"\n"
	"    basic_usages:\n"
	"      - \"keyCertSign\"\n"
	"    enhanced_usage_oids:\n"
	"      - \"1.3.6.1.5.5.7.3.3\"\n";

static char *write_yaml(const char *directory, const char *name,
			const char *text)
{
	size_t length = strlen(directory) + strlen(name) + 2;
	char *path = malloc(length);

	if (path == NULL)
		return NULL;
	snprintf(path, length, "%s/%s", directory, name);
	if (!test_write_file(path, text, strlen(text))) {
		free(path);
		return NULL;
	}
	return path;
}

static void test_load_valid(void)
{
	char *directory = test_temp_dir();
	char *path;
	config_t *config = NULL;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);
	path = write_yaml(directory, "valid.yaml", valid_yaml);
	CU_ASSERT_PTR_NOT_NULL_FATAL(path);

	CU_ASSERT_EQUAL(config_load(path, &config), CONFIG_OK);
	CU_ASSERT_PTR_NOT_NULL_FATAL(config);
	CU_ASSERT_STRING_EQUAL(config->store.path, "test.db");
	CU_ASSERT_STRING_EQUAL(config->http.address, "127.0.0.1");
	CU_ASSERT_EQUAL(config->http.port, 8443);
	CU_ASSERT_EQUAL(config->http.max_connections, 64);
	CU_ASSERT_STRING_EQUAL(config->crl_publish_path, "crl");
	CU_ASSERT_STRING_EQUAL(config->cacerts_publish_path, "cacerts");

	CU_ASSERT_EQUAL(config->hsm_providers_count, 1);
	CU_ASSERT_STRING_EQUAL(config->hsm_providers[0].name, "soft");
	CU_ASSERT_STRING_EQUAL(config->hsm_providers[0].library,
			       "/usr/lib/libsoft.so");
	CU_ASSERT_STRING_EQUAL(config->hsm_providers[0].model,
			       "SoftHSM v2");
	CU_ASSERT_STRING_EQUAL(config->hsm_providers[0].serial, "abc");

	CU_ASSERT_EQUAL(config->certificate_templates_count, 1);
	CU_ASSERT_STRING_EQUAL(config->certificate_templates[0].name, "tpl");
	CU_ASSERT_EQUAL(config->certificate_templates[0].aia.issuer_uris_count,
			1);
	CU_ASSERT_STRING_EQUAL(
		config->certificate_templates[0].aia.issuer_uris[0],
		"http://ca/ca.crt");
	CU_ASSERT_EQUAL(config->certificate_templates[0].aia.ocsp_uris_count,
			1);
	CU_ASSERT_EQUAL(config->certificate_templates[0].crl_uris_count, 1);

	CU_ASSERT_EQUAL(config->certificate_policies_count, 1);
	CU_ASSERT_EQUAL(config->certificate_policies[0].cps_count, 1);
	CU_ASSERT_STRING_EQUAL(config->certificate_policies[0].cps[0].oid,
			       "2.23.140.1.4.1");

	CU_ASSERT_EQUAL(config->certificate_usages_count, 1);
	CU_ASSERT_EQUAL(config->certificate_usages[0].basic_usages_count, 1);
	CU_ASSERT_EQUAL(
		config->certificate_usages[0].enhanced_usage_oids_count, 1);

	config_free(config);
	test_remove_tree(directory);
	free(path);
	free(directory);
}

static void test_errors(void)
{
	char *directory = test_temp_dir();
	char *path;
	char *bad_path;
	config_t *config = (config_t *) 1;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);

	CU_ASSERT_EQUAL(config_load(NULL, &config), CONFIG_ERR_ARGUMENT);
	CU_ASSERT_EQUAL(config_load("missing.yaml", NULL),
			CONFIG_ERR_ARGUMENT);

	CU_ASSERT_EQUAL(config_load("/nonexistent/anyca.yaml", &config),
			CONFIG_ERR_FILE_OPEN);
	CU_ASSERT_PTR_NULL(config);

	bad_path = write_yaml(directory, "bad.yaml", "store: [\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(bad_path);
	CU_ASSERT_EQUAL(config_load(bad_path, &config),
			CONFIG_ERR_LOAD_FAILED);
	CU_ASSERT_PTR_NULL(config);

	path = write_yaml(directory, "unknown.yaml",
			  "store:\n  path: \"x.db\"\n"
			  "http:\n  address: \"x\"\n  port: 1\n"
			  "hsm_providers:\n  - name: \"p\"\n"
			  "    library: \"l.so\"\n"
			  "bogus: 1\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(path);
	CU_ASSERT_EQUAL(config_load(path, &config),
			CONFIG_ERR_LOAD_FAILED);

	config_free(NULL);
	test_remove_tree(directory);
	free(bad_path);
	free(path);
	free(directory);
}

static void test_limits(void)
{
	char *directory = test_temp_dir();
	config_t *config = NULL;
	char *path;
	char *deep;
	size_t depth = 70;

	CU_ASSERT_PTR_NOT_NULL_FATAL(directory);

	/* Port 0 would ask the OS to bind an arbitrary port. */
	path = write_yaml(directory, "port0.yaml",
			  "store:\n  path: \"x.db\"\n"
			  "http:\n  address: \"x\"\n  port: 0\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(path);
	CU_ASSERT_EQUAL(config_load(path, &config),
			CONFIG_ERR_LOAD_FAILED);
	CU_ASSERT_PTR_NULL(config);

	/* YAML aliases could expand a small file into a huge document. */
	path = write_yaml(directory, "alias.yaml",
			  "store: &s\n  path: \"x.db\"\n"
			  "http:\n  address: \"x\"\n  port: 1\n"
			  "hsm_providers: *s\n");
	CU_ASSERT_PTR_NOT_NULL_FATAL(path);
	CU_ASSERT_EQUAL(config_load(path, &config),
			CONFIG_ERR_LOAD_FAILED);
	CU_ASSERT_PTR_NULL(config);

	/* Deep flow nesting must be rejected before the document is built. */
	deep = malloc(depth * 2 + 1);
	CU_ASSERT_PTR_NOT_NULL_FATAL(deep);
	for (size_t i = 0; i < depth; i++)
		deep[i] = '[';
	for (size_t i = 0; i < depth; i++)
		deep[depth + i] = ']';
	deep[depth * 2] = '\0';
	path = write_yaml(directory, "deep.yaml", deep);
	CU_ASSERT_PTR_NOT_NULL_FATAL(path);
	CU_ASSERT_EQUAL(config_load(path, &config),
			CONFIG_ERR_LOAD_FAILED);
	CU_ASSERT_PTR_NULL(config);

	free(deep);
	test_remove_tree(directory);
	free(directory);
}

void test_config_register(void)
{
	CU_pSuite suite = CU_add_suite("config", NULL, NULL);

	CU_add_test(suite, "load_valid", test_load_valid);
	CU_add_test(suite, "errors", test_errors);
	CU_add_test(suite, "limits", test_limits);
}
