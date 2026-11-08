/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <anyca/osal/log.h>

#include <anyca/config.h>
#include <anyca/core.h>

#include "crl_service.h"
#include "http_server.h"

static void _server_usage(FILE *stream)
{
	fprintf(stream,
		"Usage: anyca_server [-c|--config <path>]\n"
		"  -c, --config <path>  configuration file (default: "
		CONFIG_DEFAULT_PATH ")\n"
		"  -h, --help           show this help\n"
		"  -V, --version        show the version\n");
}

/*
 * Return the configuration path, or NULL after reporting invalid arguments.
 * The default is the relative path config.yaml; -c/--config override it.
 * -h/--help and -V/--version select their action and return immediately.
 */
static const char *_server_config_path(int argc, char **argv, bool *help,
				       bool *version)
{
	const char *path = CONFIG_DEFAULT_PATH;

	*help = false;
	*version = false;
	for (int i = 1; i < argc; i++) {
		const char *argument = argv[i];

		if (strcmp(argument, "-h") == 0
		    || strcmp(argument, "--help") == 0) {
			*help = true;
			return path;
		}
		if (strcmp(argument, "-V") == 0
		    || strcmp(argument, "--version") == 0) {
			*version = true;
			return path;
		}
		if (strcmp(argument, "-c") == 0
		    || strcmp(argument, "--config") == 0) {
			if (i + 1 >= argc || argv[i + 1][0] == '\0') {
				fprintf(stderr,
					"anyca_server: %s needs a value\n",
					argument);
				return nullptr;
			}
			path = argv[++i];
		} else if (strncmp(argument, "--config=", 9) == 0) {
			if (argument[9] == '\0') {
				fprintf(stderr,
					"anyca_server: --config needs a value\n");
				return nullptr;
			}
			path = argument + 9;
		} else {
			fprintf(stderr,
				"anyca_server: unknown argument: %s\n",
				argument);
			return nullptr;
		}
	}
	return path;
}

int main(int argc, char **argv)
{
	config_t *config = nullptr;
	config_err_t config_status;
	const char *config_path;
	bool help;
	bool version;
	bool server_ok;

	/* Debug logging includes complete request URLs, which carry OCSP
	 * requests in Base64.  Keep it opt-in rather than the default. */
	osal_log_set_level(OSAL_LOG_INFO);

	config_path = _server_config_path(argc, argv, &help, &version);
	if (config_path == nullptr) {
		_server_usage(stderr);
		return EXIT_FAILURE;
	}
	if (help) {
		_server_usage(stdout);
		return EXIT_SUCCESS;
	}
	if (version) {
		printf("anyca_server %s\n", core_version());
		return EXIT_SUCCESS;
	}

	LOGI("Welcome to AnyCA (version: %s)", core_version());

	config_status = config_load(config_path, &config);
	if (config_status != CONFIG_OK) {
		LOGF("config_load failed for %s: %d", config_path,
		     (int) config_status);
		return EXIT_FAILURE;
	}

	LOGI("Loaded config file %s.\n\tHTTP Server: %s:%u"
	     "\n\tCount: HSM Provider: %u; CU: %u; CP: %u; CT: %u",
	     config_path,
	     (config->http.address != nullptr) ? config->http.address
					       : "<unset>",
	     (unsigned) config->http.port,
	     config->hsm_providers_count, config->certificate_usages_count,
	     config->certificate_policies_count,
	     config->certificate_templates_count);

	if (!core_init(config)) {
		LOGF("Failed to initialize the core");
		core_fini();
		config_free(config);
		return EXIT_FAILURE;
	}
	LOGI("Loaded %u CA(s)", core_ca_count());

	if (core_cacerts_publish_path() != nullptr) {
		for (unsigned i = 0; i < core_ca_count(); i++) {
			ca_t *ca = core_ca_at(i);

			if (ca != nullptr
			    && !core_publish_ca_certificate(ca))
				LOGW("CA %s: initial certificate publication "
				     "failed",
				     ca->name);
		}
	}

	if (!crl_service_start()) {
		LOGF("Failed to start CRL generation");
		core_fini();
		config_free(config);
		return EXIT_FAILURE;
	}

	/* The server reads the listening address while it runs. */
	server_ok = http_server_start(&(http_server_t) {
		.ipv4_address = config->http.address,
		.ipv4_port = config->http.port,
		.max_connections = config->http.max_connections,
		.requests_per_second = config->http.requests_per_second,
		.request_burst = config->http.request_burst,
	});

	crl_service_stop();
	core_fini();
	config_free(config);
	return server_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
