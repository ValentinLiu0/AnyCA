/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_CONFIG_H
#define ANYCA_CONFIG_H

/**
 * @file config.h
 * @brief Parsed AnyCA configuration.
 */

#include <stddef.h>
#include <stdint.h>

/**
 * Default configuration file path, relative to the process working directory.
 * Shared by anyca_cli and anyca_server; override with -c/--config.
 */
#define CONFIG_DEFAULT_PATH "config.yaml"

typedef struct config_store {
	/* SQLite database file path. */
	char *path;
} config_store_t;

/** HTTP listening settings. */
typedef struct config_http {
	char *address;
	uint16_t port;
	/**
	 * Maximum number of libwebsockets file descriptors, covering client
	 * connections and the listener.  Zero selects the built-in default.
	 */
	uint32_t max_connections;
	/**
	 * Maximum HTTP requests accepted per second across all clients.  Zero
	 * selects the built-in default.  Requests above the limit receive 503
	 * Service Unavailable.
	 */
	uint32_t requests_per_second;
	/**
	 * Maximum request burst allowed after an idle period.  Zero selects
	 * the built-in default.
	 */
	uint32_t request_burst;
} config_http_t;

typedef struct config_hsm_provider {
	char *name;
	char *library;
	/**
	 * Optional token model used to select this entry when a PKCS #11 URI
	 * omits the provider attribute.  Compared with the URI model
	 * attribute.
	 */
	char *model;
	/**
	 * Optional token serial used when a PKCS #11 URI omits the provider
	 * attribute.  Compared with the URI serial attribute.
	 */
	char *serial;
} config_hsm_provider_t;

typedef struct config_certificate_policy_cps {
	char *oid;
	char *uri;
} config_certificate_policy_cps_t;

typedef struct config_certificate_policy {
	char *name;

	config_certificate_policy_cps_t *cps;
	unsigned cps_count;
} config_certificate_policy_t;

typedef struct config_certificate_usage {
	char *name;

	char **basic_usages;
	unsigned basic_usages_count;

	char **enhanced_usage_oids;
	unsigned enhanced_usage_oids_count;
} config_certificate_usage_t;

/** AIA URIs of one certificate template. */
typedef struct config_certificate_template_aia {
	/** authorityInfoAccess id-ad-caIssuers URIs. */
	char **issuer_uris;
	unsigned issuer_uris_count;

	/** authorityInfoAccess id-ad-OCSP URIs. */
	char **ocsp_uris;
	unsigned ocsp_uris_count;
} config_certificate_template_aia_t;

/**
 * Reusable certificate profile selected at issuance time.
 *
 * The template supplies authorityInfoAccess and cRLDistributionPoints; it
 * holds no key or CA settings.
 */
typedef struct config_certificate_template {
	char *name;

	config_certificate_template_aia_t aia;

	/** cRLDistributionPoints fullName URIs. */
	char **crl_uris;
	unsigned crl_uris_count;
} config_certificate_template_t;

typedef struct config {
	config_store_t store;
	config_http_t http;

	/**
	 * Directory receiving published CRLs as <path>/<CA-name>/<CA-name>.crl.
	 * NULL or empty disables CRL publication.
	 */
	char *crl_publish_path;
	/**
	 * Directory receiving published CA certificates as
	 * <path>/<CA-name>.crt.  NULL or empty disables publication.
	 */
	char *cacerts_publish_path;

	config_hsm_provider_t *hsm_providers;
	unsigned hsm_providers_count;

	config_certificate_policy_t *certificate_policies;
	unsigned certificate_policies_count;

	config_certificate_usage_t *certificate_usages;
	unsigned certificate_usages_count;

	config_certificate_template_t *certificate_templates;
	unsigned certificate_templates_count;
} config_t;

/** Configuration load result.  CONFIG_OK is zero, failures are negative. */
typedef enum config_err {
	CONFIG_OK = 0,
	/** path or out is NULL. */
	CONFIG_ERR_ARGUMENT = -1,
	/** The file could not be opened. */
	CONFIG_ERR_FILE_OPEN = -2,
	/** The YAML is malformed or does not match the schema. */
	CONFIG_ERR_LOAD_FAILED = -3,
	/** Memory allocation failed while loading the file. */
	CONFIG_ERR_MEMORY = -4,
} config_err_t;

/**
 * Load the AnyCA configuration from a YAML file.  out is set to NULL on
 * failure; release success with config_free().
 */
config_err_t config_load(const char *path, config_t **out);

/** Release a configuration returned by config_load(). */
void config_free(config_t *config);

#endif // ANYCA_CONFIG_H