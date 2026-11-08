/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_CLI_H
#define ANYCA_CLI_H

/**
 * @file cli.h
 * @brief Internal interfaces shared by the anyca_cli command modules.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <anyca/ca.h>
#include <anyca/cert.h>
#include <anyca/config.h>
#include <anyca/hsm.h>
#include <anyca/store.h>

/** Default and maximum validity accepted by --days. */
#define CLI_DEFAULT_VALIDITY_DAYS 3650U
#define CLI_MAX_VALIDITY_DAYS 365000U

/** Default CRL publication period for a new CA: 7 days. */
#define CLI_DEFAULT_CRL_PUBLISH_PERIOD_MIN (7U * 24U * 60U)
/** Default OCSP nextUpdate period for a new CA, in minutes. */
#define CLI_DEFAULT_OCSP_UPDATE_PERIOD_MIN 10U

/** id-kp-OCSPSigning, required in an OCSP signing certificate. */
#define CLI_OCSP_SIGNING_EKU "1.3.6.1.5.5.7.3.9"

/** Returned by a command whose options were invalid; main prints usage. */
#define CLI_EXIT_USAGE (-1)

/** Global options, accepted before and after the command name. */
typedef struct cli_global_options {
	const char *config_path;
	/** Command being run, for command-specific help; set by main(). */
	const char *command;
	/** Subcommand being run, for command-specific help; set by main(). */
	const char *subcommand;
} cli_global_options_t;

/** A CA loaded from the store configuration. */
typedef struct cli_ca {
	ca_t *ca;
	store_ca_id_t store_id;
} cli_ca_t;

/** Loaded configuration, store and optional CAs used by a command. */
typedef struct cli_context {
	config_t *config;
	cli_ca_t *cas;
	unsigned cas_count;
} cli_context_t;

/** Result of parsing one argument as a global option. */
typedef enum cli_global_option_result {
	CLI_GLOBAL_OPTION_NOT_MATCHED,
	CLI_GLOBAL_OPTION_HANDLED,
	CLI_GLOBAL_OPTION_HELP,
	CLI_GLOBAL_OPTION_VERSION,
	CLI_GLOBAL_OPTION_ERROR,
} cli_global_option_result_t;

/** Result of a command's option parser. */
typedef enum cli_parse_result {
	CLI_PARSE_OK,
	CLI_PARSE_HELP,
	CLI_PARSE_VERSION,
	CLI_PARSE_ERROR,
} cli_parse_result_t;

/** One option accepted by cli_parse_options(). */
typedef struct cli_option_spec {
	const char *name;
	/** offsetof() of the field that receives the value. */
	size_t offset;
	/** Accept an empty value (string options only). */
	bool allow_empty;
	/** The option takes no value and stores true in a bool field. */
	bool is_flag;
} cli_option_spec_t;

#define CLI_OPTION_SPEC(type, field, name) \
	{ (name), offsetof(type, field), false, false }
#define CLI_OPTION_SPEC_ALLOW_EMPTY(type, field, name) \
	{ (name), offsetof(type, field), true, false }
#define CLI_OPTION_SPEC_FLAG(type, field, name) \
	{ (name), offsetof(type, field), false, true }
#define CLI_OPTION_COUNT(specs) (sizeof (specs) / sizeof (specs)[0])

/** Finish a command entry point after cli_parse_options(). */
#define CLI_PARSE_OR_RETURN(parse, global) \
	do { \
		if ((parse) == CLI_PARSE_HELP) { \
			cli_usage_current(stdout, (global)); \
			return EXIT_SUCCESS; \
		} \
		if ((parse) == CLI_PARSE_VERSION) { \
			cli_print_version(stdout); \
			return EXIT_SUCCESS; \
		} \
		if ((parse) == CLI_PARSE_ERROR) \
			return CLI_EXIT_USAGE; \
	} while (0)

/**
 * Parse global options and the options in specs.
 *
 * options must be zero-initialized; string values are stored as
 * const char * at the spec offset, and flags store true in a bool field.
 */
cli_parse_result_t cli_parse_options(int argc, char **argv, int first,
				     cli_global_options_t *global,
				     const cli_option_spec_t *specs,
				     size_t count, void *options);

/** Print the top-level command reference. */
void cli_usage(FILE *stream);

/** Print the subcommands and description of one command group. */
void cli_usage_group(FILE *stream, const char *group);

/** Print the reference for one command. */
void cli_usage_command(FILE *stream, const char *group, const char *name);

/** Print the reference for the command selected in global. */
void cli_usage_current(FILE *stream, const cli_global_options_t *global);

/** Print the program name and version. */
void cli_print_version(FILE *stream);

/** Match "--name" or "--name=value"; return the inline value when present. */
bool cli_option_matches(const char *argument, const char *name,
			const char **inline_value);

/** Read an option value, either inline or from the next argument. */
const char *cli_option_value(int argc, char **argv, int *index,
			     const char *inline_value, const char *name);

/** Like cli_option_value(), but an empty value is accepted. */
const char *cli_option_value_allow_empty(int argc, char **argv, int *index,
					 const char *inline_value,
					 const char *name);

/** Handle -h/--help, -V/--version, -c/--config. */
cli_global_option_result_t cli_parse_global_option(
	int argc, char **argv, int *index, const char *argument,
	cli_global_options_t *global);

char *cli_strdup(const char *value);
bool cli_parse_serial(const char *text, unsigned char **serial,
		      size_t *serial_length);
/** Parse a positive CA id, as printed by "ca list". */
bool cli_parse_ca_id(const char *text, store_ca_id_t *ca_id);
/**
 * Resolve the --ca-name/--ca-id selector to a configuration name.
 *
 * At most one selector may be set.  With neither, *name is NULL and the
 * result is true only when allow_none is true.  A CA id must name a
 * registered identity whose key hash matches the current CA certificate.  On
 * success *name is osal_malloc()ed; release it with osal_free().
 */
bool cli_ca_selection_resolve(const char *ca_name,
					    const char *ca_id, bool allow_none,
					    char **name);
char *cli_bytes_to_hex(const unsigned char *data, size_t length);

/** Optional output of cli_record_issued_certificate(). */
typedef struct cli_certificate_record {
	store_ca_id_t ca_id;
	/** osal_malloc()ed serial; the caller releases it with osal_free(). */
	unsigned char *serial;
	size_t serial_length;
	/** true when a new record was added, false when an existing record was
	 *  updated. */
	bool created;
} cli_certificate_record_t;

/**
 * Record a DER certificate under the CA that issued it.
 *
 * The CA identity is registered from ca_cert_der (idempotently, by name and
 * SPKI SHA-256); serial and notAfter come from certificate_der.  An existing
 * serial has its notAfter updated instead.
 *
 * result_record is optional and receives the store id and serial on success;
 * it can be used to roll the record back with store_certificate_delete().
 */
bool cli_record_issued_certificate(
	const char *ca_name, const unsigned char *ca_cert_der,
	size_t ca_cert_der_length, const unsigned char *certificate_der,
	size_t certificate_der_length,
	cli_certificate_record_t *result_record);

bool cli_parse_int64(const char *text, int64_t *value);
bool cli_parse_uint32(const char *text, uint32_t *value);
bool cli_parse_bool(const char *text, bool *value);
/** Parse --days within CLI_MAX_VALIDITY_DAYS; text must not be NULL. */
bool cli_parse_validity_days(const char *text, uint32_t *days);
/** Parse sha1, sha256, sha384 or sha512 into a digest algorithm. */
bool cli_parse_digest(const char *text, cert_digest_algorithm_t *digest);
/** Canonical name of a digest algorithm; NULL for an invalid value. */
const char *cli_digest_name(cert_digest_algorithm_t digest);
bool cli_read_file(const char *path, unsigned char **data, size_t *length);
bool cli_write_file(const char *path, const unsigned char *data, size_t length);
bool cli_require_option(const char *value, const char *option);
/** Find an hsm_providers entry by name. */
const config_hsm_provider_t *cli_hsm_provider_find(const config_t *config,
						   const char *name);
/** Find a certificate_usages entry by name. */
const config_certificate_usage_t *cli_certificate_usage_find(
	const config_t *config, const char *name);
/** Find a certificate_templates entry by name. */
const config_certificate_template_t *cli_certificate_template_find(
	const config_t *config, const char *name);
/** Find a certificate_policies entry by name. */
const config_certificate_policy_t *cli_certificate_policy_find(
	const config_t *config, const char *name);

bool cli_context_init(const char *config_path, cli_context_t *context,
		      bool load_cas);
void cli_context_fini(cli_context_t *context);

/** Location of an HSM key used by the CLI. */
typedef struct cli_hsm_key {
	/** Resolved HSM provider name from config.hsm_providers. */
	const char *hsm_provider;
	/** Token label. */
	const char *token_label;
	/** Token user PIN. */
	const char *pin;
	/** Key label. */
	const char *key_label;
} cli_hsm_key_t;

/** Open PKCS #11 module and token used by one CLI command. */
typedef struct cli_hsm_session {
	hsm_token_t *token;
	hsm_module_t *module;
} cli_hsm_session_t;

/** Report the last HSM error from a failed operation. */
void cli_hsm_log(const char *what, hsm_status_t status);

/**
 * Open a provider's module and one token.
 *
 * When pin is NULL the token is opened without logging in; private-key
 * operations require a PIN.  Failures are reported before returning false.
 */
bool cli_hsm_session_open(cli_hsm_session_t *session,
					const config_hsm_provider_t *provider,
					const char *token_label,
					const char *pin);

/** Close a session opened by cli_hsm_session_open(). */
void cli_hsm_session_close(cli_hsm_session_t *session);

/**
 * Parsed PKCS #11 URI.
 *
 * Uses the RFC 7512 form: ';'-separated path attributes and optional
 * '&'-separated query attributes.  AnyCA adds the vendor-specific path
 * attribute provider=<name> and also accepts pin-value/pin-source in the
 * path for compatibility.
 *
 * Without provider, the hsm_providers entry is selected by model and serial;
 * see cli_hsm_uri_resolve_provider().  token and object are CKA_LABEL values.
 * %XX escapes are accepted.  The fields point into storage or pin_storage and
 * stay valid until cli_hsm_uri_free().
 */
typedef struct cli_hsm_uri {
	cli_hsm_key_t key;
	/** URI model attribute; selects the provider when provider is absent. */
	const char *model;
	/** URI serial attribute; refines the provider match. */
	const char *serial;
	/** URI manufacturer attribute, accepted for RFC 7512 compatibility. */
	const char *manufacturer;
	/** Owned copy of the URI attributes; allocated with
	 *  osal_secure_malloc() because it may contain pin-value. */
	char *storage;
	/** Owned PIN read from pin-source; NULL for pin-value.  Allocated with
	 *  osal_secure_malloc(). */
	char *pin_storage;
} cli_hsm_uri_t;

/**
 * Parse a PKCS #11 URI.
 *
 * Path attributes: provider (AnyCA extension), token, object, model, serial,
 * manufacturer, type (private only), pin-value and pin-source.  The query
 * accepts pin-value and pin-source.
 */
bool cli_hsm_uri_parse(const char *uri, cli_hsm_uri_t *parsed);

/**
 * Resolve the hsm_providers entry named or described by a parsed URI.
 *
 * With provider, the named entry is used and model/serial must match when the
 * entry declares them.  Without provider, model and serial must select exactly
 * one entry; an entry declaring every attribute takes precedence.  On success
 * key.hsm_provider points to the selected entry's name.
 *
 * @param option option name used in diagnostics, e.g. "--key-uri".
 */
bool cli_hsm_uri_resolve_provider(const config_t *config,
						cli_hsm_uri_t *uri,
						const char *option);

/** Release a parsed URI.  Passing NULL is a no-op. */
void cli_hsm_uri_free(cli_hsm_uri_t *parsed);

/**
 * Generate an RSA, EC or ML-DSA key pair in the token named by key.
 *
 * @param key_type "rsa", "ec", "ml-dsa-44", "ml-dsa-65" or "ml-dsa-87".
 * @param rsa_bits RSA modulus size, at least 2048.
 * @param ec_curve "p256", "p384" or "p521".
 */
bool cli_generate_key_pair(const config_t *config,
					 const cli_hsm_key_t *key,
					 const char *key_type,
					 unsigned int rsa_bits,
					 const char *ec_curve);

/**
 * Destroy a key pair created by cli_generate_key_pair().
 *
 * Used to clean up after a later step failed.  Returns true when the key pair
 * no longer exists; on failure the operator must remove it manually.
 */
bool cli_delete_key_pair(const config_t *config,
				       const cli_hsm_key_t *key);

/**
 * Verify that an HSM key belongs to a certificate by signing a fixed
 * challenge and verifying it with the certificate public key.  RSA, EC and
 * ML-DSA keys are supported.
 *
 * @param what description used in diagnostics, e.g. "CA" or "OCSP signer".
 */
bool cli_key_matches_certificate(const config_t *config,
					       const cli_hsm_key_t *key,
					       const X509 *certificate,
					       const char *what);

/** Parameters for cli_generate_certificate(). */
typedef struct cli_cert_options {
	/**
	 * DER-encoded issuer certificate.  NULL makes the certificate
	 * self-signed.
	 */
	const unsigned char *issuer_certificate;
	size_t issuer_certificate_length;
	/** Issuer signing key; also the subject key for a self-signed cert. */
	cli_hsm_key_t issuer_key;

	/** Subject distinguished name. */
	const char *subject;
	/**
	 * Subject public key.  hsm_provider may be NULL or empty to use the
	 * issuer provider.
	 */
	cli_hsm_key_t subject_key;
	/** certificate_usages entry name.  NULL selects the explicit usage. */
	const char *certificate_usage;
	/** keyUsage bits used when certificate_usage is NULL. */
	uint32_t key_usage;
	/** enhancedKeyUsage OIDs used when certificate_usage is NULL. */
	const char *const *enhanced_usage_oids;
	size_t enhanced_usage_oids_count;
	/**
	 * Optional certificate_templates entry name.  When set, the template
	 * supplies the authorityInfoAccess and cRLDistributionPoints URIs.
	 */
	const char *certificate_template;
	/** Signature digest; zero (CERT_DIGEST_SHA384) is the default. */
	cert_digest_algorithm_t digest;

	/** basicConstraints cA value. */
	bool is_ca;
	/** Emit pathLenConstraint when true (requires is_ca). */
	bool has_path_length;
	/** pathLenConstraint value when has_path_length is true. */
	uint32_t path_length;
	/** Optional serial bytes; NULL or zero length selects 16 random bytes. */
	const unsigned char *serial;
	size_t serial_length;
	/** Validity period in days; zero selects 3650. */
	uint32_t validity_days;
	/** notBefore as Unix time; zero selects the current time. */
	int64_t not_before;
} cli_cert_options_t;

/**
 * Build and sign a certificate with configured HSM keys.
 *
 * A NULL issuer_certificate produces a self-signed certificate; otherwise the
 * issuer certificate signs the subject key.  The certificate_usages entry
 * supplies keyUsage bits and, for issued certificates, EKU OIDs.
 */
bool cli_generate_certificate(const config_t *config,
			      const cli_cert_options_t *options,
			      cert_blob_t *certificate);

/** Parameters for cli_sign_certificate_request(). */
typedef struct cli_csr_sign_options {
	/** DER-encoded issuer certificate. */
	const unsigned char *issuer_certificate;
	size_t issuer_certificate_length;
	/** Issuer signing key. */
	cli_hsm_key_t issuer_key;
	/** Request whose subject and public key are copied. */
	const cert_request_t *request;

	/** Basic mode: build extensions from the profile below. */
	bool basic;
	/** basicConstraints cA (basic mode). */
	bool is_ca;
	/** Emit pathLenConstraint (basic mode; requires is_ca). */
	bool has_path_length;
	/** pathLenConstraint value when has_path_length is true. */
	uint32_t path_length;
	/** certificate_usages entry name (basic mode). */
	const char *certificate_usage;
	/** Optional certificate_templates entry name (basic mode). */
	const char *certificate_template;
	/** Optional certificate_policies entry name (basic mode). */
	const char *certificate_policy;

	/** Add authorityKeyIdentifier when true. */
	bool add_aki;
	/** Add subjectKeyIdentifier to CA certificates when true. */
	bool add_ski;

	/** Signature digest; zero (CERT_DIGEST_SHA384) is the default. */
	cert_digest_algorithm_t digest;
	/** Optional serial bytes; NULL or zero length selects 16 random bytes. */
	const unsigned char *serial;
	size_t serial_length;
	/** Validity period in days; zero selects 3650. */
	uint32_t validity_days;
	/** notBefore as Unix time; zero selects the current time. */
	int64_t not_before;
} cli_csr_sign_options_t;

/**
 * Sign a certificate request with a configured HSM key.
 *
 * Basic mode copies only the request subject and public key and builds the
 * extensions from the configured profiles.  Enforce mode copies the requested
 * extensions (except subject and authority key identifiers) and forces
 * keyUsage and basicConstraints critical.  Both modes add
 * authorityKeyIdentifier when add_aki is set and a computed
 * subjectKeyIdentifier on CA certificates when add_ski is set.
 */
bool cli_sign_certificate_request(const config_t *config,
				  const cli_csr_sign_options_t *options,
				  cert_blob_t *certificate);

/** Build the default OCSP signer subject "CN=<ca name> OCSP Signer", escaping
 *  DN special characters.  Returns an osal_malloc()ed string. */
char *cli_ocsp_signer_subject(const char *ca_name);

/**
 * Generate an OCSP signing certificate and return its DER encoding.
 *
 * The certificate is issued by issuer_certificate with issuer_key, carries
 * signer_key's public key and is signed with digest.  Extensions are fixed:
 * critical keyUsage digitalSignature and basicConstraints cA=false, plus
 * OCSPSigning EKU.  subject defaults to cli_ocsp_signer_subject(ca_name).
 * notBefore is backdated one hour so the certificate is immediately usable.
 */
bool cli_generate_ocsp_signer_certificate(
	const config_t *config, const char *ca_name,
	const unsigned char *issuer_certificate,
	size_t issuer_certificate_length,
	const cli_hsm_key_t *issuer_key,
	const cli_hsm_key_t *signer_key, cert_digest_algorithm_t digest,
	const char *subject,
	uint32_t validity_days, const unsigned char *serial,
	size_t serial_length, cert_blob_t *certificate);

/* Command entry points: parse options starting at first, then run. */
int cli_cmd_ca_create(cli_global_options_t *global, int argc, char **argv,
		      int first);
int cli_cmd_ca_import(cli_global_options_t *global, int argc, char **argv,
		      int first);
int cli_cmd_ca_list(cli_global_options_t *global, int argc, char **argv,
		    int first);
int cli_cmd_ca_update(cli_global_options_t *global, int argc, char **argv,
		      int first);
int cli_cmd_ca_delete(cli_global_options_t *global, int argc, char **argv,
		      int first);
int cli_cmd_ca_publish_crl(cli_global_options_t *global, int argc, char **argv,
			   int first);
int cli_cmd_ca_ocsp_renew(cli_global_options_t *global, int argc, char **argv,
			  int first);

int cli_cmd_cert_issue(cli_global_options_t *global, int argc, char **argv,
		       int first);
int cli_cmd_cert_new_root(cli_global_options_t *global, int argc, char **argv,
			  int first);
int cli_cmd_cert_record(cli_global_options_t *global, int argc, char **argv,
			int first);
int cli_cmd_cert_revoke(cli_global_options_t *global, int argc, char **argv,
			int first);
int cli_cmd_cert_list(cli_global_options_t *global, int argc, char **argv,
		      int first);

int cli_cmd_crl_publish(cli_global_options_t *global, int argc, char **argv,
			int first);

int cli_cmd_hsm_list(cli_global_options_t *global, int argc, char **argv,
		     int first);
int cli_cmd_hsm_token_info(cli_global_options_t *global, int argc, char **argv,
			   int first);
int cli_cmd_hsm_key_list(cli_global_options_t *global, int argc, char **argv,
			 int first);
int cli_cmd_hsm_key_info(cli_global_options_t *global, int argc, char **argv,
			 int first);
int cli_cmd_hsm_fetch_uri(cli_global_options_t *global, int argc, char **argv,
			  int first);
int cli_cmd_hsm_search_key(cli_global_options_t *global, int argc, char **argv,
			   int first);
int cli_cmd_hsm_keygen(cli_global_options_t *global, int argc, char **argv,
		       int first);
int cli_cmd_hsm_keydel(cli_global_options_t *global, int argc, char **argv,
		       int first);
int cli_cmd_hsm_pin_set(cli_global_options_t *global, int argc, char **argv,
			int first);

#endif // ANYCA_CLI_H
