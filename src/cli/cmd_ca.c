/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <anyca/osal/compat.h>
#include <anyca/osal/memory.h>

#include <anyca/ca.h>
#include <anyca/cert.h>
#include <anyca/core.h>
#include <anyca/store.h>

#include "cli.h"

typedef struct cli_ca_options {
	const char *name;
	const char *ca_name;
	const char *ca_id;
	const char *key_uri;
	const char *ca_cert_path;
	const char *ocsp_key_uri;
	const char *subject;
	const char *certificate_usage;
	const char *key_type;
	const char *rsa_bits;
	const char *ec_curve;
	const char *crl_publish_period_min;
	const char *ocsp_update_period_min;
	const char *ocsp_responder_endpoint;
	const char *ocsp_signer_hash_algorithm;
	bool all;
} cli_ca_options_t;

static bool _cli_replace_string(char **destination, const char *value)
{
	char *copy = cli_strdup(value);

	if (value != nullptr && copy == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}
	osal_free(*destination);
	*destination = copy;
	return true;
}

/* Replace a PIN field; secure memory is wiped when the old value is freed. */
static bool _cli_replace_secure_string(char **destination, const char *value)
{
	char *copy = nullptr;

	if (value != nullptr) {
		size_t length = strlen(value) + 1;

		copy = osal_secure_malloc(length);
		if (copy == nullptr) {
			fprintf(stderr, "anyca_cli: out of memory\n");
			return false;
		}
		memcpy(copy, value, length);
	}
	osal_secure_free(*destination);
	*destination = copy;
	return true;
}

/* Reject a CA name or OCSP endpoint that an existing configuration uses. */
static bool _cli_ca_config_available(const char *name, const char *endpoint)
{
	store_ca_config_t *configs = nullptr;
	size_t count = 0;
	bool available = true;

	if (store_ca_config_list(&configs, &count) != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: cannot check the existing CA configurations\n");
		return false;
	}

	for (size_t i = 0; i < count; i++) {
		if (name != nullptr && configs[i].name != nullptr
		    && strcmp(configs[i].name, name) == 0) {
			fprintf(stderr,
				"anyca_cli: CA name is already in use: %s\n",
				name);
			available = false;
			break;
		}
		if (endpoint != nullptr
		    && configs[i].ocsp_responder_endpoint != nullptr
		    && strcmp(configs[i].ocsp_responder_endpoint, endpoint)
			       == 0) {
			fprintf(stderr,
				"anyca_cli: OCSP responder endpoint is already in use: %s\n",
				endpoint);
			available = false;
			break;
		}
	}

	store_ca_config_list_free(configs, count);
	return available;
}

/* Remove a key pair created by this command after a later step failed. */
static void _cli_delete_generated_key(const config_t *config,
				      const cli_hsm_key_t *key,
				      bool generated, const char *what)
{
	if (!generated)
		return;

	if (!cli_delete_key_pair(config, key))
		fprintf(stderr,
			"anyca_cli: warning: cannot remove the generated %s key \"%s\" from the token; delete it manually\n",
			what, key->key_label);
}

/* Read and validate one DER certificate.  The caller owns the buffer. */
static bool _cli_read_certificate(const char *path, unsigned char **data,
				  size_t *length, const char *what)
{
	X509 *certificate;

	*data = nullptr;
	*length = 0;
	if (!cli_read_file(path, data, length))
		return false;

	certificate = ca_certificate_load_der(*data, *length);
	if (certificate == nullptr) {
		fprintf(stderr, "anyca_cli: cannot parse %s: %s\n", what, path);
		osal_free(*data);
		*data = nullptr;
		*length = 0;
		return false;
	}
	ca_certificate_free(certificate);
	return true;
}

static bool _cli_replace_certificate(const char *path,
				     unsigned char **data, size_t *length,
				     const char *what)
{
	unsigned char *new_data = nullptr;
	size_t new_length = 0;

	if (!_cli_read_certificate(path, &new_data, &new_length, what))
		return false;

	osal_free(*data);
	*data = new_data;
	*length = new_length;
	return true;
}

/*
 * Build a CA probe from borrowed DER buffers.  The caller must clear the
 * borrowed blobs with _cli_ca_probe_free() rather than releasing them here.
 */
static void _cli_ca_probe_free(ca_t *probe);

static ca_t *_cli_ca_probe_new(const store_ca_config_t *config,
			       const unsigned char *signer_cert,
			       size_t signer_cert_length)
{
	ca_t *probe = ca_new();

	if (probe == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return nullptr;
	}
	probe->ca_cert_der.data = config->ca_cert;
	probe->ca_cert_der.length = config->ca_cert_length;
	probe->ocsp_signer_cert_der.data = (unsigned char *) signer_cert;
	probe->ocsp_signer_cert_der.length = signer_cert_length;

	if (!ca_load_certificate(probe)) {
		_cli_ca_probe_free(probe);
		return nullptr;
	}
	return probe;
}

static void _cli_ca_probe_free(ca_t *probe)
{
	if (probe == nullptr)
		return;

	/* The DER buffers are borrowed from the store configuration. */
	probe->ca_cert_der.data = nullptr;
	probe->ca_cert_der.length = 0;
	probe->ocsp_signer_cert_der.data = nullptr;
	probe->ocsp_signer_cert_der.length = 0;
	ca_free(probe);
}

static void _cli_ca_config_keys(const store_ca_config_t *config,
				cli_hsm_key_t *ca_key,
				cli_hsm_key_t *signer_key)
{
	const char *signer_provider =
		config->ocsp_signer_hsm_provider != nullptr
			&& config->ocsp_signer_hsm_provider[0] != '\0'
			? config->ocsp_signer_hsm_provider
			: config->hsm_provider;

	*ca_key = (cli_hsm_key_t){
		.hsm_provider = config->hsm_provider,
		.token_label = config->token_label,
		.pin = config->pin,
		.key_label = config->key_label,
	};
	*signer_key = (cli_hsm_key_t){
		.hsm_provider = signer_provider,
		.token_label = config->ocsp_signer_token_label,
		.pin = config->ocsp_signer_pin,
		.key_label = config->ocsp_signer_key_label,
	};
}

/*
 * Check that the CA key matches the CA certificate and that the OCSP signer
 * key matches an authorized signer certificate.  If the signer certificate is
 * no longer usable (for example after a key or CA certificate rotation), a
 * replacement signer certificate is issued and stored in config.
 */
static bool _cli_ca_update_validate(const config_t *app_config,
				    store_ca_config_t *config,
				    bool force_reissue,
				    bool *reissued)
{
	cli_hsm_key_t ca_key;
	cli_hsm_key_t signer_key;
	ca_t *probe = nullptr;
	X509 *ca_certificate = nullptr;
	X509 *signer_certificate = nullptr;
	ca_t authorization = { 0 };
	cert_digest_algorithm_t digest = CERT_DIGEST_DEFAULT;
	cert_blob_t generated = { 0 };
	bool authorized = false;
	bool ok = false;

	*reissued = false;
	_cli_ca_config_keys(config, &ca_key, &signer_key);

	if (config->ca_cert == nullptr || config->ca_cert_length == 0) {
		fprintf(stderr,
			"anyca_cli: the CA has no stored certificate\n");
		return false;
	}

	probe = _cli_ca_probe_new(config, nullptr, 0);
	if (probe == nullptr) {
		fprintf(stderr,
			"anyca_cli: cannot load the CA certificate; nothing was updated\n");
		return false;
	}
	if (!cli_key_matches_certificate(app_config, &ca_key,
					 probe->certificate, "CA")) {
		fprintf(stderr,
			"anyca_cli: the CA key does not match the CA certificate; nothing was updated\n");
		goto done;
	}
	_cli_ca_probe_free(probe);
	probe = nullptr;

	if (!force_reissue && config->ocsp_signer_cert != nullptr
	    && config->ocsp_signer_cert_length != 0) {
		ca_certificate = ca_certificate_load_der(
			config->ca_cert, config->ca_cert_length);
		signer_certificate = ca_certificate_load_der(
			config->ocsp_signer_cert,
			config->ocsp_signer_cert_length);
		if (ca_certificate != nullptr && signer_certificate != nullptr) {
			authorization.certificate = ca_certificate;
			authorization.ocsp_signer_certificate =
				signer_certificate;
			authorized = ca_ocsp_signer_authorized(&authorization)
				&& cli_key_matches_certificate(
					app_config, &signer_key,
					signer_certificate, "OCSP signer");
			authorization.certificate = nullptr;
			authorization.ocsp_signer_certificate = nullptr;
		}
	}
	if (authorized) {
		ok = true;
		goto done;
	}

	/*
	 * The stored signer certificate does not match the new identity or
	 * key.  Reissue it so a successful update leaves a loadable CA.
	 */
	if (config->ocsp_signer_digest != nullptr
	    && !cli_parse_digest(config->ocsp_signer_digest, &digest)) {
		fprintf(stderr,
			"anyca_cli: the CA has an invalid OCSP signer digest: %s\n",
			config->ocsp_signer_digest);
		goto done;
	}
	if (!cli_generate_ocsp_signer_certificate(
		    app_config, config->name, config->ca_cert,
		    config->ca_cert_length, &ca_key, &signer_key, digest,
		    nullptr, 0, nullptr, 0, &generated)) {
		fprintf(stderr,
			"anyca_cli: cannot reissue the OCSP signing certificate; nothing was updated\n");
		goto done;
	}

	probe = _cli_ca_probe_new(config, generated.data, generated.length);
	if (probe == nullptr) {
		fprintf(stderr,
			"anyca_cli: the reissued OCSP signing certificate is not authorized by the CA; nothing was updated\n");
		goto done;
	}
	if (!cli_key_matches_certificate(app_config, &signer_key,
					 probe->ocsp_signer_certificate,
					 "OCSP signer")) {
		fprintf(stderr,
			"anyca_cli: the OCSP signer key does not match the reissued certificate; nothing was updated\n");
		goto done;
	}

	osal_free(config->ocsp_signer_cert);
	config->ocsp_signer_cert = generated.data;
	config->ocsp_signer_cert_length = generated.length;
	generated.data = nullptr;
	generated.length = 0;
	*reissued = true;
	ok = true;

done:
	_cli_ca_probe_free(probe);
	ca_certificate_free(ca_certificate);
	ca_certificate_free(signer_certificate);
	cert_blob_free(&generated);
	return ok;
}

/* Validate the options shared by ca create and ca import. */
static bool _cli_ca_validate(const cli_ca_options_t *options,
			     cert_digest_algorithm_t *digest)
{
	if (!ca_name_is_valid(options->name)) {
		fprintf(stderr, "anyca_cli: invalid CA name: %s\n",
			options->name);
		return false;
	}
	if (!ca_ocsp_responder_endpoint_is_valid(
		    options->ocsp_responder_endpoint)) {
		fprintf(stderr,
			"anyca_cli: invalid --ocsp-responder-endpoint: %s\n",
			options->ocsp_responder_endpoint != nullptr
				? options->ocsp_responder_endpoint
				: "<empty>");
		return false;
	}
	if (options->ocsp_signer_hash_algorithm != nullptr
	    && !cli_parse_digest(options->ocsp_signer_hash_algorithm, digest)) {
		fprintf(stderr, "anyca_cli: invalid --ocsp-signer-hash-algorithm: %s\n",
			options->ocsp_signer_hash_algorithm);
		return false;
	}
	return true;
}

/* Build CN=<name> with RFC 4514 escaping for the characters that matter. */
static char *_cli_default_ca_subject(const char *name)
{
	static const char special[] = ",+\"\\<>;=";
	size_t extra = 0;
	size_t name_length = strlen(name);
	char *subject;
	char *out;

	for (size_t i = 0; i < name_length; i++) {
		if (strchr(special, name[i]) != nullptr)
			extra++;
	}
	subject = osal_malloc(sizeof "CN=" + name_length + extra);
	if (subject == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return nullptr;
	}
	memcpy(subject, "CN=", 3);
	out = subject + 3;
	for (size_t i = 0; i < name_length; i++) {
		if (strchr(special, name[i]) != nullptr)
			*out++ = '\\';
		*out++ = name[i];
	}
	*out = '\0';
	return subject;
}

/* Replace a provider/token/PIN/key-label group with the values in key. */
static bool _cli_replace_key_fields(char **provider, char **token_label,
				    char **pin, char **key_label,
				    const cli_hsm_key_t *key)
{
	return _cli_replace_string(provider, key->hsm_provider)
		&& _cli_replace_string(token_label, key->token_label)
		&& _cli_replace_secure_string(pin, key->pin)
		&& _cli_replace_string(key_label, key->key_label);
}

static bool _cli_replace_key(store_ca_config_t *config,
			     const cli_hsm_key_t *key)
{
	return _cli_replace_key_fields(&config->hsm_provider,
				       &config->token_label, &config->pin,
				       &config->key_label, key);
}

static bool _cli_parse_uri_for_ca(const config_t *config, const char *uri,
				  cli_hsm_uri_t *parsed, const char *option)
{
	if (!cli_hsm_uri_parse(uri, parsed))
		return false;
	if (!cli_hsm_uri_resolve_provider(config, parsed, option)) {
		cli_hsm_uri_free(parsed);
		return false;
	}
	return true;
}

/*
 * Write a complete CA configuration and register the CA identity.
 *
 * The certificate buffers are always consumed.  On failure nothing is left
 * in the store.
 */
static bool _cli_ca_store(const config_t *app_config,
			  const cli_ca_options_t *options,
			  const cli_hsm_key_t *ca_key,
			  const cli_hsm_key_t *signer_key,
			  unsigned char *ca_cert, size_t ca_cert_length,
			  unsigned char *ocsp_cert, size_t ocsp_cert_length,
			  cert_digest_algorithm_t digest)
{
	store_ca_config_t config = { 0 };
	store_ca_id_t store_id = 0;
	ca_t *probe = nullptr;
	store_result_t result;
	bool added = false;
	bool ok = false;

	config.ca_cert = ca_cert;
	config.ca_cert_length = ca_cert_length;
	config.ocsp_signer_cert = ocsp_cert;
	config.ocsp_signer_cert_length = ocsp_cert_length;

	if (!_cli_replace_string(&config.name, options->name)
	    || !_cli_replace_key(&config, ca_key)
	    || !_cli_replace_key_fields(&config.ocsp_signer_hsm_provider,
					&config.ocsp_signer_token_label,
					&config.ocsp_signer_pin,
					&config.ocsp_signer_key_label,
					signer_key)
	    || !_cli_replace_string(&config.ocsp_signer_digest,
				cli_digest_name(digest))
	    || !_cli_replace_string(&config.ocsp_responder_endpoint,
				options->ocsp_responder_endpoint))
		goto done;

	config.crl_publish_period_min = CLI_DEFAULT_CRL_PUBLISH_PERIOD_MIN;
	if (options->crl_publish_period_min != nullptr
	    && !cli_parse_uint32(options->crl_publish_period_min,
				 &config.crl_publish_period_min)) {
		fprintf(stderr,
			"anyca_cli: invalid --crl-publish-period-min: %s\n",
			options->crl_publish_period_min);
		goto done;
	}
	config.ocsp_update_period_min = CLI_DEFAULT_OCSP_UPDATE_PERIOD_MIN;
	if (options->ocsp_update_period_min != nullptr
	    && !cli_parse_uint32(options->ocsp_update_period_min,
				 &config.ocsp_update_period_min)) {
		fprintf(stderr,
			"anyca_cli: invalid --ocsp-update-period-min: %s\n",
			options->ocsp_update_period_min);
		goto done;
	}

	result = store_ca_config_add(&config);
	if (result == STORE_ERR_DUPLICATE) {
		fprintf(stderr,
			"anyca_cli: CA name or OCSP responder endpoint is already in use; delete the existing CA first\n");
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot add the CA configuration\n");
		goto done;
	}
	added = true;

	probe = ca_new();
	if (probe == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		goto done;
	}
	if (!_cli_replace_string(&probe->name, config.name))
		goto done;

	/* The probe takes ownership; config no longer frees these buffers. */
	probe->ca_cert_der.data = config.ca_cert;
	probe->ca_cert_der.length = config.ca_cert_length;
	config.ca_cert = nullptr;
	config.ca_cert_length = 0;
	probe->ocsp_signer_cert_der.data = config.ocsp_signer_cert;
	probe->ocsp_signer_cert_der.length = config.ocsp_signer_cert_length;
	config.ocsp_signer_cert = nullptr;
	config.ocsp_signer_cert_length = 0;

	if (!ca_load_certificate(probe)) {
		fprintf(stderr, "anyca_cli: cannot load CA certificate: %s\n",
			options->name);
		goto done;
	}
	if (!cli_key_matches_certificate(app_config, ca_key,
					 probe->certificate, "CA")
	    || !cli_key_matches_certificate(app_config, signer_key,
					    probe->ocsp_signer_certificate,
					    "OCSP signer")) {
		fprintf(stderr,
			"anyca_cli: the HSM key does not match the certificate for CA %s\n",
			options->name);
		goto done;
	}
	if (store_ca_register(probe->name, probe->spki_hash_sha256.data,
			      probe->spki_hash_sha256.length,
			      &store_id) != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot register CA %s in the store\n",
			probe->name);
		goto done;
	}
	{
		store_certificate_t record;
		unsigned char *serial = nullptr;
		size_t serial_length = 0;
		int64_t not_after = 0;

		if (!ca_certificate_serial(probe->ocsp_signer_certificate,
					   &serial, &serial_length)
		    || !ca_certificate_not_after(
			    probe->ocsp_signer_certificate, &not_after)) {
			fprintf(stderr,
				"anyca_cli: cannot read the generated OCSP signing certificate\n");
			osal_free(serial);
			goto done;
		}
		record.serial = serial;
		record.serial_length = serial_length;
		record.not_after = not_after;
		result = store_certificate_add(store_id, &record);
		osal_free(serial);
		if (result != STORE_OK && result != STORE_ERR_DUPLICATE) {
			fprintf(stderr,
				"anyca_cli: cannot record the generated OCSP signing certificate\n");
			goto done;
		}
	}

	ok = true;

done:
	if (!ok && added) {
		if (store_ca_config_delete(options->name) != STORE_OK)
			fprintf(stderr,
				"anyca_cli: warning: cannot roll back the CA configuration\n");
	}
	ca_free(probe);
	store_ca_config_free(&config);
	return ok;
}

static int _cli_ca_import(cli_global_options_t *global,
			  const cli_ca_options_t *options)
{
	cli_context_t context;
	cli_hsm_uri_t ca_uri = { 0 };
	cli_hsm_uri_t signer_uri = { 0 };
	cert_blob_t generated = { 0 };
	cert_digest_algorithm_t digest = CERT_DIGEST_DEFAULT;
	unsigned char *ca_cert = nullptr;
	size_t ca_cert_length = 0;
	unsigned char *ocsp_cert = nullptr;
	size_t ocsp_cert_length = 0;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->name, "--name")
	    || !cli_require_option(options->key_uri, "--key-uri")
	    || !cli_require_option(options->ca_cert_path, "--in")
	    || !cli_require_option(options->ocsp_key_uri, "--ocsp-key-uri")
	    || !cli_require_option(options->ocsp_responder_endpoint,
				   "--ocsp-responder-endpoint"))
		return EXIT_FAILURE;
	if (!_cli_ca_validate(options, &digest))
		return EXIT_FAILURE;

	if (!cli_context_init(global->config_path, &context, false))
		return EXIT_FAILURE;
	if (!_cli_ca_config_available(options->name,
				      options->ocsp_responder_endpoint))
		goto done;
	if (!_cli_parse_uri_for_ca(context.config, options->key_uri, &ca_uri,
				   "--key-uri")
	    || !_cli_parse_uri_for_ca(context.config, options->ocsp_key_uri,
				      &signer_uri, "--ocsp-key-uri"))
		goto done;

	if (!_cli_read_certificate(options->ca_cert_path, &ca_cert,
				   &ca_cert_length, "CA certificate"))
		goto done;

	if (!cli_generate_ocsp_signer_certificate(
		    context.config, options->name, ca_cert, ca_cert_length,
		    &ca_uri.key, &signer_uri.key, digest, nullptr, 0, nullptr,
		    0, &generated)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the OCSP signing certificate for CA %s\n",
			options->name);
		goto done;
	}
	ocsp_cert = generated.data;
	ocsp_cert_length = generated.length;
	generated.data = nullptr;
	generated.length = 0;

	{
		bool stored = _cli_ca_store(context.config, options,
					    &ca_uri.key, &signer_uri.key,
					    ca_cert, ca_cert_length,
					    ocsp_cert, ocsp_cert_length, digest);

		/* The store helper always consumes both certificate buffers. */
		ca_cert = nullptr;
		ocsp_cert = nullptr;
		if (!stored)
			goto done;
	}

	printf("Imported CA: %s\n", options->name);
	status = EXIT_SUCCESS;

done:
	osal_free(ca_cert);
	osal_free(ocsp_cert);
	cert_blob_free(&generated);
	cli_hsm_uri_free(&signer_uri);
	cli_hsm_uri_free(&ca_uri);
	cli_context_fini(&context);
	return status;
}

static int _cli_ca_create(cli_global_options_t *global,
		       const cli_ca_options_t *options)
{
	cli_context_t context;
	cli_hsm_uri_t ca_uri = { 0 };
	cli_hsm_uri_t signer_uri = { 0 };
	cli_cert_options_t cert_options = { 0 };
	cert_blob_t ca_certificate = { 0 };
	cert_blob_t ocsp_certificate = { 0 };
	char *default_subject = nullptr;
	const char *subject;
	const char *certificate_usage;
	const char *key_type;
	const char *ec_curve;
	unsigned int rsa_bits = 3072;
	cert_digest_algorithm_t digest = CERT_DIGEST_DEFAULT;
	bool ca_key_generated = false;
	bool signer_key_generated = false;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->name, "--name")
	    || !cli_require_option(options->key_uri, "--key-uri")
	    || !cli_require_option(options->ocsp_key_uri, "--ocsp-key-uri")
	    || !cli_require_option(options->ocsp_responder_endpoint,
				   "--ocsp-responder-endpoint"))
		return EXIT_FAILURE;
	if (!_cli_ca_validate(options, &digest))
		return EXIT_FAILURE;

	key_type = options->key_type != nullptr ? options->key_type : "rsa";
	ec_curve = options->ec_curve != nullptr ? options->ec_curve : "p384";
	if (options->rsa_bits != nullptr) {
		uint32_t bits;

		if (!cli_parse_uint32(options->rsa_bits, &bits)
		    || bits < 2048 || bits > 16384) {
			fprintf(stderr,
				"anyca_cli: invalid --rsa-bits: %s (2048..16384)\n",
				options->rsa_bits);
			return EXIT_FAILURE;
		}
		rsa_bits = bits;
	}
	certificate_usage = options->certificate_usage != nullptr
		? options->certificate_usage
		: "ca";

	if (!cli_context_init(global->config_path, &context, false))
		return EXIT_FAILURE;
	if (!_cli_ca_config_available(options->name,
				      options->ocsp_responder_endpoint))
		goto done;
	if (!_cli_parse_uri_for_ca(context.config, options->key_uri, &ca_uri,
				   "--key-uri")
	    || !_cli_parse_uri_for_ca(context.config, options->ocsp_key_uri,
				      &signer_uri, "--ocsp-key-uri"))
		goto done;

	subject = options->subject;
	if (subject == nullptr || subject[0] == '\0') {
		default_subject = _cli_default_ca_subject(options->name);
		if (default_subject == nullptr)
			goto done;
		subject = default_subject;
	}

	if (!cli_generate_key_pair(context.config, &ca_uri.key, key_type,
				   rsa_bits, ec_curve)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the CA key pair in the token\n");
		goto done;
	}
	ca_key_generated = true;

	if (!cli_generate_key_pair(context.config, &signer_uri.key, key_type,
				   rsa_bits, ec_curve)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the OCSP signer key pair in the token\n");
		goto done;
	}
	signer_key_generated = true;

	cert_options.issuer_key = ca_uri.key;
	cert_options.subject_key = ca_uri.key;
	cert_options.subject = subject;
	cert_options.certificate_usage = certificate_usage;
	cert_options.digest = digest;
	cert_options.is_ca = true;
	cert_options.validity_days = CLI_DEFAULT_VALIDITY_DAYS;
	if (!cli_generate_certificate(context.config, &cert_options,
				      &ca_certificate)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the CA certificate\n");
		goto done;
	}

	if (!cli_generate_ocsp_signer_certificate(
		    context.config, options->name, ca_certificate.data,
		    ca_certificate.length, &ca_uri.key, &signer_uri.key, digest,
		    nullptr, 0, nullptr, 0, &ocsp_certificate)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the OCSP signing certificate for CA %s\n",
			options->name);
		goto done;
	}

	{
		bool stored = _cli_ca_store(
			context.config, options, &ca_uri.key, &signer_uri.key,
			ca_certificate.data, ca_certificate.length,
			ocsp_certificate.data, ocsp_certificate.length, digest);

		/* The store helper always consumes both certificate buffers. */
		ca_certificate.data = nullptr;
		ca_certificate.length = 0;
		ocsp_certificate.data = nullptr;
		ocsp_certificate.length = 0;
		if (!stored)
			goto done;
	}

	printf("Created CA: %s\n", options->name);
	status = EXIT_SUCCESS;

done:
	if (status != EXIT_SUCCESS) {
		_cli_delete_generated_key(context.config, &signer_uri.key,
					  signer_key_generated,
					  "OCSP signer");
		_cli_delete_generated_key(context.config, &ca_uri.key,
					  ca_key_generated, "CA");
	}
	osal_free(default_subject);
	cert_blob_free(&ocsp_certificate);
	cert_blob_free(&ca_certificate);
	cli_hsm_uri_free(&signer_uri);
	cli_hsm_uri_free(&ca_uri);
	cli_context_fini(&context);
	return status;
}

static unsigned
_cli_update_option_count(const cli_ca_options_t *options)
{
	return (options->key_uri != nullptr)
		+ (options->ca_cert_path != nullptr)
		+ (options->ocsp_key_uri != nullptr)
		+ (options->ocsp_signer_hash_algorithm != nullptr)
		+ (options->crl_publish_period_min != nullptr)
		+ (options->ocsp_update_period_min != nullptr)
		+ (options->ocsp_responder_endpoint != nullptr);
}

static int _cli_ca_update(cli_global_options_t *global,
			  const cli_ca_options_t *options)
{
	cli_context_t context;
	cli_hsm_uri_t ca_uri = { 0 };
	cli_hsm_uri_t signer_uri = { 0 };
	store_ca_config_t config = { 0 };
	cli_certificate_record_t recorded = { 0 };
	store_result_t result;
	char *ca_name = nullptr;
	unsigned changes;
	bool identity_changed;
	bool signer_reissued = false;
	int status = EXIT_FAILURE;

	changes = _cli_update_option_count(options);
	if (changes == 0) {
		fprintf(stderr,
			"anyca_cli: ca update requires at least one field option\n");
		return EXIT_FAILURE;
	}

	if (!cli_context_init(global->config_path, &context, false))
		return EXIT_FAILURE;
	if (!cli_ca_selection_resolve(options->ca_name, options->ca_id, false,
				      &ca_name))
		goto done;

	result = store_ca_config_get(ca_name, &config);
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr, "anyca_cli: unknown CA: %s\n", ca_name);
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: cannot read the CA configuration: %s\n",
			ca_name);
		goto done;
	}

	if (options->key_uri != nullptr) {
		if (!_cli_parse_uri_for_ca(context.config, options->key_uri,
					   &ca_uri, "--key-uri"))
			goto done;
		if (!_cli_replace_key(&config, &ca_uri.key))
			goto done;
	}
	if (options->ocsp_key_uri != nullptr) {
		if (!_cli_parse_uri_for_ca(context.config,
					   options->ocsp_key_uri, &signer_uri,
					   "--ocsp-key-uri"))
			goto done;
		if (!_cli_replace_key_fields(&config.ocsp_signer_hsm_provider,
					     &config.ocsp_signer_token_label,
					     &config.ocsp_signer_pin,
					     &config.ocsp_signer_key_label,
					     &signer_uri.key))
			goto done;
	}
	if (options->ca_cert_path != nullptr
	    && !_cli_replace_certificate(options->ca_cert_path, &config.ca_cert,
					 &config.ca_cert_length,
					 "CA certificate"))
		goto done;
	if (options->ocsp_signer_hash_algorithm != nullptr) {
		cert_digest_algorithm_t digest;

		if (!cli_parse_digest(options->ocsp_signer_hash_algorithm, &digest)) {
			fprintf(stderr, "anyca_cli: invalid --ocsp-signer-hash-algorithm: %s\n",
				options->ocsp_signer_hash_algorithm);
			goto done;
		}
		if (!_cli_replace_string(&config.ocsp_signer_digest,
					 cli_digest_name(digest)))
			goto done;
	}
	if (options->crl_publish_period_min != nullptr
	    && !cli_parse_uint32(options->crl_publish_period_min,
				 &config.crl_publish_period_min)) {
		fprintf(stderr,
			"anyca_cli: invalid --crl-publish-period-min: %s\n",
			options->crl_publish_period_min);
		goto done;
	}
	if (options->ocsp_update_period_min != nullptr
	    && !cli_parse_uint32(options->ocsp_update_period_min,
				 &config.ocsp_update_period_min)) {
		fprintf(stderr,
			"anyca_cli: invalid --ocsp-update-period-min: %s\n",
			options->ocsp_update_period_min);
		goto done;
	}
	if (options->ocsp_responder_endpoint != nullptr) {
		if (!ca_ocsp_responder_endpoint_is_valid(
			    options->ocsp_responder_endpoint)) {
			fprintf(stderr,
				"anyca_cli: invalid --ocsp-responder-endpoint: %s\n",
				options->ocsp_responder_endpoint);
			goto done;
		}
		if (!_cli_replace_string(&config.ocsp_responder_endpoint,
					 options->ocsp_responder_endpoint))
			goto done;
	}

	/*
	 * Validate every identity-affecting change before touching the store:
	 * a key that does not match its certificate would make the server skip
	 * the CA while the command still reported success.
	 */
	identity_changed = options->key_uri != nullptr
		|| options->ca_cert_path != nullptr
		|| options->ocsp_key_uri != nullptr;
	if (identity_changed
	    && !_cli_ca_update_validate(
		    context.config, &config,
		    options->ocsp_key_uri != nullptr, &signer_reissued))
		goto done;

	/* Record before publishing the new configuration, so a failure cannot
	 * leave the store pointing at an unrecorded certificate. */
	if (signer_reissued
	    && !cli_record_issued_certificate(
		    config.name, config.ca_cert, config.ca_cert_length,
		    config.ocsp_signer_cert, config.ocsp_signer_cert_length,
		    &recorded)) {
		fprintf(stderr,
			"anyca_cli: cannot record the reissued OCSP signing certificate; nothing was updated\n");
		goto done;
	}

	result = store_ca_config_update(&config);
	if (result != STORE_OK && recorded.created
	    && store_certificate_delete(recorded.ca_id, recorded.serial,
					recorded.serial_length) != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: warning: cannot remove the certificate record left by the failed update\n");
	}
	if (result == STORE_ERR_DUPLICATE) {
		fprintf(stderr,
			"anyca_cli: OCSP responder endpoint is already in use\n");
		goto done;
	}
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr, "anyca_cli: unknown CA: %s\n", config.name);
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot update the CA configuration\n");
		goto done;
	}

	printf("Updated CA %s: %u field(s)%s (applied on the next OCSP response "
	       "or CRL check)\n", config.name, changes,
	       signer_reissued
		       ? "; OCSP signing certificate reissued"
		       : "");
	status = EXIT_SUCCESS;

done:
	osal_free(recorded.serial);
	osal_free(ca_name);
	cli_hsm_uri_free(&signer_uri);
	cli_hsm_uri_free(&ca_uri);
	store_ca_config_free(&config);
	cli_context_fini(&context);
	return status;
}

static int _cli_ca_delete(cli_global_options_t *global,
			  const cli_ca_options_t *options)
{
	cli_context_t context;
	store_result_t result;
	char *ca_name = nullptr;
	int status = EXIT_FAILURE;

	if (!cli_context_init(global->config_path, &context, false))
		return EXIT_FAILURE;
	if (!cli_ca_selection_resolve(options->ca_name, options->ca_id, false,
				      &ca_name))
		goto done;

	result = store_ca_config_delete(ca_name);
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr, "anyca_cli: unknown CA: %s\n", ca_name);
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: cannot delete the CA configuration: %s\n",
			ca_name);
		goto done;
	}

	printf("Deleted CA configuration: %s "
	       "(stored certificate records are kept)\n",
	       ca_name);
	status = EXIT_SUCCESS;

done:
	osal_free(ca_name);
	cli_context_fini(&context);
	return status;
}

static const store_ca_record_t *
_cli_latest_ca_record(const store_ca_record_t *records, size_t count,
		      const char *name)
{
	const store_ca_record_t *latest = nullptr;

	for (size_t i = 0; i < count; i++) {
		if (records[i].name == nullptr || name == nullptr
		    || strcmp(records[i].name, name) != 0)
			continue;
		if (latest == nullptr || records[i].id > latest->id)
			latest = &records[i];
	}
	return latest;
}

static int _cli_ca_list(cli_global_options_t *global)
{
	cli_context_t context;
	store_ca_config_t *configs = nullptr;
	store_ca_record_t *records = nullptr;
	size_t count = 0;
	size_t record_count = 0;
	int status = EXIT_FAILURE;

	if (!cli_context_init(global->config_path, &context, false))
		return EXIT_FAILURE;

	if (store_ca_config_list(&configs, &count) != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot list CA configurations\n");
		goto done;
	}
	if (store_ca_list(&records, &record_count) != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot list CAs\n");
		goto done;
	}

	for (size_t i = 0; i < count; i++) {
		const store_ca_config_t *entry = &configs[i];
		const store_ca_record_t *record =
			_cli_latest_ca_record(records, record_count, entry->name);
		const char *signer_provider =
			entry->ocsp_signer_hsm_provider != nullptr
				&& entry->ocsp_signer_hsm_provider[0] != '\0'
				? entry->ocsp_signer_hsm_provider
				: entry->hsm_provider;
		char *hash_text = nullptr;

		if (i != 0)
			fputc('\n', stdout);
		printf("CA %s", entry->name != nullptr ? entry->name : "<unset>");
		if (record != nullptr)
			printf(" (id %" PRId64 ")", record->id);
		else
			printf(" (not registered)");
		fputc('\n', stdout);

		printf("  key: %s/%s/%s\n",
		       entry->hsm_provider != nullptr ? entry->hsm_provider
						      : "<unset>",
		       entry->token_label != nullptr ? entry->token_label
						     : "<unset>",
		       entry->key_label != nullptr ? entry->key_label
						   : "<unset>");
		printf("  OCSP signer: %s/%s/%s\n",
		       signer_provider != nullptr ? signer_provider : "<unset>",
		       entry->ocsp_signer_token_label != nullptr
			       ? entry->ocsp_signer_token_label
			       : "<unset>",
		       entry->ocsp_signer_key_label != nullptr
			       ? entry->ocsp_signer_key_label
			       : "<unset>");
		printf("  OCSP digest: %s\n",
		       entry->ocsp_signer_digest != nullptr
			       ? entry->ocsp_signer_digest
			       : "<unset>");
		printf("  endpoint: %s\n",
		       entry->ocsp_responder_endpoint != nullptr
			       ? entry->ocsp_responder_endpoint
			       : "<unset>");
		printf("  periods: CRL %u min, OCSP %u min, CRL number %" PRIu64
		       "\n",
		       entry->crl_publish_period_min,
		       entry->ocsp_update_period_min, entry->crl_number);
		if (record != nullptr) {
			hash_text = cli_bytes_to_hex(record->key_hash,
						     record->key_hash_length);
			printf("  key hash: %s\n",
			       hash_text != nullptr ? hash_text
						    : "<out of memory>");
			osal_free(hash_text);
		}
	}
	if (count == 0)
		printf("No CA configurations.\n");
	status = EXIT_SUCCESS;

done:
	store_ca_list_free(records, record_count);
	store_ca_config_list_free(configs, count);
	cli_context_fini(&context);
	return status;
}

static int _cli_publish_crls(cli_global_options_t *global,
			    const cli_ca_options_t *options, bool single)
{
	config_t *config = nullptr;
	unsigned published = 0;
	unsigned failed = 0;
	bool found = false;
	char *ca_name = nullptr;
	const char *command = single ? "ca publish-crl" : "crl publish";
	int status = EXIT_FAILURE;

	if (options->all
	    && (options->ca_name != nullptr || options->ca_id != nullptr)) {
		fprintf(stderr,
			"anyca_cli: --all cannot be combined with --ca-name or --ca-id\n");
		return EXIT_FAILURE;
	}
	if (!options->all && options->ca_name == nullptr
	    && options->ca_id == nullptr) {
		fprintf(stderr,
			"anyca_cli: %s requires %s\n", command,
			single ? "--ca-name or --ca-id"
			       : "--ca-name, --ca-id or --all");
		return EXIT_FAILURE;
	}
	if (options->ca_name != nullptr && options->ca_id != nullptr) {
		fprintf(stderr,
			"anyca_cli: --ca-name and --ca-id are mutually exclusive\n");
		return EXIT_FAILURE;
	}
	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	if (config->crl_publish_path == nullptr
	    || config->crl_publish_path[0] == '\0') {
		fprintf(stderr, "anyca_cli: crl_publish_path is not configured\n");
		goto done;
	}
	if (!core_init(config)) {
		fprintf(stderr, "anyca_cli: cannot initialize the core\n");
		goto done;
	}
	if (!options->all
	    && !cli_ca_selection_resolve(options->ca_name, options->ca_id,
					 false, &ca_name)) {
		core_fini();
		goto done;
	}

	for (unsigned i = 0; i < core_ca_count(); i++) {
		ca_t *ca = core_ca_at(i);

		if (ca == nullptr)
			continue;
		if (!options->all && strcmp(ca->name, ca_name) != 0)
			continue;
		found = true;
		if (core_publish_crl(ca)) {
			printf("Published CRL: %s\n", ca->name);
			published++;
		} else {
			failed++;
		}
	}
	if (!found) {
		if (options->all)
			fprintf(stderr,
				"anyca_cli: no available CA configurations\n");
		else
			fprintf(stderr,
				"anyca_cli: unknown or unavailable CA: %s\n",
				ca_name);
	} else if (failed != 0) {
		fprintf(stderr, "anyca_cli: %u CRL(s) failed\n", failed);
	} else {
		printf("Published %u CRL(s)\n", published);
		status = EXIT_SUCCESS;
	}

	core_fini();

done:
	osal_free(ca_name);
	config_free(config);
	return status;
}

typedef struct cli_ca_ocsp_options {
	const char *ca_name;
	const char *ca_id;
	const char *ocsp_signer_hash_algorithm;
	const char *subject;
	const char *validity_days;
	const char *serial;
	const char *out_path;
} cli_ca_ocsp_options_t;

static int _cli_ca_ocsp_renew(cli_global_options_t *global,
			      const cli_ca_ocsp_options_t *options)
{
	cli_context_t context;
	store_ca_config_t ca_config = { 0 };
	cert_blob_t certificate = { 0 };
	unsigned char *serial = nullptr;
	size_t serial_length = 0;
	uint32_t validity_days = CLI_DEFAULT_VALIDITY_DAYS;
	cert_digest_algorithm_t digest = CERT_DIGEST_DEFAULT;
	bool digest_given = options->ocsp_signer_hash_algorithm != nullptr;
	store_result_t result;
	char *ca_name = nullptr;
	int status = EXIT_FAILURE;

	if (options->validity_days != nullptr
	    && !cli_parse_validity_days(options->validity_days,
					&validity_days)) {
		fprintf(stderr, "anyca_cli: invalid --days: %s\n",
			options->validity_days);
		return EXIT_FAILURE;
	}
	if (options->serial != nullptr
	    && !cli_parse_serial(options->serial, &serial, &serial_length)) {
		fprintf(stderr, "anyca_cli: invalid --serial: %s\n",
			options->serial);
		return EXIT_FAILURE;
	}
	if (digest_given
	    && !cli_parse_digest(options->ocsp_signer_hash_algorithm, &digest)) {
		fprintf(stderr, "anyca_cli: invalid --ocsp-signer-hash-algorithm: %s\n",
			options->ocsp_signer_hash_algorithm);
		return EXIT_FAILURE;
	}

	if (!cli_context_init(global->config_path, &context, false))
		goto done;
	if (!cli_ca_selection_resolve(options->ca_name, options->ca_id, false,
				      &ca_name))
		goto done;

	result = store_ca_config_get(ca_name, &ca_config);
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr, "anyca_cli: unknown issuer CA: %s\n", ca_name);
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot load issuer CA configuration: %s\n",
			ca_name);
		goto done;
	}
	if (ca_config.name == nullptr || ca_config.hsm_provider == nullptr
	    || ca_config.token_label == nullptr || ca_config.pin == nullptr
	    || ca_config.key_label == nullptr || ca_config.ca_cert == nullptr
	    || ca_config.ca_cert_length == 0
	    || ca_config.ocsp_signer_token_label == nullptr
	    || ca_config.ocsp_signer_pin == nullptr
	    || ca_config.ocsp_signer_key_label == nullptr) {
		fprintf(stderr,
			"anyca_cli: issuer CA %s has an incomplete configuration\n",
			ca_name);
		goto done;
	}
	if (!digest_given
	    && !cli_parse_digest(ca_config.ocsp_signer_digest, &digest)) {
		fprintf(stderr,
			"anyca_cli: CA %s has an invalid OCSP signer digest: %s\n",
			ca_config.name,
			ca_config.ocsp_signer_digest != nullptr
				? ca_config.ocsp_signer_digest
				: "<unset>");
		goto done;
	}

	const char *signer_provider =
		ca_config.ocsp_signer_hsm_provider != nullptr
			&& ca_config.ocsp_signer_hsm_provider[0] != '\0'
			? ca_config.ocsp_signer_hsm_provider
			: ca_config.hsm_provider;
	const cli_hsm_key_t issuer_key = {
		.hsm_provider = ca_config.hsm_provider,
		.token_label = ca_config.token_label,
		.pin = ca_config.pin,
		.key_label = ca_config.key_label,
	};
	const cli_hsm_key_t signer_key = {
		.hsm_provider = signer_provider,
		.token_label = ca_config.ocsp_signer_token_label,
		.pin = ca_config.ocsp_signer_pin,
		.key_label = ca_config.ocsp_signer_key_label,
	};

	if (!cli_generate_ocsp_signer_certificate(
		    context.config, ca_config.name, ca_config.ca_cert,
		    ca_config.ca_cert_length, &issuer_key, &signer_key, digest,
		    options->subject, validity_days, serial, serial_length,
		    &certificate)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the OCSP signing certificate for CA %s\n",
			ca_config.name);
		goto done;
	}

	osal_free(ca_config.ocsp_signer_cert);
	ca_config.ocsp_signer_cert = certificate.data;
	ca_config.ocsp_signer_cert_length = certificate.length;
	certificate.data = nullptr;
	certificate.length = 0;

	/* Record and store the renewed certificate before publishing a copy:
	 * a failure must not leave an unrecorded certificate in use. */
	if (!cli_record_issued_certificate(ca_config.name, ca_config.ca_cert,
					   ca_config.ca_cert_length,
					   ca_config.ocsp_signer_cert,
					   ca_config.ocsp_signer_cert_length,
					   nullptr))
		goto done;

	/*
	 * Write --out before changing the store: if the output cannot be
	 * written the command must fail without activating the new
	 * certificate.
	 */
	if (options->out_path != nullptr
	    && !cli_write_file(options->out_path,
			       ca_config.ocsp_signer_cert,
			       ca_config.ocsp_signer_cert_length))
		goto done;

	result = store_ca_config_update(&ca_config);
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr, "anyca_cli: unknown issuer CA: %s\n", ca_name);
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot update the CA configuration: %s\n",
			ca_name);
		goto done;
	}

	printf("Renewed OCSP signing certificate for CA %s "
	       "(%zu bytes, stored; used on the next OCSP response)\n",
	       ca_config.name, ca_config.ocsp_signer_cert_length);
	status = EXIT_SUCCESS;

done:
	cert_blob_free(&certificate);
	osal_free(serial);
	store_ca_config_free(&ca_config);
	osal_free(ca_name);
	cli_context_fini(&context);
	return status;
}

#define CLI_CA_ENDPOINT_SPECS \
	CLI_OPTION_SPEC(cli_ca_options_t, crl_publish_period_min, \
			"--crl-publish-period-min"), \
	CLI_OPTION_SPEC(cli_ca_options_t, ocsp_update_period_min, \
			"--ocsp-update-period-min"), \
	CLI_OPTION_SPEC(cli_ca_options_t, ocsp_responder_endpoint, \
			"--ocsp-responder-endpoint"), \
	CLI_OPTION_SPEC(cli_ca_options_t, ocsp_signer_hash_algorithm, \
			"--ocsp-signer-hash-algorithm")

static const cli_option_spec_t _cli_ca_import_specs[] = {
	CLI_OPTION_SPEC(cli_ca_options_t, name, "--name"),
	CLI_OPTION_SPEC(cli_ca_options_t, key_uri, "--key-uri"),
	CLI_OPTION_SPEC(cli_ca_options_t, ca_cert_path, "--in"),
	CLI_OPTION_SPEC(cli_ca_options_t, ocsp_key_uri, "--ocsp-key-uri"),
	CLI_CA_ENDPOINT_SPECS,
};

static const cli_option_spec_t _cli_ca_create_specs[] = {
	CLI_OPTION_SPEC(cli_ca_options_t, name, "--name"),
	CLI_OPTION_SPEC(cli_ca_options_t, key_uri, "--key-uri"),
	CLI_OPTION_SPEC(cli_ca_options_t, ocsp_key_uri, "--ocsp-key-uri"),
	CLI_OPTION_SPEC(cli_ca_options_t, subject, "--subject"),
	CLI_OPTION_SPEC(cli_ca_options_t, certificate_usage,
			"--certificate-usage"),
	CLI_OPTION_SPEC(cli_ca_options_t, key_type, "--key-type"),
	CLI_OPTION_SPEC(cli_ca_options_t, rsa_bits, "--rsa-bits"),
	CLI_OPTION_SPEC(cli_ca_options_t, ec_curve, "--ec-curve"),
	CLI_CA_ENDPOINT_SPECS,
};

static const cli_option_spec_t _cli_ca_update_specs[] = {
	CLI_OPTION_SPEC(cli_ca_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_ca_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC(cli_ca_options_t, key_uri, "--key-uri"),
	CLI_OPTION_SPEC(cli_ca_options_t, ca_cert_path, "--in"),
	CLI_OPTION_SPEC(cli_ca_options_t, ocsp_key_uri, "--ocsp-key-uri"),
	CLI_CA_ENDPOINT_SPECS,
};

static const cli_option_spec_t _cli_ca_publish_crl_specs[] = {
	CLI_OPTION_SPEC(cli_ca_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_ca_options_t, ca_id, "--ca-id"),
};

static const cli_option_spec_t _cli_crl_publish_specs[] = {
	CLI_OPTION_SPEC(cli_ca_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_ca_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC_FLAG(cli_ca_options_t, all, "--all"),
};

static const cli_option_spec_t _cli_ca_delete_specs[] = {
	CLI_OPTION_SPEC(cli_ca_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_ca_options_t, ca_id, "--ca-id"),
};

static const cli_option_spec_t _cli_ca_ocsp_renew_specs[] = {
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, subject, "--subject"),
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, validity_days, "--days"),
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, ocsp_signer_hash_algorithm,
			"--ocsp-signer-hash-algorithm"),
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, serial, "--serial"),
	CLI_OPTION_SPEC(cli_ca_ocsp_options_t, out_path, "--out"),
};

int cli_cmd_ca_import(cli_global_options_t *global, int argc, char **argv,
		      int first)
{
	cli_ca_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_ca_import_specs,
				  CLI_OPTION_COUNT(_cli_ca_import_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_ca_import(global, &options);
}

int cli_cmd_ca_create(cli_global_options_t *global, int argc, char **argv,
		      int first)
{
	cli_ca_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_ca_create_specs,
				  CLI_OPTION_COUNT(_cli_ca_create_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_ca_create(global, &options);
}

int cli_cmd_ca_update(cli_global_options_t *global, int argc, char **argv,
		      int first)
{
	cli_ca_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_ca_update_specs,
				  CLI_OPTION_COUNT(_cli_ca_update_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_ca_update(global, &options);
}

int cli_cmd_ca_delete(cli_global_options_t *global, int argc, char **argv,
		      int first)
{
	cli_ca_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_ca_delete_specs,
				  CLI_OPTION_COUNT(_cli_ca_delete_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_ca_delete(global, &options);
}

int cli_cmd_ca_list(cli_global_options_t *global, int argc, char **argv,
		    int first)
{
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global, nullptr, 0,
				  nullptr);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_ca_list(global);
}

int cli_cmd_ca_publish_crl(cli_global_options_t *global, int argc, char **argv,
			   int first)
{
	cli_ca_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_ca_publish_crl_specs,
				  CLI_OPTION_COUNT(_cli_ca_publish_crl_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_publish_crls(global, &options, true);
}

int cli_cmd_ca_ocsp_renew(cli_global_options_t *global, int argc, char **argv,
			  int first)
{
	cli_ca_ocsp_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_ca_ocsp_renew_specs,
				  CLI_OPTION_COUNT(_cli_ca_ocsp_renew_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_ca_ocsp_renew(global, &options);
}

int cli_cmd_crl_publish(cli_global_options_t *global, int argc, char **argv,
			int first)
{
	cli_ca_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_crl_publish_specs,
				  CLI_OPTION_COUNT(_cli_crl_publish_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_publish_crls(global, &options, false);
}
