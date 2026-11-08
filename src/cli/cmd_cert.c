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
#include <time.h>

#include <anyca/osal/compat.h>
#include <anyca/osal/memory.h>

#include <anyca/ca.h>
#include <anyca/cert.h>
#include <anyca/store.h>

#include "cli.h"

typedef struct cli_cert_target_options {
	const char *ca_name;
	const char *ca_id;
	const char *serial;
	const char *in_path;
	const char *not_after;
	bool add;
	bool delete;
} cli_cert_target_options_t;

typedef struct cli_cert_revoke_options {
	const char *ca_name;
	const char *ca_id;
	const char *serial;
	const char *in_path;
	const char *revoked_at;
	const char *reason;
	bool add;
	bool delete;
} cli_cert_revoke_options_t;

typedef struct cli_cert_list_options {
	const char *ca_name;
	const char *ca_id;
	const char *limit;
	bool revocation;
} cli_cert_list_options_t;

typedef struct cli_cert_issue_options {
	const char *ca_name;
	const char *ca_id;
	const char *in_path;
	bool basic;
	bool enforce;
	const char *is_ca;
	const char *path_length;
	const char *certificate_usage;
	const char *certificate_template;
	const char *certificate_policy;
	const char *digest;
	const char *days;
	const char *serial;
	const char *out_path;
	bool no_aki;
	bool no_ski;
} cli_cert_issue_options_t;

typedef struct cli_cert_root_options {
	const char *subject;
	const char *key_uri;
	const char *certificate_usage;
	const char *certificate_template;
	const char *ca_value;
	const char *path_length;
	const char *validity_days;
	const char *digest;
	const char *serial;
	const char *out_path;
} cli_cert_root_options_t;

typedef struct cli_cert_target {
	cli_ca_t *ca;
	unsigned char *serial;
	size_t serial_length;
	int64_t not_after;
	X509 *certificate;
} cli_cert_target_t;

static cli_ca_t *_cli_find_ca(cli_context_t *context, const char *name)
{
	for (unsigned i = 0; i < context->cas_count; i++) {
		if (context->cas[i].ca->name != nullptr
		    && strcmp(context->cas[i].ca->name, name) == 0)
			return &context->cas[i];
	}
	return nullptr;
}

static cli_ca_t *_cli_find_ca_by_id(cli_context_t *context, store_ca_id_t id)
{
	for (unsigned i = 0; i < context->cas_count; i++) {
		if (context->cas[i].store_id == id)
			return &context->cas[i];
	}
	return nullptr;
}

/* Resolve --ca-name/--ca-id to a configured CA. */
static cli_ca_t *_cli_select_ca(cli_context_t *context, const char *ca_name,
				const char *ca_id)
{
	store_ca_id_t id;
	cli_ca_t *ca;

	if (ca_name != nullptr) {
		ca = _cli_find_ca(context, ca_name);
		if (ca == nullptr)
			fprintf(stderr, "anyca_cli: unknown CA: %s\n", ca_name);
		return ca;
	}
	if (!cli_parse_ca_id(ca_id, &id)) {
		fprintf(stderr, "anyca_cli: invalid --ca-id: %s\n", ca_id);
		return nullptr;
	}
	ca = _cli_find_ca_by_id(context, id);
	if (ca == nullptr)
		fprintf(stderr, "anyca_cli: unknown CA id: %" PRId64 "\n", id);
	return ca;
}

static cli_ca_t *_cli_match_ca(cli_context_t *context, X509 *certificate)
{
	cli_ca_t *match = nullptr;
	unsigned matches = 0;

	for (unsigned i = 0; i < context->cas_count; i++) {
		if (ca_issued_certificate(context->cas[i].ca, certificate)) {
			match = &context->cas[i];
			matches++;
		}
	}

	if (matches == 0) {
		fprintf(stderr,
			"anyca_cli: no configured CA issued this certificate\n");
		return nullptr;
	}
	if (matches > 1) {
		fprintf(stderr,
			"anyca_cli: certificate matches multiple CAs; "
			"use --ca-name or --ca-id:\n");
		for (unsigned i = 0; i < context->cas_count; i++) {
			if (ca_issued_certificate(context->cas[i].ca,
						  certificate))
				fprintf(stderr, "  %s\n",
					context->cas[i].ca->name);
		}
		return nullptr;
	}
	return match;
}

static void _cli_target_fini(cli_cert_target_t *target)
{
	osal_free(target->serial);
	ca_certificate_free(target->certificate);
	memset(target, 0, sizeof *target);
}

static bool _cli_apply_not_after(const char *text, cli_cert_target_t *target)
{
	int64_t value;

	if (text == nullptr)
		return true;
	if (!cli_parse_int64(text, &value) || value < 0) {
		fprintf(stderr, "anyca_cli: invalid --not-after: %s\n", text);
		return false;
	}
	target->not_after = value;
	return true;
}

static bool _cli_target_resolve(cli_context_t *context,
				const char *ca_name, const char *ca_id,
				const char *serial, const char *in_path,
				const char *not_after, cli_cert_target_t *target)
{
	unsigned char *given_serial = nullptr;
	size_t given_serial_length = 0;
	bool resolved = false;

	memset(target, 0, sizeof *target);

	if (ca_name != nullptr && ca_id != nullptr) {
		fprintf(stderr,
			"anyca_cli: --ca-name and --ca-id are mutually exclusive\n");
		goto done;
	}

	if (in_path != nullptr) {
		target->certificate = ca_certificate_load(in_path);
		if (target->certificate == nullptr) {
			fprintf(stderr,
				"anyca_cli: cannot load certificate: %s\n",
				in_path);
			goto done;
		}
		if (!ca_certificate_serial(target->certificate,
					   &target->serial,
					   &target->serial_length)) {
			fprintf(stderr,
				"anyca_cli: cannot read the certificate serial\n");
			goto done;
		}
		if (!ca_certificate_not_after(target->certificate,
					      &target->not_after)) {
			fprintf(stderr,
				"anyca_cli: cannot read the certificate "
				"notAfter; using 0\n");
			target->not_after = 0;
		}

		if (ca_name != nullptr || ca_id != nullptr) {
			target->ca = _cli_select_ca(context, ca_name, ca_id);
			if (target->ca == nullptr)
				goto done;
			if (!ca_issued_certificate(target->ca->ca,
						   target->certificate)) {
				fprintf(stderr,
					"anyca_cli: CA %s did not issue this "
					"certificate\n",
					target->ca->ca->name);
				goto done;
			}
		} else {
			target->ca = _cli_match_ca(context, target->certificate);
			if (target->ca == nullptr)
				goto done;
		}

		if (serial != nullptr) {
			if (!cli_parse_serial(serial, &given_serial,
					      &given_serial_length)) {
				fprintf(stderr,
					"anyca_cli: invalid serial: %s\n",
					serial);
				goto done;
			}
			if (given_serial_length != target->serial_length
			    || memcmp(given_serial, target->serial,
				      target->serial_length) != 0) {
				fprintf(stderr,
					"anyca_cli: --serial does not match the "
					"certificate\n");
				goto done;
			}
		}
	} else {
		if ((ca_name == nullptr && ca_id == nullptr)
		    || serial == nullptr) {
			fprintf(stderr,
				"anyca_cli: --ca-name or --ca-id and --serial "
				"are required without --in\n");
			goto done;
		}
		target->ca = _cli_select_ca(context, ca_name, ca_id);
		if (target->ca == nullptr)
			goto done;
		if (!cli_parse_serial(serial, &target->serial,
				      &target->serial_length)) {
			fprintf(stderr, "anyca_cli: invalid serial: %s\n",
				serial);
			goto done;
		}
	}

	if (!_cli_apply_not_after(not_after, target))
		goto done;
	resolved = true;

done:
	osal_free(given_serial);
	if (!resolved)
		_cli_target_fini(target);
	return resolved;
}

static bool _cli_require_action(const bool add, const bool delete)
{
	if (add == delete) {
		fprintf(stderr,
			"anyca_cli: exactly one of --add or --delete is required\n");
		return false;
	}
	return true;
}

static int _cli_cert_record(cli_global_options_t *global,
			    const cli_cert_target_options_t *options)
{
	cli_context_t context;
	cli_cert_target_t target;
	store_certificate_t certificate;
	store_result_t result;
	char *serial_text;
	int status = EXIT_FAILURE;

	if (!_cli_require_action(options->add, options->delete))
		return EXIT_FAILURE;
	if (options->delete && options->not_after != nullptr) {
		fprintf(stderr,
			"anyca_cli: --not-after is only valid with --add\n");
		return EXIT_FAILURE;
	}

	if (!cli_context_init(global->config_path, &context, true))
		return EXIT_FAILURE;
	if (!_cli_target_resolve(&context, options->ca_name, options->ca_id,
				 options->serial, options->in_path,
				 options->not_after, &target)) {
		cli_context_fini(&context);
		return EXIT_FAILURE;
	}

	serial_text = cli_bytes_to_hex(target.serial, target.serial_length);

	if (options->add) {
		certificate.serial = target.serial;
		certificate.serial_length = target.serial_length;
		certificate.not_after = target.not_after;

		result = store_certificate_add(target.ca->store_id, &certificate);
		if (result == STORE_ERR_DUPLICATE) {
			fprintf(stderr,
				"anyca_cli: certificate is already recorded\n");
			goto done;
		}
		if (result != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot record the certificate\n");
			goto done;
		}

		printf("Recorded certificate: CA %s (id %" PRId64 "), "
		       "serial %s, notAfter %" PRId64 "\n",
		       target.ca->ca->name, target.ca->store_id,
		       serial_text != nullptr ? serial_text : "<out of memory>",
		       target.not_after);
	} else {
		result = store_certificate_delete(target.ca->store_id,
						  target.serial,
						  target.serial_length);
		if (result == STORE_ERR_NOT_FOUND) {
			fprintf(stderr,
				"anyca_cli: certificate record not found\n");
			goto done;
		}
		if (result == STORE_ERR_CONFLICT) {
			fprintf(stderr,
				"anyca_cli: certificate is still revoked; "
				"delete the revocation record first\n");
			goto done;
		}
		if (result != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot delete the certificate record\n");
			goto done;
		}

		printf("Deleted certificate record: CA %s (id %" PRId64 "), "
		       "serial %s\n",
		       target.ca->ca->name, target.ca->store_id,
		       serial_text != nullptr ? serial_text : "<out of memory>");
	}
	status = EXIT_SUCCESS;

done:
	osal_free(serial_text);
	_cli_target_fini(&target);
	cli_context_fini(&context);
	return status;
}

static int _cli_cert_revoke(cli_global_options_t *global,
			    const cli_cert_revoke_options_t *options)
{
	cli_context_t context;
	cli_cert_target_t target;
	store_certificate_t placeholder;
	store_revocation_t revocation;
	store_result_t result;
	int64_t revoked_at;
	int64_t reason_value;
	int reason = 0;
	char *serial_text = nullptr;
	int status = EXIT_FAILURE;

	if (!_cli_require_action(options->add, options->delete))
		return EXIT_FAILURE;
	if (options->delete
	    && (options->revoked_at != nullptr || options->reason != nullptr)) {
		fprintf(stderr,
			"anyca_cli: --revoked-at and --reason are only valid "
			"with --add\n");
		return EXIT_FAILURE;
	}

	if (!cli_context_init(global->config_path, &context, true))
		return EXIT_FAILURE;
	if (!_cli_target_resolve(&context, options->ca_name, options->ca_id,
				 options->serial, options->in_path, nullptr,
				 &target)) {
		cli_context_fini(&context);
		return EXIT_FAILURE;
	}

	serial_text = cli_bytes_to_hex(target.serial, target.serial_length);

	if (options->delete) {
		result = store_revocation_delete(target.ca->store_id,
						 target.serial,
						 target.serial_length);
		if (result == STORE_ERR_NOT_FOUND) {
			fprintf(stderr,
				"anyca_cli: certificate is not revoked\n");
			goto done;
		}
		if (result != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot delete the revocation record\n");
			goto done;
		}

		printf("Deleted revocation record: CA %s (id %" PRId64 "), "
		       "serial %s\n",
		       target.ca->ca->name, target.ca->store_id,
		       serial_text != nullptr ? serial_text : "<out of memory>");
		status = EXIT_SUCCESS;
		goto done;
	}

	revoked_at = (int64_t) time(nullptr);
	if (revoked_at <= 0) {
		fprintf(stderr, "anyca_cli: cannot read the current time\n");
		goto done;
	}
	if (options->revoked_at != nullptr) {
		if (!cli_parse_int64(options->revoked_at, &revoked_at)
		    || revoked_at <= 0) {
			fprintf(stderr, "anyca_cli: invalid --revoked-at: %s\n",
				options->revoked_at);
			goto done;
		}
	}
	if (options->reason != nullptr) {
		if (!cli_parse_int64(options->reason, &reason_value)
		    || reason_value < 0 || reason_value > 10
		    || reason_value == 7) {
			fprintf(stderr, "anyca_cli: invalid --reason: %s\n",
				options->reason);
			goto done;
		}
		reason = (int) reason_value;
	}

	result = store_certificate_exists(target.ca->store_id, target.serial,
					  target.serial_length);
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr,
			"anyca_cli: warning: certificate is not recorded; "
			"adding a placeholder record\n");
		placeholder.serial = target.serial;
		placeholder.serial_length = target.serial_length;
		placeholder.not_after = target.not_after;
		result = store_certificate_add(target.ca->store_id,
					       &placeholder);
		if (result != STORE_OK && result != STORE_ERR_DUPLICATE) {
			fprintf(stderr, "anyca_cli: cannot add the placeholder "
					"record\n");
			goto done;
		}
	} else if (result != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot query the certificate\n");
		goto done;
	}

	revocation.serial = target.serial;
	revocation.serial_length = target.serial_length;
	revocation.revoked_at = revoked_at;
	revocation.reason = reason;
	result = store_revocation_add(target.ca->store_id, &revocation);
	if (result == STORE_ERR_DUPLICATE) {
		fprintf(stderr, "anyca_cli: certificate is already revoked\n");
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot record the revocation\n");
		goto done;
	}

	printf("Revoked certificate: CA %s (id %" PRId64 "), serial %s, "
	       "revokedAt %" PRId64 ", reason %d\n",
	       target.ca->ca->name, target.ca->store_id,
	       serial_text != nullptr ? serial_text : "<out of memory>",
	       revoked_at, reason);
	status = EXIT_SUCCESS;

done:
	osal_free(serial_text);
	_cli_target_fini(&target);
	cli_context_fini(&context);
	return status;
}

static const store_revocation_t *
_cli_find_revocation(const store_revocation_t *revocations, size_t count,
		     const unsigned char *serial, size_t serial_length)
{
	for (size_t i = 0; i < count; i++) {
		if (revocations[i].serial_length == serial_length
		    && memcmp(revocations[i].serial, serial,
			      serial_length) == 0)
			return &revocations[i];
	}
	return nullptr;
}

static int _cli_cert_list(cli_global_options_t *global,
			  const cli_cert_list_options_t *options)
{
	cli_context_t context;
	cli_ca_t *ca;
	int64_t limit = 0;
	int status = EXIT_FAILURE;

	if (options->ca_name == nullptr && options->ca_id == nullptr) {
		fprintf(stderr,
			"anyca_cli: --ca-name or --ca-id is required\n");
		return EXIT_FAILURE;
	}
	if (options->ca_name != nullptr && options->ca_id != nullptr) {
		fprintf(stderr,
			"anyca_cli: --ca-name and --ca-id are mutually exclusive\n");
		return EXIT_FAILURE;
	}
	if (options->limit != nullptr
	    && (!cli_parse_int64(options->limit, &limit) || limit <= 0)) {
		fprintf(stderr, "anyca_cli: invalid --n: %s\n",
			options->limit);
		return EXIT_FAILURE;
	}

	if (!cli_context_init(global->config_path, &context, true))
		return EXIT_FAILURE;
	ca = _cli_select_ca(&context, options->ca_name, options->ca_id);
	if (ca == nullptr)
		goto done;

	if (options->revocation) {
		store_revocation_t *records = nullptr;
		size_t count = 0;

		if (store_revocation_list(ca->store_id, limit, &records,
					  &count) != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot list revocations\n");
			goto done;
		}
		for (size_t i = 0; i < count; i++) {
			char *serial_text = cli_bytes_to_hex(
				records[i].serial, records[i].serial_length);

			printf("Revocation: CA %s (id %" PRId64 "), serial %s, "
			       "revokedAt %" PRId64 ", reason %d\n",
			       ca->ca->name, ca->store_id,
			       serial_text != nullptr ? serial_text
						      : "<out of memory>",
			       records[i].revoked_at, records[i].reason);
			osal_free(serial_text);
		}
		store_revocation_list_free(records, count);
	} else {
		store_certificate_t *records = nullptr;
		store_revocation_t *revocations = nullptr;
		size_t count = 0;
		size_t revocation_count = 0;

		if (store_certificate_list(ca->store_id, limit, &records,
					   &count) != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot list certificates\n");
			goto done;
		}
		if (store_revocation_list(ca->store_id, 0, &revocations,
					  &revocation_count) != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot list revocations\n");
			store_certificate_list_free(records, count);
			goto done;
		}
		for (size_t i = 0; i < count; i++) {
			const store_revocation_t *revocation =
				_cli_find_revocation(revocations,
						     revocation_count,
						     records[i].serial,
						     records[i].serial_length);
			char *serial_text = cli_bytes_to_hex(
				records[i].serial, records[i].serial_length);

			printf("Certificate: CA %s (id %" PRId64 "), serial %s, "
			       "notAfter %" PRId64,
			       ca->ca->name, ca->store_id,
			       serial_text != nullptr ? serial_text
						      : "<out of memory>",
			       records[i].not_after);
			if (revocation != nullptr)
				printf(", revokedAt %" PRId64 ", reason %d",
				       revocation->revoked_at,
				       revocation->reason);
			fputc('\n', stdout);
			osal_free(serial_text);
		}
		store_revocation_list_free(revocations, revocation_count);
		store_certificate_list_free(records, count);
	}
	status = EXIT_SUCCESS;

done:
	cli_context_fini(&context);
	return status;
}

static bool _cli_issue_mode(const cli_cert_issue_options_t *options)
{
	if (options->basic == options->enforce) {
		fprintf(stderr,
			"anyca_cli: exactly one of --basic and --enforce is required\n");
		return false;
	}
	if (!options->basic)
		return true;

	if (options->is_ca == nullptr) {
		fprintf(stderr, "anyca_cli: --is-ca is required with --basic\n");
		return false;
	}
	if (options->certificate_usage == nullptr) {
		fprintf(stderr,
			"anyca_cli: --certificate-usage is required with --basic\n");
		return false;
	}
	return true;
}

static bool _cli_issue_reject_enforce_option(const char *value,
					     const char *option)
{
	if (value == nullptr)
		return true;
	fprintf(stderr, "anyca_cli: %s is only valid with --basic\n", option);
	return false;
}

static int _cli_cert_issue(cli_global_options_t *global,
			   const cli_cert_issue_options_t *options)
{
	cli_context_t context;
	store_ca_config_t ca_config = { 0 };
	cert_request_t *request = nullptr;
	cli_csr_sign_options_t sign = { 0 };
	cert_blob_t certificate = { 0 };
	unsigned char *serial = nullptr;
	size_t serial_length = 0;
	uint32_t validity_days = CLI_DEFAULT_VALIDITY_DAYS;
	uint32_t path_length = 0;
	cert_digest_algorithm_t digest = CERT_DIGEST_DEFAULT;
	store_result_t result;
	char *ca_name = nullptr;
	bool has_path_length = false;
	bool is_ca = false;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->in_path, "--in")
	    || !cli_require_option(options->out_path, "--out"))
		return EXIT_FAILURE;
	if (!_cli_issue_mode(options))
		return EXIT_FAILURE;
	if (options->enforce) {
		fprintf(stderr,
			"anyca_cli: warning: --enforce accepts every extension requested by the CSR, including basicConstraints and keyUsage; review the request before issuing\n");
	}

	if (options->basic) {
		if (!cli_parse_bool(options->is_ca, &is_ca)) {
			fprintf(stderr, "anyca_cli: invalid --is-ca: %s\n",
				options->is_ca);
			return EXIT_FAILURE;
		}
		if (options->path_length != nullptr) {
			if (strcasecmp(options->path_length, "none") == 0) {
				has_path_length = false;
			} else if (!cli_parse_uint32(options->path_length,
						     &path_length)) {
				fprintf(stderr,
					"anyca_cli: invalid --path-length: %s\n",
					options->path_length);
				return EXIT_FAILURE;
			} else {
				has_path_length = true;
			}
		}
		if (has_path_length && !is_ca) {
			fprintf(stderr,
				"anyca_cli: --path-length requires --is-ca true\n");
			return EXIT_FAILURE;
		}
	} else if (!_cli_issue_reject_enforce_option(options->is_ca,
						     "--is-ca")
		   || !_cli_issue_reject_enforce_option(options->path_length,
							"--path-length")
		   || !_cli_issue_reject_enforce_option(
			   options->certificate_usage, "--certificate-usage")
		   || !_cli_issue_reject_enforce_option(
			   options->certificate_template,
			   "--certificate-template")
		   || !_cli_issue_reject_enforce_option(
			   options->certificate_policy,
			   "--certificate-policy")) {
		return EXIT_FAILURE;
	}

	if (options->digest != nullptr
	    && !cli_parse_digest(options->digest, &digest)) {
		fprintf(stderr, "anyca_cli: invalid --digest: %s\n",
			options->digest);
		return EXIT_FAILURE;
	}
	if (options->days != nullptr
	    && !cli_parse_validity_days(options->days, &validity_days)) {
		fprintf(stderr, "anyca_cli: invalid --days: %s\n",
			options->days);
		return EXIT_FAILURE;
	}
	if (options->serial != nullptr
	    && !cli_parse_serial(options->serial, &serial, &serial_length)) {
		fprintf(stderr, "anyca_cli: invalid --serial: %s\n",
			options->serial);
		return EXIT_FAILURE;
	}

	if (!cli_context_init(global->config_path, &context, false))
		goto done;
	/* cli_context_fini() tolerates a partially initialized context. */

	if (!cli_ca_selection_resolve(options->ca_name, options->ca_id, false,
				      &ca_name))
		goto done;

	result = store_ca_config_get(ca_name, &ca_config);
	if (result == STORE_ERR_NOT_FOUND) {
		fprintf(stderr, "anyca_cli: unknown issuer CA: %s\n", ca_name);
		goto done;
	}
	if (result != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: cannot load issuer CA configuration: %s\n",
			ca_name);
		goto done;
	}
	if (ca_config.hsm_provider == nullptr
	    || ca_config.token_label == nullptr || ca_config.pin == nullptr
	    || ca_config.key_label == nullptr || ca_config.ca_cert == nullptr
	    || ca_config.ca_cert_length == 0) {
		fprintf(stderr,
			"anyca_cli: issuer CA %s has an incomplete configuration\n",
			ca_name);
		goto done;
	}

	request = cert_request_load_file(options->in_path);
	if (request == nullptr) {
		fprintf(stderr,
			"anyca_cli: cannot load or verify the certificate request: %s\n",
			options->in_path);
		goto done;
	}

	sign.issuer_certificate = ca_config.ca_cert;
	sign.issuer_certificate_length = ca_config.ca_cert_length;
	sign.issuer_key.hsm_provider = ca_config.hsm_provider;
	sign.issuer_key.token_label = ca_config.token_label;
	sign.issuer_key.pin = ca_config.pin;
	sign.issuer_key.key_label = ca_config.key_label;
	sign.request = request;
	sign.basic = options->basic;
	sign.is_ca = is_ca;
	sign.has_path_length = has_path_length;
	sign.path_length = path_length;
	sign.certificate_usage = options->certificate_usage;
	sign.certificate_template = options->certificate_template;
	sign.certificate_policy = options->certificate_policy;
	sign.add_aki = !options->no_aki;
	sign.add_ski = !options->no_ski;
	sign.digest = digest;
	sign.serial = serial;
	sign.serial_length = serial_length;
	sign.validity_days = validity_days;
	sign.not_before = 0;

	if (!cli_sign_certificate_request(context.config, &sign, &certificate)) {
		fprintf(stderr,
			"anyca_cli: cannot issue the certificate\n");
		goto done;
	}
	/* Record first: a certificate file that clients can fetch must never
	 * exist without a store record that allows it to be revoked. */
	if (!cli_record_issued_certificate(ca_config.name, ca_config.ca_cert,
					   ca_config.ca_cert_length,
					   certificate.data,
					   certificate.length, nullptr))
		goto done;
	if (!cli_write_file(options->out_path, certificate.data,
			    certificate.length))
		goto done;

	printf("Issued certificate: %s (%zu bytes)\n", options->out_path,
	       certificate.length);
	status = EXIT_SUCCESS;

done:
	cert_blob_free(&certificate);
	cert_request_free(request);
	store_ca_config_free(&ca_config);
	osal_free(serial);
	osal_free(ca_name);
	cli_context_fini(&context);
	return status;
}

static int _cli_cert_new_root(cli_global_options_t *global,
			      const cli_cert_root_options_t *options)
{
	config_t *config = nullptr;
	cli_hsm_uri_t key_uri = { 0 };
	cli_cert_options_t params = { 0 };
	cert_blob_t certificate = { 0 };
	unsigned char *serial = nullptr;
	size_t serial_length = 0;
	uint32_t path_length = 0;
	uint32_t validity_days = CLI_DEFAULT_VALIDITY_DAYS;
	cert_digest_algorithm_t digest = CERT_DIGEST_DEFAULT;
	bool has_path_length = false;
	bool is_ca = true;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->subject, "--subject")
	    || !cli_require_option(options->key_uri, "--key-uri")
	    || !cli_require_option(options->certificate_usage,
				   "--certificate-usage")
	    || !cli_require_option(options->out_path, "--out"))
		return EXIT_FAILURE;

	if (options->digest != nullptr
	    && !cli_parse_digest(options->digest, &digest)) {
		fprintf(stderr, "anyca_cli: invalid --digest: %s\n",
			options->digest);
		return EXIT_FAILURE;
	}
	if (options->ca_value != nullptr
	    && !cli_parse_bool(options->ca_value, &is_ca)) {
		fprintf(stderr, "anyca_cli: invalid --is-ca: %s\n",
			options->ca_value);
		return EXIT_FAILURE;
	}
	if (options->path_length != nullptr) {
		if (strcasecmp(options->path_length, "none") == 0) {
			has_path_length = false;
		} else if (!cli_parse_uint32(options->path_length,
					     &path_length)) {
			fprintf(stderr,
				"anyca_cli: invalid --path-length: %s\n",
				options->path_length);
			return EXIT_FAILURE;
		} else {
			has_path_length = true;
		}
	}
	if (has_path_length && !is_ca) {
		fprintf(stderr,
			"anyca_cli: --path-length requires --is-ca true\n");
		return EXIT_FAILURE;
	}
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

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		goto done;
	}
	if (!cli_hsm_uri_parse(options->key_uri, &key_uri))
		goto done;
	if (!cli_hsm_uri_resolve_provider(config, &key_uri, "--key-uri"))
		goto done;

	params.issuer_key = key_uri.key;
	params.subject_key = params.issuer_key;
	params.subject = options->subject;
	params.certificate_usage = options->certificate_usage;
	params.certificate_template = options->certificate_template;
	params.digest = digest;
	params.is_ca = is_ca;
	params.has_path_length = has_path_length;
	params.path_length = path_length;
	params.serial = serial;
	params.serial_length = serial_length;
	params.validity_days = validity_days;
	params.not_before = 0;

	if (!cli_generate_certificate(config, &params, &certificate)) {
		fprintf(stderr,
			"anyca_cli: cannot generate the root certificate\n");
		goto done;
	}
	if (!cli_write_file(options->out_path, certificate.data,
			    certificate.length))
		goto done;

	printf("Generated root certificate: %s (%zu bytes)\n",
	       options->out_path, certificate.length);
	status = EXIT_SUCCESS;

done:
	cert_blob_free(&certificate);
	osal_free(serial);
	cli_hsm_uri_free(&key_uri);
	config_free(config);
	return status;
}

static const cli_option_spec_t _cli_cert_record_specs[] = {
	CLI_OPTION_SPEC(cli_cert_target_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_cert_target_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC(cli_cert_target_options_t, serial, "--serial"),
	CLI_OPTION_SPEC(cli_cert_target_options_t, in_path, "--in"),
	CLI_OPTION_SPEC(cli_cert_target_options_t, not_after, "--not-after"),
	CLI_OPTION_SPEC_FLAG(cli_cert_target_options_t, add, "--add"),
	CLI_OPTION_SPEC_FLAG(cli_cert_target_options_t, delete, "--delete"),
};

static const cli_option_spec_t _cli_cert_revoke_specs[] = {
	CLI_OPTION_SPEC(cli_cert_revoke_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_cert_revoke_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC(cli_cert_revoke_options_t, serial, "--serial"),
	CLI_OPTION_SPEC(cli_cert_revoke_options_t, in_path, "--in"),
	CLI_OPTION_SPEC(cli_cert_revoke_options_t, revoked_at, "--revoked-at"),
	CLI_OPTION_SPEC(cli_cert_revoke_options_t, reason, "--reason"),
	CLI_OPTION_SPEC_FLAG(cli_cert_revoke_options_t, add, "--add"),
	CLI_OPTION_SPEC_FLAG(cli_cert_revoke_options_t, delete, "--delete"),
};

static const cli_option_spec_t _cli_cert_list_specs[] = {
	CLI_OPTION_SPEC(cli_cert_list_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_cert_list_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC(cli_cert_list_options_t, limit, "--n"),
	CLI_OPTION_SPEC_FLAG(cli_cert_list_options_t, revocation,
			     "--revocation"),
};

static const cli_option_spec_t _cli_cert_issue_specs[] = {
	CLI_OPTION_SPEC(cli_cert_issue_options_t, ca_name, "--ca-name"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, ca_id, "--ca-id"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, in_path, "--in"),
	CLI_OPTION_SPEC_FLAG(cli_cert_issue_options_t, basic, "--basic"),
	CLI_OPTION_SPEC_FLAG(cli_cert_issue_options_t, enforce, "--enforce"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, is_ca, "--is-ca"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, path_length, "--path-length"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, certificate_usage,
			"--certificate-usage"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, certificate_template,
			"--certificate-template"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, certificate_policy,
			"--certificate-policy"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, digest, "--digest"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, days, "--days"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, serial, "--serial"),
	CLI_OPTION_SPEC(cli_cert_issue_options_t, out_path, "--out"),
	CLI_OPTION_SPEC_FLAG(cli_cert_issue_options_t, no_aki, "--no-aki"),
	CLI_OPTION_SPEC_FLAG(cli_cert_issue_options_t, no_ski, "--no-ski"),
};

static const cli_option_spec_t _cli_cert_new_root_specs[] = {
	CLI_OPTION_SPEC(cli_cert_root_options_t, subject, "--subject"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, key_uri, "--key-uri"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, certificate_usage,
			"--certificate-usage"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, certificate_template,
			"--certificate-template"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, ca_value, "--is-ca"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, path_length, "--path-length"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, validity_days, "--days"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, digest, "--digest"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, serial, "--serial"),
	CLI_OPTION_SPEC(cli_cert_root_options_t, out_path, "--out"),
};

int cli_cmd_cert_record(cli_global_options_t *global, int argc, char **argv,
			int first)
{
	cli_cert_target_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_cert_record_specs,
				  CLI_OPTION_COUNT(_cli_cert_record_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_cert_record(global, &options);
}

int cli_cmd_cert_revoke(cli_global_options_t *global, int argc, char **argv,
			int first)
{
	cli_cert_revoke_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_cert_revoke_specs,
				  CLI_OPTION_COUNT(_cli_cert_revoke_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_cert_revoke(global, &options);
}

int cli_cmd_cert_list(cli_global_options_t *global, int argc, char **argv,
		      int first)
{
	cli_cert_list_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_cert_list_specs,
				  CLI_OPTION_COUNT(_cli_cert_list_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_cert_list(global, &options);
}

int cli_cmd_cert_issue(cli_global_options_t *global, int argc, char **argv,
		       int first)
{
	cli_cert_issue_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_cert_issue_specs,
				  CLI_OPTION_COUNT(_cli_cert_issue_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_cert_issue(global, &options);
}

int cli_cmd_cert_new_root(cli_global_options_t *global, int argc, char **argv,
			  int first)
{
	cli_cert_root_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_cert_new_root_specs,
				  CLI_OPTION_COUNT(_cli_cert_new_root_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_cert_new_root(global, &options);
}
