/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#endif

#include <anyca/osal/compat.h>
#include <anyca/osal/file.h>
#include <anyca/osal/memory.h>

#include <anyca/ca.h>
#include <anyca/config.h>
#include <anyca/store.h>

#include "cli.h"

char *cli_strdup(const char *value)
{
	char *copy;
	size_t length;

	if (value == nullptr)
		return nullptr;
	length = strlen(value) + 1;
	copy = osal_malloc(length);
	if (copy != nullptr)
		memcpy(copy, value, length);
	return copy;
}

void cli_hsm_log(const char *what, hsm_status_t status)
{
	const struct hsm_error *error = hsm_get_last_error();

	fprintf(stderr, "anyca_cli: %s failed: %s: %s\n", what,
		hsm_status_to_string(status), error->message);
}

void cli_hsm_session_close(cli_hsm_session_t *session)
{
	hsm_status_t status;

	if (session->token != nullptr) {
		hsm_token_close(session->token);
		session->token = nullptr;
	}
	if (session->module != nullptr) {
		status = hsm_module_close(session->module);
		if (status != HSM_OK)
			cli_hsm_log("hsm_module_close", status);
		session->module = nullptr;
	}
}

bool cli_hsm_session_open(cli_hsm_session_t *session,
			  const config_hsm_provider_t *provider,
			  const char *token_label, const char *pin)
{
	struct hsm_config config;
	hsm_status_t status;

	memset(session, 0, sizeof *session);
	if (provider == nullptr || provider->library == nullptr
	    || provider->library[0] == '\0') {
		fprintf(stderr, "anyca_cli: HSM provider has no library path\n");
		return false;
	}

	config.module_path = provider->library;
	config.max_sessions_per_token = HSM_DEFAULT_MAX_SESSIONS;

	status = hsm_module_open(&config, &session->module);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_module_open", status);
		return false;
	}

	status = hsm_token_open(session->module, token_label, &session->token);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_token_open", status);
		goto fail;
	}

	if (pin != nullptr) {
		status = hsm_token_login(session->token, pin);
		if (status != HSM_OK) {
			cli_hsm_log("hsm_token_login", status);
			goto fail;
		}
	}
	return true;

fail:
	cli_hsm_session_close(session);
	return false;
}

static int _cli_hex_digit(char digit)
{
	if (digit >= '0' && digit <= '9')
		return digit - '0';
	if (digit >= 'a' && digit <= 'f')
		return digit - 'a' + 10;
	if (digit >= 'A' && digit <= 'F')
		return digit - 'A' + 10;
	return -1;
}

bool cli_parse_serial(const char *text, unsigned char **serial,
		      size_t *serial_length)
{
	unsigned char *buffer;
	size_t digits;
	size_t position = 0;

	if (text == nullptr || serial == nullptr || serial_length == nullptr)
		return false;
	*serial = nullptr;
	*serial_length = 0;

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
		text += 2;

	digits = strlen(text);
	if (digits == 0)
		return false;
	for (size_t i = 0; i < digits; i++) {
		if (_cli_hex_digit(text[i]) < 0)
			return false;
	}
	while (digits > 1 && text[0] == '0') {
		text++;
		digits--;
	}

	buffer = osal_malloc((digits + 1) / 2);
	if (buffer == nullptr)
		return false;

	if (digits % 2 != 0) {
		buffer[position++] = (unsigned char) _cli_hex_digit(text[0]);
		text++;
		digits--;
	}
	while (digits > 0) {
		int high = _cli_hex_digit(text[0]);
		int low = _cli_hex_digit(text[1]);

		buffer[position++] = (unsigned char) ((high << 4) | low);
		text += 2;
		digits -= 2;
	}

	*serial = buffer;
	*serial_length = position;
	return true;
}

bool cli_parse_ca_id(const char *text, store_ca_id_t *ca_id)
{
	int64_t value;

	if (text == nullptr || ca_id == nullptr)
		return false;
	if (!cli_parse_int64(text, &value) || value <= 0)
		return false;
	*ca_id = (store_ca_id_t) value;
	return true;
}

/* Tell whether key_hash is the SPKI hash of the configured CA certificate. */
static bool _cli_ca_config_matches(const store_ca_config_t *config,
				   const unsigned char *key_hash,
				   size_t key_hash_length)
{
	ca_t *ca;
	bool matches;

	ca = ca_new();
	if (ca == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}

	/* The configuration owns the certificate buffer; ca must not free it. */
	ca->ca_cert_der.data = config->ca_cert;
	ca->ca_cert_der.length = config->ca_cert_length;
	if (!ca_load_certificate(ca)) {
		fprintf(stderr,
			"anyca_cli: cannot parse the certificate of CA %s\n",
			config->name);
		ca->ca_cert_der.data = nullptr;
		ca->ca_cert_der.length = 0;
		ca_free(ca);
		return false;
	}

	matches = ca->spki_hash_sha256.length == key_hash_length
	    && memcmp(ca->spki_hash_sha256.data, key_hash, key_hash_length) == 0;
	ca->ca_cert_der.data = nullptr;
	ca->ca_cert_der.length = 0;
	ca_free(ca);
	return matches;
}

bool cli_ca_selection_resolve(const char *ca_name, const char *ca_id,
			      bool allow_none, char **name)
{
	const store_ca_record_t *selected = nullptr;
	store_ca_record_t *records = nullptr;
	store_ca_config_t config = { 0 };
	store_ca_id_t id;
	size_t count = 0;
	bool resolved = false;

	if (name == nullptr)
		return false;
	*name = nullptr;

	if (ca_name != nullptr && ca_id != nullptr) {
		fprintf(stderr,
			"anyca_cli: --ca-name and --ca-id are mutually exclusive\n");
		return false;
	}
	if (ca_name != nullptr) {
		*name = cli_strdup(ca_name);
		if (*name == nullptr)
			fprintf(stderr, "anyca_cli: out of memory\n");
		return *name != nullptr;
	}
	if (ca_id == nullptr) {
		if (!allow_none)
			fprintf(stderr,
				"anyca_cli: one of --ca-name or --ca-id is required\n");
		return allow_none;
	}

	if (!cli_parse_ca_id(ca_id, &id)) {
		fprintf(stderr, "anyca_cli: invalid --ca-id: %s\n", ca_id);
		return false;
	}
	if (store_ca_list(&records, &count) != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot list CAs\n");
		return false;
	}
	for (size_t i = 0; i < count; i++) {
		if (records[i].id == id) {
			selected = &records[i];
			break;
		}
	}
	if (selected == nullptr) {
		fprintf(stderr, "anyca_cli: unknown CA id: %" PRId64 "\n", id);
		goto done;
	}
	if (store_ca_config_get(selected->name, &config) != STORE_OK) {
		fprintf(stderr, "anyca_cli: unknown CA id: %" PRId64 "\n", id);
		goto done;
	}
	if (!_cli_ca_config_matches(&config, selected->key_hash,
				    selected->key_hash_length)) {
		fprintf(stderr,
			"anyca_cli: CA id %" PRId64 " does not match the current certificate of CA %s; use --ca-name\n",
			id, selected->name);
		goto done;
	}

	*name = cli_strdup(selected->name);
	if (*name == nullptr)
		fprintf(stderr, "anyca_cli: out of memory\n");
	resolved = *name != nullptr;

done:
	store_ca_config_free(&config);
	store_ca_list_free(records, count);
	return resolved;
}

char *cli_bytes_to_hex(const unsigned char *data, size_t length)
{
	static const char digits[] = "0123456789ABCDEF";
	char *text;
	size_t position = 0;

	text = osal_malloc(length * 2 + 1);
	if (text == nullptr)
		return nullptr;
	for (size_t i = 0; i < length; i++) {
		text[position++] = digits[data[i] >> 4];
		text[position++] = digits[data[i] & 0x0f];
	}
	text[position] = '\0';
	return text;
}

bool cli_record_issued_certificate(const char *ca_name,
				   const unsigned char *ca_cert_der,
				   size_t ca_cert_der_length,
				   const unsigned char *certificate_der,
				   size_t certificate_der_length,
				   cli_certificate_record_t *result_record)
{
	ca_t *ca = nullptr;
	X509 *certificate = nullptr;
	store_ca_id_t ca_id = 0;
	store_certificate_t entry = { 0 };
	store_result_t result;
	char *serial_text = nullptr;
	bool updated = false;
	bool ok = false;

	if (result_record != nullptr)
		memset(result_record, 0, sizeof *result_record);

	if (ca_name == nullptr || ca_name[0] == '\0' || ca_cert_der == nullptr
	    || ca_cert_der_length == 0 || certificate_der == nullptr
	    || certificate_der_length == 0) {
		fprintf(stderr,
			"anyca_cli: cannot record the certificate: missing issuer or certificate data\n");
		return false;
	}

	ca = ca_new();
	if (ca == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}
	ca->name = cli_strdup(ca_name);
	ca->ca_cert_der.data = osal_malloc(ca_cert_der_length);
	if (ca->name == nullptr || ca->ca_cert_der.data == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		goto done;
	}
	memcpy(ca->ca_cert_der.data, ca_cert_der, ca_cert_der_length);
	ca->ca_cert_der.length = ca_cert_der_length;

	if (!ca_load_certificate(ca)) {
		fprintf(stderr,
			"anyca_cli: cannot load the issuer certificate of CA %s\n",
			ca_name);
		goto done;
	}
	if (store_ca_register(ca->name, ca->spki_hash_sha256.data,
			      ca->spki_hash_sha256.length,
			      &ca_id) != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: cannot register CA %s in the store\n",
			ca_name);
		goto done;
	}

	certificate = ca_certificate_load_der(certificate_der,
					      certificate_der_length);
	if (certificate == nullptr) {
		fprintf(stderr,
			"anyca_cli: cannot parse the certificate to record\n");
		goto done;
	}
	if (!ca_certificate_serial(certificate, &entry.serial,
				   &entry.serial_length)
	    || !ca_certificate_not_after(certificate, &entry.not_after)) {
		fprintf(stderr,
			"anyca_cli: cannot read the certificate serial or notAfter\n");
		goto done;
	}

	result = store_certificate_add(ca_id, &entry);
	if (result == STORE_ERR_DUPLICATE) {
		result = store_certificate_update(ca_id, &entry);
		updated = true;
	}
	if (result != STORE_OK) {
		fprintf(stderr,
			"anyca_cli: cannot record the issued certificate\n");
		goto done;
	}

	serial_text = cli_bytes_to_hex(entry.serial, entry.serial_length);
	if (serial_text == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		goto done;
	}
	if (updated)
		printf("Updated certificate record: CA %s (id %" PRId64 "), "
		       "serial %s, notAfter %" PRId64 "\n",
		       ca_name, ca_id, serial_text, entry.not_after);
	else
		printf("Recorded certificate: CA %s (id %" PRId64 "), "
		       "serial %s, notAfter %" PRId64 "\n",
		       ca_name, ca_id, serial_text, entry.not_after);

	if (result_record != nullptr) {
		result_record->ca_id = ca_id;
		result_record->created = !updated;
		result_record->serial = entry.serial;
		result_record->serial_length = entry.serial_length;
		entry.serial = nullptr;
		entry.serial_length = 0;
	}
	ok = true;

done:
	osal_free(serial_text);
	osal_free(entry.serial);
	ca_certificate_free(certificate);
	ca_free(ca);
	return ok;
}

bool cli_parse_int64(const char *text, int64_t *value)
{
	char *end = nullptr;
	long long parsed;

	if (text == nullptr || *text == '\0' || value == nullptr)
		return false;
	errno = 0;
	parsed = strtoll(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0')
		return false;
	*value = (int64_t) parsed;
	return true;
}

/* Parse an optional uint32 option; NULL means zero. */
bool cli_parse_uint32(const char *text, uint32_t *value)
{
	int64_t parsed;

	if (text == nullptr) {
		*value = 0;
		return true;
	}
	if (!cli_parse_int64(text, &parsed) || parsed < 0
	    || parsed > UINT32_MAX)
		return false;
	*value = (uint32_t) parsed;
	return true;
}

bool cli_parse_bool(const char *text, bool *value)
{
	if (text == nullptr || value == nullptr)
		return false;

	if (strcasecmp(text, "true") == 0 || strcasecmp(text, "yes") == 0
	    || strcmp(text, "1") == 0) {
		*value = true;
		return true;
	}
	if (strcasecmp(text, "false") == 0 || strcasecmp(text, "no") == 0
	    || strcmp(text, "0") == 0) {
		*value = false;
		return true;
	}
	return false;
}

bool cli_parse_validity_days(const char *text, uint32_t *days)
{
	uint32_t value;

	if (text == nullptr || days == nullptr)
		return false;
	if (!cli_parse_uint32(text, &value) || value == 0
	    || value > CLI_MAX_VALIDITY_DAYS)
		return false;
	*days = value;
	return true;
}

bool cli_parse_digest(const char *text, cert_digest_algorithm_t *digest)
{
	if (text == nullptr || digest == nullptr)
		return false;

	if (strcasecmp(text, "sha1") == 0)
		*digest = CERT_DIGEST_SHA1;
	else if (strcasecmp(text, "sha256") == 0)
		*digest = CERT_DIGEST_SHA256;
	else if (strcasecmp(text, "sha384") == 0)
		*digest = CERT_DIGEST_SHA384;
	else if (strcasecmp(text, "sha512") == 0)
		*digest = CERT_DIGEST_SHA512;
	else
		return false;
	return true;
}

const char *cli_digest_name(cert_digest_algorithm_t digest)
{
	switch (digest) {
	case CERT_DIGEST_SHA1:
		return "sha1";
	case CERT_DIGEST_SHA256:
		return "sha256";
	case CERT_DIGEST_SHA384:
		return "sha384";
	case CERT_DIGEST_SHA512:
		return "sha512";
	}
	return nullptr;
}

bool cli_write_file(const char *path, const unsigned char *data, size_t length)
{
	/*
	 * Publish atomically: an interrupted or failed write must not leave a
	 * truncated certificate at a path that clients may already fetch.
	 */
	if (!osal_file_write_atomic(path, data, length, 0644)) {
		fprintf(stderr, "anyca_cli: cannot write %s: %s\n", path,
			osal_file_error());
		return false;
	}
	return true;
}

bool cli_require_option(const char *value, const char *option)
{
	if (value == nullptr || value[0] == '\0') {
		fprintf(stderr, "anyca_cli: %s is required\n", option);
		return false;
	}
	return true;
}

/* Read a whole file into an osal_malloc()ed buffer. */
bool cli_read_file(const char *path, unsigned char **data, size_t *length)
{
	FILE *file;
	long size;
	unsigned char *buffer;
	size_t read_length;

	*data = nullptr;
	*length = 0;

	file = fopen(path, "rb");
	if (file == nullptr) {
		fprintf(stderr, "anyca_cli: cannot open %s: %s\n", path,
			strerror(errno));
		return false;
	}
	if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
	    || fseek(file, 0, SEEK_SET) != 0) {
		fprintf(stderr, "anyca_cli: cannot read %s: %s\n", path,
			strerror(errno));
		fclose(file);
		return false;
	}
	if (size == 0 || size > INT_MAX) {
		fprintf(stderr, "anyca_cli: invalid file size for %s\n", path);
		fclose(file);
		return false;
	}

	buffer = osal_malloc((size_t) size);
	if (buffer == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		fclose(file);
		return false;
	}

	read_length = fread(buffer, 1, (size_t) size, file);
	if (read_length != (size_t) size) {
		fprintf(stderr, "anyca_cli: cannot read %s\n", path);
		/* The partial contents may include a PIN. */
		memset(buffer, 0, (size_t) size);
		osal_free(buffer);
		fclose(file);
		return false;
	}
	fclose(file);

	*data = buffer;
	*length = read_length;
	return true;
}

const config_hsm_provider_t *cli_hsm_provider_find(const config_t *config,
						   const char *name)
{
	if (config == nullptr || name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < config->hsm_providers_count; i++) {
		if (config->hsm_providers[i].name != nullptr
		    && strcmp(config->hsm_providers[i].name, name) == 0)
			return &config->hsm_providers[i];
	}
	return nullptr;
}

bool cli_hsm_uri_resolve_provider(const config_t *config, cli_hsm_uri_t *uri,
				  const char *option)
{
	const config_hsm_provider_t *match;
	const config_hsm_provider_t *full_match = nullptr;
	const config_hsm_provider_t *loose_match = nullptr;
	unsigned matches = 0;
	unsigned full_matches = 0;
	unsigned loose_matches = 0;

	if (config == nullptr || uri == nullptr)
		return false;

	if (uri->key.hsm_provider != nullptr) {
		match = cli_hsm_provider_find(config, uri->key.hsm_provider);
		if (match == nullptr) {
			fprintf(stderr,
				"anyca_cli: %s references unknown HSM provider: %s\n",
				option, uri->key.hsm_provider);
			return false;
		}
		if (uri->model != nullptr && match->model != nullptr
		    && strcmp(uri->model, match->model) != 0) {
			fprintf(stderr,
				"anyca_cli: %s model \"%s\" does not match HSM provider \"%s\" (model \"%s\")\n",
				option, uri->model, match->name, match->model);
			return false;
		}
		if (uri->serial != nullptr && match->serial != nullptr
		    && strcmp(uri->serial, match->serial) != 0) {
			fprintf(stderr,
				"anyca_cli: %s serial \"%s\" does not match HSM provider \"%s\" (serial \"%s\")\n",
				option, uri->serial, match->name, match->serial);
			return false;
		}
		return true;
	}

	for (unsigned i = 0; i < config->hsm_providers_count; i++) {
		const config_hsm_provider_t *candidate = &config->hsm_providers[i];
		bool full;

		if (candidate->name == nullptr)
			continue;
		if (uri->model != nullptr && candidate->model != nullptr
		    && strcmp(uri->model, candidate->model) != 0)
			continue;
		if (uri->serial != nullptr && candidate->serial != nullptr
		    && strcmp(uri->serial, candidate->serial) != 0)
			continue;

		/*
		 * An entry that declares every attribute used for selection is a
		 * full match and wins over entries that leave some unconstrained.
		 */
		full = (uri->model == nullptr || candidate->model != nullptr)
		    && (uri->serial == nullptr || candidate->serial != nullptr);
		if (full) {
			full_match = candidate;
			full_matches++;
		} else {
			loose_match = candidate;
			loose_matches++;
		}
	}

	if (full_matches == 0 && loose_matches == 0) {
		fprintf(stderr,
			"anyca_cli: %s matches no hsm_providers entry (model \"%s\", serial \"%s\")\n",
			option,
			uri->model != nullptr ? uri->model : "<unset>",
			uri->serial != nullptr ? uri->serial : "<unset>");
		return false;
	}

	match = full_matches > 0 ? full_match : loose_match;
	matches = full_matches > 0 ? full_matches : loose_matches;
	if (matches > 1) {
		fprintf(stderr,
			"anyca_cli: %s matches %u hsm_providers entries; add model/serial to the configuration or use provider\n",
			option, matches);
		return false;
	}

	uri->key.hsm_provider = match->name;
	return true;
}

const config_certificate_usage_t *
cli_certificate_usage_find(const config_t *config, const char *name)
{
	if (config == nullptr || name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < config->certificate_usages_count; i++) {
		if (config->certificate_usages[i].name != nullptr
		    && strcmp(config->certificate_usages[i].name, name) == 0)
			return &config->certificate_usages[i];
	}
	return nullptr;
}

const config_certificate_template_t *
cli_certificate_template_find(const config_t *config, const char *name)
{
	if (config == nullptr || name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < config->certificate_templates_count; i++) {
		if (config->certificate_templates[i].name != nullptr
		    && strcmp(config->certificate_templates[i].name, name) == 0)
			return &config->certificate_templates[i];
	}
	return nullptr;
}

const config_certificate_policy_t *
cli_certificate_policy_find(const config_t *config, const char *name)
{
	if (config == nullptr || name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < config->certificate_policies_count; i++) {
		if (config->certificate_policies[i].name != nullptr
		    && strcmp(config->certificate_policies[i].name, name) == 0)
			return &config->certificate_policies[i];
	}
	return nullptr;
}

void cli_context_fini(cli_context_t *context)
{
	for (unsigned i = 0; i < context->cas_count; i++)
		ca_free(context->cas[i].ca);
	osal_free(context->cas);
	store_fini();
	config_free(context->config);
	memset(context, 0, sizeof *context);
}

/* Load the CA certificates stored in ca_config and register their ids. */
static bool _cli_load_cas(cli_context_t *context)
{
	store_ca_config_t *configs = nullptr;
	size_t count = 0;
	bool ok = false;

	if (store_ca_config_list(&configs, &count) != STORE_OK) {
		fprintf(stderr, "anyca_cli: cannot list CA configurations\n");
		return false;
	}
	if (count == 0) {
		ok = true;
		goto done;
	}
	if (count > UINT_MAX) {
		fprintf(stderr, "anyca_cli: too many CA configurations\n");
		goto done;
	}

	context->cas = osal_calloc(count, sizeof *context->cas);
	if (context->cas == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		goto done;
	}

	for (size_t i = 0; i < count; i++) {
		const store_ca_config_t *source = &configs[i];
		ca_t *ca = ca_new();

		if (ca == nullptr) {
			fprintf(stderr, "anyca_cli: out of memory\n");
			goto done;
		}
		context->cas[i].ca = ca;
		context->cas_count = (unsigned) (i + 1);

		if (source->name == nullptr || source->name[0] == '\0'
		    || source->ca_cert == nullptr
		    || source->ca_cert_length == 0) {
			fprintf(stderr,
				"anyca_cli: CA %zu has no name or certificate\n",
				i);
			goto done;
		}
		ca->name = cli_strdup(source->name);
		if (ca->name == nullptr) {
			fprintf(stderr, "anyca_cli: out of memory\n");
			goto done;
		}
		ca->ca_cert_der.data = osal_malloc(source->ca_cert_length);
		if (ca->ca_cert_der.data == nullptr) {
			fprintf(stderr, "anyca_cli: out of memory\n");
			goto done;
		}
		memcpy(ca->ca_cert_der.data, source->ca_cert,
		       source->ca_cert_length);
		ca->ca_cert_der.length = source->ca_cert_length;

		if (!ca_load_certificate(ca)) {
			fprintf(stderr,
				"anyca_cli: cannot load CA certificate: %s\n",
				source->name);
			goto done;
		}
		if (store_ca_register(ca->name, ca->spki_hash_sha256.data,
				      ca->spki_hash_sha256.length,
				      &context->cas[i].store_id) != STORE_OK) {
			fprintf(stderr,
				"anyca_cli: cannot register CA %s in the store\n",
				ca->name);
			goto done;
		}
	}
	ok = true;

done:
	store_ca_config_list_free(configs, count);
	return ok;
}

bool cli_context_init(const char *config_path, cli_context_t *context,
		      bool load_cas)
{
	memset(context, 0, sizeof *context);
	if (config_load(config_path, &context->config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			config_path);
		return false;
	}
	if (context->config->store.path == nullptr
	    || context->config->store.path[0] == '\0') {
		fprintf(stderr, "anyca_cli: store.path is not configured\n");
		goto fail;
	}
	if (!store_init(context->config->store.path)) {
		fprintf(stderr, "anyca_cli: cannot open store: %s\n",
			context->config->store.path);
		goto fail;
	}
	if (load_cas && !_cli_load_cas(context))
		goto fail;
	return true;

fail:
	cli_context_fini(context);
	return false;
}

bool cli_option_matches(const char *argument, const char *name,
			const char **inline_value)
{
	size_t length = strlen(name);

	if (strcmp(argument, name) == 0) {
		*inline_value = nullptr;
		return true;
	}
	if (strncmp(argument, name, length) == 0 && argument[length] == '=') {
		*inline_value = argument + length + 1;
		return true;
	}
	return false;
}

const char *cli_option_value_allow_empty(int argc, char **argv, int *index,
					 const char *inline_value,
					 const char *name)
{
	const char *value;

	if (inline_value != nullptr) {
		value = inline_value;
	} else if (*index + 1 < argc) {
		value = argv[++(*index)];
	} else {
		fprintf(stderr, "anyca_cli: %s needs a value\n", name);
		return nullptr;
	}
	return value;
}

const char *cli_option_value(int argc, char **argv, int *index,
			     const char *inline_value, const char *name)
{
	const char *value = cli_option_value_allow_empty(
		argc, argv, index, inline_value, name);

	if (value != nullptr && *value == '\0') {
		fprintf(stderr, "anyca_cli: %s needs a value\n", name);
		return nullptr;
	}
	return value;
}

cli_parse_result_t cli_parse_options(int argc, char **argv, int first,
				     cli_global_options_t *global,
				     const cli_option_spec_t *specs,
				     size_t count, void *options)
{
	for (int index = first; index < argc; index++) {
		const char *argument = argv[index];
		const char *inline_value;
		const char *value;
		size_t i;

		switch (cli_parse_global_option(argc, argv, &index, argument,
						global)) {
		case CLI_GLOBAL_OPTION_HELP:
			return CLI_PARSE_HELP;
		case CLI_GLOBAL_OPTION_VERSION:
			return CLI_PARSE_VERSION;
		case CLI_GLOBAL_OPTION_ERROR:
			return CLI_PARSE_ERROR;
		case CLI_GLOBAL_OPTION_HANDLED:
			continue;
		case CLI_GLOBAL_OPTION_NOT_MATCHED:
			break;
		}

		for (i = 0; i < count; i++) {
			if (specs[i].is_flag) {
				if (strcmp(argument, specs[i].name) != 0)
					continue;
				*(bool *) ((unsigned char *) options
					   + specs[i].offset) = true;
				break;
			}
			if (!cli_option_matches(argument, specs[i].name,
						&inline_value))
				continue;
			value = specs[i].allow_empty
				? cli_option_value_allow_empty(
					  argc, argv, &index, inline_value,
					  specs[i].name)
				: cli_option_value(argc, argv, &index,
						   inline_value, specs[i].name);
			if (value == nullptr)
				return CLI_PARSE_ERROR;
			*(const char **) ((unsigned char *) options
					  + specs[i].offset) = value;
			break;
		}
		if (i == count) {
			fprintf(stderr, "anyca_cli: unknown option: %s\n",
				argument);
			return CLI_PARSE_ERROR;
		}
	}
	return CLI_PARSE_OK;
}

cli_global_option_result_t cli_parse_global_option(
	int argc, char **argv, int *index, const char *argument,
	cli_global_options_t *global)
{
	const char *inline_value;

	if (strcmp(argument, "-h") == 0 || strcmp(argument, "--help") == 0)
		return CLI_GLOBAL_OPTION_HELP;
	if (strcmp(argument, "-V") == 0 || strcmp(argument, "--version") == 0)
		return CLI_GLOBAL_OPTION_VERSION;

	if (strcmp(argument, "-c") == 0) {
		if (++(*index) >= argc) {
			fprintf(stderr, "anyca_cli: -c needs a value\n");
			return CLI_GLOBAL_OPTION_ERROR;
		}
		global->config_path = argv[*index];
		return CLI_GLOBAL_OPTION_HANDLED;
	}
	if (cli_option_matches(argument, "--config", &inline_value)) {
		global->config_path = cli_option_value(argc, argv, index,
						       inline_value, "--config");
		return global->config_path != nullptr
			       ? CLI_GLOBAL_OPTION_HANDLED
			       : CLI_GLOBAL_OPTION_ERROR;
	}
	return CLI_GLOBAL_OPTION_NOT_MATCHED;
}

/* Percent-decode text in place; return false on a malformed escape. */
static bool _cli_uri_decode(char *text)
{
	char *source = text;
	char *destination = text;

	while (*source != '\0') {
		if (*source != '%') {
			*destination++ = *source++;
			continue;
		}
		if (source[1] == '\0' || source[2] == '\0') {
			fprintf(stderr,
				"anyca_cli: truncated %% escape in PKCS #11 URI\n");
			return false;
		}
		int high = _cli_hex_digit(source[1]);
		int low = _cli_hex_digit(source[2]);
		int byte;

		if (high < 0 || low < 0) {
			fprintf(stderr,
				"anyca_cli: invalid %% escape in PKCS #11 URI\n");
			return false;
		}
		byte = (high << 4) | low;
		if (byte == 0) {
			fprintf(stderr,
				"anyca_cli: NUL byte in PKCS #11 URI\n");
			return false;
		}
		*destination++ = (char) byte;
		source += 3;
	}
	*destination = '\0';
	return true;
}

/*
 * Read a PIN file.  POSIX requires a regular file that the calling user (or
 * root) owns and that group/other cannot access; O_NOFOLLOW also rejects a
 * symlink instead of following it.
 */
static char *_cli_read_pin_file(const char *path)
{
	unsigned char *data = nullptr;
	size_t length = 0;
	size_t data_length;
	char *pin;
	size_t pin_length;
	FILE *file = nullptr;
	long size;
	size_t read_length;

	if (path == nullptr || path[0] == '\0') {
		fprintf(stderr, "anyca_cli: PIN source path is empty\n");
		return nullptr;
	}

#if defined(_WIN32)
	{
		DWORD attributes = GetFileAttributesA(path);

		if (attributes == INVALID_FILE_ATTRIBUTES
		    || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
		    || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
			fprintf(stderr,
				"anyca_cli: PIN source %s must be a regular file, not a directory or symlink\n",
				path);
			return nullptr;
		}
	}
	file = fopen(path, "rb");
	if (file == nullptr) {
		fprintf(stderr, "anyca_cli: cannot open %s: %s\n", path,
			strerror(errno));
		return nullptr;
	}
#else
	{
		struct stat status;
		int descriptor = open(path, O_RDONLY | O_NOFOLLOW);

		if (descriptor < 0) {
			fprintf(stderr, "anyca_cli: cannot open %s: %s\n", path,
				strerror(errno));
			return nullptr;
		}
		if (fstat(descriptor, &status) != 0
		    || !S_ISREG(status.st_mode)
		    || (status.st_uid != geteuid() && status.st_uid != 0)
		    || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
			fprintf(stderr,
				"anyca_cli: PIN source %s must be a regular file owned by the current user with no group or other permissions\n",
				path);
			(void) close(descriptor);
			return nullptr;
		}
		file = fdopen(descriptor, "rb");
		if (file == nullptr) {
			fprintf(stderr, "anyca_cli: cannot read %s: %s\n", path,
				strerror(errno));
			(void) close(descriptor);
			return nullptr;
		}
	}
#endif

	if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
	    || fseek(file, 0, SEEK_SET) != 0) {
		fprintf(stderr, "anyca_cli: cannot read %s: %s\n", path,
			strerror(errno));
		fclose(file);
		return nullptr;
	}
	if (size == 0 || size > INT_MAX) {
		fprintf(stderr, "anyca_cli: invalid file size for %s\n", path);
		fclose(file);
		return nullptr;
	}

	data = osal_malloc((size_t) size);
	if (data == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		fclose(file);
		return nullptr;
	}
	read_length = fread(data, 1, (size_t) size, file);
	fclose(file);
	if (read_length != (size_t) size) {
		fprintf(stderr, "anyca_cli: cannot read %s\n", path);
		memset(data, 0, (size_t) size);
		osal_free(data);
		return nullptr;
	}

	length = read_length;
	data_length = length;
	if (memchr(data, '\0', length) != nullptr) {
		fprintf(stderr,
			"anyca_cli: PIN source %s contains a NUL byte\n", path);
		memset(data, 0, data_length);
		osal_free(data);
		return nullptr;
	}
	while (length > 0
	       && (data[length - 1] == '\n' || data[length - 1] == '\r'))
		length--;
	if (length == 0) {
		fprintf(stderr, "anyca_cli: PIN source %s is empty\n", path);
		memset(data, 0, data_length);
		osal_free(data);
		return nullptr;
	}

	pin_length = length;
	pin = osal_secure_malloc(pin_length + 1);
	if (pin == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		memset(data, 0, data_length);
		osal_free(data);
		return nullptr;
	}
	memcpy(pin, data, pin_length);
	pin[pin_length] = '\0';
	memset(data, 0, data_length);
	osal_free(data);
	return pin;
}

/* Duplicate a string into locked, wipe-on-free memory. */
static char *_cli_secure_strdup(const char *value)
{
	size_t length;
	char *copy;

	if (value == nullptr)
		return nullptr;
	length = strlen(value) + 1;
	copy = osal_secure_malloc(length);
	if (copy != nullptr)
		memcpy(copy, value, length);
	return copy;
}

typedef struct cli_uri_seen {
	bool provider;
	bool token;
	bool object;
	bool model;
	bool serial;
	bool manufacturer;
	bool type;
	bool pin_value;
	bool pin_source;
} cli_uri_seen_t;

static bool _cli_uri_seen_once(bool *seen, const char *name)
{
	if (*seen) {
		fprintf(stderr,
			"anyca_cli: duplicate attribute \"%s\" in PKCS #11 URI\n",
			name);
		return false;
	}
	*seen = true;
	return true;
}

/* Store one path or query attribute; query only accepts the PIN attributes. */
static bool _cli_uri_store_attribute(cli_hsm_uri_t *parsed, const char *name,
				     char *value, bool query,
				     cli_uri_seen_t *seen)
{
	if (strcmp(name, "pin-value") == 0) {
		if (!_cli_uri_seen_once(&seen->pin_value, name))
			return false;
		parsed->key.pin = value;
		return true;
	}
	if (strcmp(name, "pin-source") == 0) {
		if (!_cli_uri_seen_once(&seen->pin_source, name))
			return false;
		parsed->pin_storage = _cli_read_pin_file(value);
		if (parsed->pin_storage == nullptr)
			return false;
		parsed->key.pin = parsed->pin_storage;
		return true;
	}
	if (query) {
		fprintf(stderr,
			"anyca_cli: unknown query attribute \"%s\" in PKCS #11 URI\n",
			name);
		return false;
	}
	if (strcmp(name, "provider") == 0) {
		if (!_cli_uri_seen_once(&seen->provider, name))
			return false;
		parsed->key.hsm_provider = value;
	} else if (strcmp(name, "token") == 0) {
		if (!_cli_uri_seen_once(&seen->token, name))
			return false;
		parsed->key.token_label = value;
	} else if (strcmp(name, "object") == 0) {
		if (!_cli_uri_seen_once(&seen->object, name))
			return false;
		parsed->key.key_label = value;
	} else if (strcmp(name, "model") == 0) {
		if (!_cli_uri_seen_once(&seen->model, name))
			return false;
		parsed->model = value;
	} else if (strcmp(name, "serial") == 0) {
		if (!_cli_uri_seen_once(&seen->serial, name))
			return false;
		parsed->serial = value;
	} else if (strcmp(name, "manufacturer") == 0) {
		if (!_cli_uri_seen_once(&seen->manufacturer, name))
			return false;
		parsed->manufacturer = value;
	} else if (strcmp(name, "type") == 0) {
		if (!_cli_uri_seen_once(&seen->type, name))
			return false;
		if (strcmp(value, "private") != 0) {
			fprintf(stderr,
				"anyca_cli: PKCS #11 URI type must be private\n");
			return false;
		}
	} else {
		fprintf(stderr,
			"anyca_cli: unknown attribute \"%s\" in PKCS #11 URI\n",
			name);
		return false;
	}
	return true;
}

/* Parse one ';'-separated path component or '&'-separated query component. */
static bool _cli_uri_attributes(cli_hsm_uri_t *parsed, char *component,
				char separator, bool query,
				cli_uri_seen_t *seen)
{
	char *cursor = component;

	while (cursor != nullptr && *cursor != '\0') {
		char *attribute = cursor;
		char *end = strchr(cursor, separator);
		char *equals;
		char *name;
		char *value;

		if (end != nullptr) {
			*end = '\0';
			cursor = end + 1;
			if (*cursor == '\0') {
				fprintf(stderr,
					"anyca_cli: empty attribute in PKCS #11 URI\n");
				return false;
			}
		} else {
			cursor = nullptr;
		}

		equals = strchr(attribute, '=');
		if (equals == nullptr || equals == attribute) {
			fprintf(stderr,
				"anyca_cli: malformed attribute \"%s\" in PKCS #11 URI\n",
				attribute);
			return false;
		}
		*equals = '\0';
		name = attribute;
		value = equals + 1;
		if (!_cli_uri_decode(value))
			return false;
		if (value[0] == '\0') {
			fprintf(stderr,
				"anyca_cli: empty value for \"%s\" in PKCS #11 URI\n",
				name);
			return false;
		}
		if (!_cli_uri_store_attribute(parsed, name, value, query, seen))
			return false;
	}
	return true;
}

bool cli_hsm_uri_parse(const char *uri, cli_hsm_uri_t *parsed)
{
	cli_uri_seen_t seen = { 0 };
	char *path;
	char *query;

	if (parsed == nullptr)
		return false;
	memset(parsed, 0, sizeof *parsed);
	if (uri == nullptr || strncasecmp(uri, "pkcs11:", 7) != 0) {
		fprintf(stderr,
			"anyca_cli: invalid PKCS #11 URI (expected pkcs11:...)\n");
		return false;
	}
	if (uri[7] == '\0') {
		fprintf(stderr, "anyca_cli: empty PKCS #11 URI\n");
		return false;
	}

	/* The URI text may carry a pin-value attribute. */
	parsed->storage = _cli_secure_strdup(uri + 7);
	if (parsed->storage == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}

	path = parsed->storage;
	query = strchr(path, '?');
	if (query != nullptr) {
		*query = '\0';
		query++;
	}

	if (!_cli_uri_attributes(parsed, path, ';', false, &seen))
		goto fail;
	if (query != nullptr && *query != '\0'
	    && !_cli_uri_attributes(parsed, query, '&', true, &seen))
		goto fail;

	if (seen.pin_value && seen.pin_source) {
		fprintf(stderr,
			"anyca_cli: pin-value and pin-source are mutually exclusive\n");
		goto fail;
	}
	if (!seen.token || !seen.object
	    || (!seen.pin_value && !seen.pin_source)) {
		fprintf(stderr,
			"anyca_cli: PKCS #11 URI requires token, object and pin-value or pin-source\n");
		goto fail;
	}
	if (!seen.provider && !seen.model && !seen.serial) {
		fprintf(stderr,
			"anyca_cli: PKCS #11 URI requires provider, model or serial\n");
		goto fail;
	}
	return true;

fail:
	cli_hsm_uri_free(parsed);
	return false;
}

void cli_hsm_uri_free(cli_hsm_uri_t *parsed)
{
	if (parsed == nullptr)
		return;

	/*
	 * storage may carry a pin-value and pin_storage holds pin-source
	 * contents, so both use secure memory and are wiped on release.
	 */
	osal_secure_free(parsed->pin_storage);
	osal_secure_free(parsed->storage);
	memset(parsed, 0, sizeof *parsed);
}
