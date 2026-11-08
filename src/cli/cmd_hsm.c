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

#include <anyca/config.h>
#include <anyca/hsm.h>
#include <anyca/ossl/pkey.h>
#include <anyca/ossl/x509.h>

#include "cli.h"

typedef struct cli_hsm_list_options {
	const char *provider;
} cli_hsm_list_options_t;

typedef struct cli_hsm_token_options {
	const char *provider;
	const char *token;
} cli_hsm_token_options_t;

typedef struct cli_hsm_key_options {
	const char *key_uri;
	const char *key_type;
	const char *rsa_bits;
	const char *ec_curve;
	const char *new_pin;
} cli_hsm_key_options_t;

typedef struct cli_hsm_key_list_options {
	const char *provider;
	const char *token;
	const char *pin_source;
	const char *pin_value;
} cli_hsm_key_list_options_t;

typedef struct cli_hsm_fetch_uri_options {
	const char *provider;
	const char *token;
	const char *label;
	const char *pin_source;
	const char *pin_value;
} cli_hsm_fetch_uri_options_t;

typedef struct cli_hsm_search_options {
	const char *in_path;
	const char *provider;
	const char *token;
	const char *pin_source;
	const char *pin_value;
} cli_hsm_search_options_t;

/* Resolve a PKCS #11 key URI and its hsm_providers entry. */
static bool _cli_hsm_key_resolve(const config_t *config, const char *text,
				 cli_hsm_uri_t *uri, const char *option)
{
	if (!cli_hsm_uri_parse(text, uri))
		return false;
	if (!cli_hsm_uri_resolve_provider(config, uri, option)) {
		cli_hsm_uri_free(uri);
		return false;
	}
	return true;
}

/* Number of significant bits in a big-endian positive integer. */
static unsigned _cli_integer_bits(const unsigned char *data, size_t length)
{
	unsigned bits;

	while (length > 0 && data[0] == 0) {
		data++;
		length--;
	}
	if (length == 0)
		return 0;

	bits = (unsigned) (length - 1) * 8;
	for (unsigned char top = data[0]; top != 0; top >>= 1)
		bits++;
	return bits;
}

/* Name of a DER-encoded namedCurve OID. */
static const char *_cli_ec_curve_name(const unsigned char *params,
				      size_t length)
{
	static const unsigned char p256[] = {
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	};
	static const unsigned char p384[] = {
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
	};
	static const unsigned char p521[] = {
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
	};

	if (length == sizeof p256 && memcmp(params, p256, length) == 0)
		return "p256";
	if (length == sizeof p384 && memcmp(params, p384, length) == 0)
		return "p384";
	if (length == sizeof p521 && memcmp(params, p521, length) == 0)
		return "p521";
	return nullptr;
}

/* OpenSSL provider name for a curve OID returned by _cli_ec_curve_name(). */
static const char *_cli_ec_group_name(const unsigned char *params,
				      size_t length)
{
	const char *curve = _cli_ec_curve_name(params, length);

	if (curve == nullptr)
		return nullptr;
	if (strcmp(curve, "p256") == 0)
		return "prime256v1";
	if (strcmp(curve, "p384") == 0)
		return "secp384r1";
	return "secp521r1";
}

static bool _cli_uri_unreserved(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	       || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
	       || c == '~';
}

/* Percent-encode a value for a PKCS #11 URI attribute. */
static char *_cli_uri_escape(const char *value)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t length = strlen(value);
	size_t cursor = 0;
	char *encoded;

	if (length > (SIZE_MAX - 1) / 3) {
		fprintf(stderr, "anyca_cli: value is too long\n");
		return nullptr;
	}
	encoded = osal_malloc(length * 3 + 1);
	if (encoded == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return nullptr;
	}

	for (size_t i = 0; i < length; i++) {
		unsigned char c = (unsigned char) value[i];

		if (_cli_uri_unreserved(c)) {
			encoded[cursor++] = (char) c;
		} else {
			encoded[cursor++] = '%';
			encoded[cursor++] = hex[c >> 4];
			encoded[cursor++] = hex[c & 0x0f];
		}
	}
	encoded[cursor] = '\0';
	return encoded;
}

/*
 * Build a PKCS #11 key URI.  pin_source and pin_value are mutually
 * exclusive; when both are NULL the URI has no credentials.
 */
static char *_cli_key_uri(const char *provider, const char *token,
			  const char *label, const char *pin_source,
			  const char *pin_value)
{
	char *encoded_provider = nullptr;
	char *encoded_token = nullptr;
	char *encoded_label = nullptr;
	char *encoded_pin = nullptr;
	const char *pin_prefix = nullptr;
	char *uri = nullptr;
	size_t capacity;
	int written;

	encoded_provider = _cli_uri_escape(provider);
	encoded_token = _cli_uri_escape(token);
	encoded_label = _cli_uri_escape(label);
	if (encoded_provider == nullptr || encoded_token == nullptr
	    || encoded_label == nullptr)
		goto done;

	if (pin_source != nullptr) {
		encoded_pin = _cli_uri_escape(pin_source);
		pin_prefix = "?pin-source=";
	} else if (pin_value != nullptr) {
		encoded_pin = _cli_uri_escape(pin_value);
		pin_prefix = "?pin-value=";
	}
	if (pin_prefix != nullptr && encoded_pin == nullptr)
		goto done;

	capacity = strlen("pkcs11:provider=") + strlen(encoded_provider)
		   + strlen(";token=") + strlen(encoded_token)
		   + strlen(";object=") + strlen(encoded_label) + 1;
	if (pin_prefix != nullptr)
		capacity += strlen(pin_prefix) + strlen(encoded_pin);

	uri = osal_malloc(capacity);
	if (uri == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		goto done;
	}
	if (pin_prefix != nullptr)
		written = snprintf(uri, capacity,
				   "pkcs11:provider=%s;token=%s;object=%s%s%s",
				   encoded_provider, encoded_token,
				   encoded_label, pin_prefix, encoded_pin);
	else
		written = snprintf(uri, capacity,
				   "pkcs11:provider=%s;token=%s;object=%s",
				   encoded_provider, encoded_token,
				   encoded_label);
	if (written < 0 || (size_t) written >= capacity) {
		memset(uri, 0, capacity);
		osal_free(uri);
		uri = nullptr;
	}

done:
	osal_free(encoded_provider);
	osal_free(encoded_token);
	osal_free(encoded_label);
	if (encoded_pin != nullptr) {
		memset(encoded_pin, 0, strlen(encoded_pin));
		osal_free(encoded_pin);
	}
	return uri;
}

/* Resolve --pin-source/--pin-value into a PIN and an optional owned copy. */
static bool _cli_hsm_pin(const char *pin_source, const char *pin_value,
			 const char **pin, char **storage)
{
	unsigned char *data = nullptr;
	size_t length = 0;
	size_t data_length;
	char *copy;

	*pin = nullptr;
	*storage = nullptr;

	if (pin_source != nullptr && pin_value != nullptr) {
		fprintf(stderr,
			"anyca_cli: --pin-source and --pin-value are mutually "
			"exclusive\n");
		return false;
	}
	if (pin_value != nullptr) {
		*pin = pin_value;
		return true;
	}
	if (pin_source == nullptr)
		return true;

	if (!cli_read_file(pin_source, &data, &length))
		return false;
	data_length = length;
	if (memchr(data, '\0', length) != nullptr) {
		fprintf(stderr, "anyca_cli: PIN file contains a NUL byte: %s\n",
			pin_source);
		memset(data, 0, data_length);
		osal_free(data);
		return false;
	}
	while (length > 0
	       && (data[length - 1] == '\n' || data[length - 1] == '\r'))
		length--;
	if (length == 0) {
		fprintf(stderr, "anyca_cli: PIN file is empty: %s\n",
			pin_source);
		memset(data, 0, data_length);
		osal_free(data);
		return false;
	}

	copy = osal_secure_malloc(length + 1);
	if (copy == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		memset(data, 0, data_length);
		osal_free(data);
		return false;
	}
	memcpy(copy, data, length);
	copy[length] = '\0';
	memset(data, 0, data_length);
	osal_free(data);

	*pin = copy;
	*storage = copy;
	return true;
}

/* Canonical OpenSSL name for an ML-DSA parameter set, or NULL. */
static const char *_cli_ml_dsa_algorithm_name(hsm_ml_dsa_parameter_set_t set)
{
	switch (set) {
	case HSM_ML_DSA_44:
		return "ML-DSA-44";
	case HSM_ML_DSA_65:
		return "ML-DSA-65";
	case HSM_ML_DSA_87:
		return "ML-DSA-87";
	}
	return nullptr;
}

/* Algorithm label such as RSA2048 or ECC-P384 for one key object. */
static void _cli_key_algorithm(const hsm_key_object_t *key,
			       const hsm_key_object_t *objects, size_t count,
			       char *buffer, size_t buffer_size)
{
	unsigned int rsa_bits = key->rsa_bits;
	const unsigned char *ec_params = key->ec_params;
	size_t ec_params_length = key->ec_params_length;

	/*
	 * Some tokens hide key-size attributes on private-key objects.
	 * Use the matching public-key object when available.
	 */
	for (size_t i = 0; i < count; i++) {
		if (strcmp(objects[i].label, key->label) != 0
		    || objects[i].key_type != key->key_type)
			continue;
		if (key->key_type == HSM_KEY_TYPE_RSA && rsa_bits == 0)
			rsa_bits = objects[i].rsa_bits;
		if (key->key_type == HSM_KEY_TYPE_EC && ec_params_length == 0
		    && objects[i].ec_params_length > 0) {
			ec_params = objects[i].ec_params;
			ec_params_length = objects[i].ec_params_length;
		}
	}

	if (key->key_type == HSM_KEY_TYPE_RSA) {
		if (rsa_bits > 0)
			snprintf(buffer, buffer_size, "RSA%u", rsa_bits);
		else
			snprintf(buffer, buffer_size, "RSA-UNKNOWN");
		return;
	}

	if (key->key_type == HSM_KEY_TYPE_ML_DSA) {
		const char *name = _cli_ml_dsa_algorithm_name(
			key->ml_dsa_parameter_set);

		snprintf(buffer, buffer_size, "%s",
			 name != nullptr ? name : "ML-DSA-UNKNOWN");
		return;
	}

	if (key->key_type != HSM_KEY_TYPE_EC) {
		snprintf(buffer, buffer_size, "UNKNOWN");
		return;
	}

	if (ec_params_length == 0) {
		snprintf(buffer, buffer_size, "ECC-UNKNOWN");
		return;
	}
	const char *curve = _cli_ec_curve_name(ec_params, ec_params_length);

	if (curve == nullptr)
		snprintf(buffer, buffer_size, "ECC-UNKNOWN");
	else if (strcmp(curve, "p256") == 0)
		snprintf(buffer, buffer_size, "ECC-P256");
	else if (strcmp(curve, "p384") == 0)
		snprintf(buffer, buffer_size, "ECC-P384");
	else
		snprintf(buffer, buffer_size, "ECC-P521");
}

static int _cli_key_object_compare(const void *left, const void *right)
{
	const hsm_key_object_t *a = left;
	const hsm_key_object_t *b = right;
	int result = strcmp(a->label, b->label);

	if (result != 0)
		return result;
	return (int) a->key_class - (int) b->key_class;
}

static bool _cli_print_key_object(const char *provider, const char *token,
				  const hsm_key_object_t *key,
				  const hsm_key_object_t *objects,
				  size_t count)
{
	char algorithm[32];
	char *uri;

	_cli_key_algorithm(key, objects, count, algorithm, sizeof algorithm);
	uri = _cli_key_uri(provider, token, key->label, nullptr, nullptr);
	if (uri == nullptr)
		return false;

	printf("Key: %s\n", key->label);
	printf("  algorithm: %s\n", algorithm);
	printf("  type: %s\n",
	       key->key_class == HSM_KEY_CLASS_PRIVATE ? "private" : "public");
	printf("  uri: %s\n", uri);
	osal_free(uri);
	return true;
}

/* Build an OpenSSL public key from material exported by the HSM. */
static EVP_PKEY *_cli_evp_from_hsm_key(const hsm_public_key_t *key)
{
	const char *group;

	if (key->type == HSM_KEY_TYPE_RSA)
		return ossl_pkey_from_rsa_public(key->modulus,
						 key->modulus_length,
						 key->exponent,
						 key->exponent_length);
	if (key->type == HSM_KEY_TYPE_ML_DSA) {
		const char *algorithm = _cli_ml_dsa_algorithm_name(
			key->ml_dsa_parameter_set);

		if (algorithm == nullptr)
			return nullptr;
		return ossl_pkey_from_ml_dsa_public(algorithm, key->ml_dsa_key,
						    key->ml_dsa_key_length);
	}

	group = _cli_ec_group_name(key->ec_params, key->ec_params_length);
	if (group == nullptr)
		return nullptr;
	return ossl_pkey_from_ec_public(group, key->ec_point,
					key->ec_point_length);
}

static bool _cli_hsm_key_matches(const hsm_public_key_t *key,
				 EVP_PKEY *target)
{
	EVP_PKEY *candidate = _cli_evp_from_hsm_key(key);
	bool matches = ossl_pkey_equal(candidate, target);

	EVP_PKEY_free(candidate);
	return matches;
}

static bool _cli_load_search_key(const char *path, EVP_PKEY **key)
{
	unsigned char *data = nullptr;
	size_t length = 0;
	EVP_PKEY *parsed;

	*key = nullptr;
	if (!cli_read_file(path, &data, &length))
		return false;

	parsed = ossl_x509_load_public_key(data, length);
	osal_free(data);

	if (parsed == nullptr) {
		fprintf(stderr,
			"anyca_cli: %s is not a DER or PEM certificate, "
			"certificate request or public key\n",
			path);
		return false;
	}
	*key = parsed;
	return true;
}

static int _cli_hsm_list(cli_global_options_t *global)
{
	config_t *config = nullptr;
	int status = EXIT_FAILURE;

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}

	if (config->hsm_providers_count == 0)
		printf("No HSM providers are configured.\n");
	for (unsigned i = 0; i < config->hsm_providers_count; i++) {
		const config_hsm_provider_t *provider = &config->hsm_providers[i];

		if (i != 0)
			fputc('\n', stdout);
		printf("HSM provider %s\n",
		       provider->name != nullptr ? provider->name : "<unset>");
		printf("  library: %s\n",
		       provider->library != nullptr ? provider->library
						    : "<unset>");
		printf("  model: %s\n",
		       provider->model != nullptr ? provider->model
						  : "<unset>");
		printf("  serial: %s\n",
		       provider->serial != nullptr ? provider->serial
						   : "<unset>");
	}
	status = EXIT_SUCCESS;
	config_free(config);
	return status;
}

static int _cli_hsm_token_info(cli_global_options_t *global,
			       const cli_hsm_token_options_t *options)
{
	config_t *config = nullptr;
	const config_hsm_provider_t *provider;
	cli_hsm_session_t session = { 0 };
	struct hsm_module_info module_info;
	struct hsm_token_info token_info;
	hsm_status_t hsm_status;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->provider, "--provider")
	    || !cli_require_option(options->token, "--token"))
		return EXIT_FAILURE;

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	provider = cli_hsm_provider_find(config, options->provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			options->provider);
		goto done;
	}

	if (!cli_hsm_session_open(&session, provider, options->token, nullptr))
		goto done;

	hsm_status = hsm_module_get_info(session.module, &module_info);
	if (hsm_status != HSM_OK) {
		cli_hsm_log("hsm_module_get_info", hsm_status);
		goto done;
	}
	hsm_status = hsm_get_token_info(session.token, &token_info);
	if (hsm_status != HSM_OK) {
		cli_hsm_log("hsm_get_token_info", hsm_status);
		goto done;
	}

	printf("Provider: %s\n", provider->name);
	printf("  library: %s\n",
	       provider->library != nullptr ? provider->library : "<unset>");
	printf("  module: %s %s (Cryptoki %lu.%lu, library %lu.%lu)\n",
	       module_info.manufacturer, module_info.description,
	       module_info.cryptoki_version_major,
	       module_info.cryptoki_version_minor,
	       module_info.library_version_major,
	       module_info.library_version_minor);
	printf("Token: %s\n", token_info.label);
	printf("  manufacturer: %s\n", token_info.manufacturer);
	printf("  model: %s\n", token_info.model);
	printf("  serial: %s\n", token_info.serial);
	printf("  flags: 0x%lx\n", token_info.flags);
	printf("  logged in: %s\n", token_info.logged_in ? "yes" : "no");
	printf("  sessions: %zu\n", token_info.session_count);
	status = EXIT_SUCCESS;

done:
	cli_hsm_session_close(&session);
	config_free(config);
	return status;
}

static int _cli_hsm_key_info(cli_global_options_t *global,
			     const cli_hsm_key_options_t *options)
{
	config_t *config = nullptr;
	cli_hsm_uri_t uri = { 0 };
	cli_hsm_session_t session = { 0 };
	const config_hsm_provider_t *provider;
	hsm_public_key_t key = { 0 };
	hsm_status_t hsm_status;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->key_uri, "--key-uri"))
		return EXIT_FAILURE;
	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	if (!_cli_hsm_key_resolve(config, options->key_uri, &uri, "--key-uri"))
		goto done;

	provider = cli_hsm_provider_find(config, uri.key.hsm_provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			uri.key.hsm_provider);
		goto done;
	}
	if (!cli_hsm_session_open(&session, provider, uri.key.token_label,
				  uri.key.pin))
		goto done;

	hsm_status = hsm_get_public_key(session.token, uri.key.key_label, &key);
	if (hsm_status != HSM_OK) {
		cli_hsm_log("hsm_get_public_key", hsm_status);
		goto done;
	}

	printf("Key: %s\n", uri.key.key_label);
	printf("  provider: %s\n", uri.key.hsm_provider);
	printf("  token: %s\n", uri.key.token_label);
	if (key.type == HSM_KEY_TYPE_RSA) {
		printf("  type: RSA\n");
		printf("  bits: %u\n",
		       _cli_integer_bits(key.modulus, key.modulus_length));
	} else if (key.type == HSM_KEY_TYPE_ML_DSA) {
		const char *algorithm = _cli_ml_dsa_algorithm_name(
			key.ml_dsa_parameter_set);

		printf("  type: ML-DSA\n");
		printf("  parameter-set: %s\n",
		       algorithm != nullptr ? algorithm : "<unknown>");
		printf("  public-key: %zu bytes\n", key.ml_dsa_key_length);
	} else {
		const char *curve = _cli_ec_curve_name(key.ec_params,
						       key.ec_params_length);

		printf("  type: EC\n");
		printf("  curve: %s\n",
		       curve != nullptr ? curve : "<unknown>");
		printf("  point: %zu bytes\n", key.ec_point_length);
	}
	status = EXIT_SUCCESS;

done:
	hsm_public_key_free(&key);
	cli_hsm_session_close(&session);
	cli_hsm_uri_free(&uri);
	config_free(config);
	return status;
}

static int _cli_hsm_key_list(cli_global_options_t *global,
			     const cli_hsm_key_list_options_t *options)
{
	config_t *config = nullptr;
	const config_hsm_provider_t *provider;
	cli_hsm_session_t session = { 0 };
	hsm_key_object_t *objects = nullptr;
	size_t count = 0;
	const char *pin = nullptr;
	char *pin_storage = nullptr;
	hsm_status_t hsm_status;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->provider, "--provider")
	    || !cli_require_option(options->token, "--token"))
		return EXIT_FAILURE;
	if (!_cli_hsm_pin(options->pin_source, options->pin_value, &pin,
			  &pin_storage))
		return EXIT_FAILURE;

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		goto done;
	}
	provider = cli_hsm_provider_find(config, options->provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			options->provider);
		goto done;
	}
	if (!cli_hsm_session_open(&session, provider, options->token, pin))
		goto done;

	hsm_status = hsm_list_key_objects(session.token, &objects, &count);
	if (hsm_status != HSM_OK) {
		cli_hsm_log("hsm_list_key_objects", hsm_status);
		goto done;
	}
	if (count > 1)
		qsort(objects, count, sizeof *objects, _cli_key_object_compare);

	if (count == 0)
		printf("No keys found in token %s.\n", options->token);
	for (size_t i = 0; i < count; i++) {
		if (i != 0)
			fputc('\n', stdout);
		if (!_cli_print_key_object(provider->name, options->token,
					   &objects[i], objects, count))
			goto done;
	}
	status = EXIT_SUCCESS;

done:
	hsm_key_object_list_free(objects, count);
	cli_hsm_session_close(&session);
	osal_secure_free(pin_storage);
	config_free(config);
	return status;
}

static int _cli_hsm_fetch_uri(cli_global_options_t *global,
			      const cli_hsm_fetch_uri_options_t *options)
{
	config_t *config = nullptr;
	const config_hsm_provider_t *provider;
	char *uri;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->provider, "--provider")
	    || !cli_require_option(options->token, "--token")
	    || !cli_require_option(options->label, "--label"))
		return EXIT_FAILURE;
	if (options->pin_source != nullptr && options->pin_value != nullptr) {
		fprintf(stderr,
			"anyca_cli: --pin-source and --pin-value are mutually "
			"exclusive\n");
		return EXIT_FAILURE;
	}

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	provider = cli_hsm_provider_find(config, options->provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			options->provider);
		goto done;
	}

	uri = _cli_key_uri(provider->name, options->token, options->label,
			   options->pin_source, options->pin_value);
	if (uri == nullptr)
		goto done;
	printf("%s\n", uri);
	memset(uri, 0, strlen(uri));
	osal_free(uri);
	status = EXIT_SUCCESS;

done:
	config_free(config);
	return status;
}

static int _cli_hsm_search_key(cli_global_options_t *global,
			       const cli_hsm_search_options_t *options)
{
	config_t *config = nullptr;
	const config_hsm_provider_t *provider;
	cli_hsm_session_t session = { 0 };
	hsm_key_object_t *objects = nullptr;
	size_t count = 0;
	bool *matched = nullptr;
	const char *pin = nullptr;
	char *pin_storage = nullptr;
	EVP_PKEY *target = nullptr;
	hsm_status_t hsm_status;
	bool found = false;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->in_path, "--in")
	    || !cli_require_option(options->provider, "--provider")
	    || !cli_require_option(options->token, "--token"))
		return EXIT_FAILURE;
	if (!_cli_hsm_pin(options->pin_source, options->pin_value, &pin,
			  &pin_storage))
		return EXIT_FAILURE;
	if (!_cli_load_search_key(options->in_path, &target))
		goto done;

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		goto done;
	}
	provider = cli_hsm_provider_find(config, options->provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			options->provider);
		goto done;
	}
	if (!cli_hsm_session_open(&session, provider, options->token, pin))
		goto done;

	hsm_status = hsm_list_key_objects(session.token, &objects, &count);
	if (hsm_status != HSM_OK) {
		cli_hsm_log("hsm_list_key_objects", hsm_status);
		goto done;
	}
	if (count > 1)
		qsort(objects, count, sizeof *objects, _cli_key_object_compare);

	if (count > 0) {
		matched = osal_calloc(count, sizeof *matched);
		if (matched == nullptr) {
			fprintf(stderr, "anyca_cli: out of memory\n");
			goto done;
		}
	}

	for (size_t i = 0; i < count; i++) {
		bool seen = false;
		hsm_public_key_t public_key = { 0 };

		for (size_t j = 0; j < i; j++) {
			if (strcmp(objects[j].label, objects[i].label) == 0) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;

		hsm_status = hsm_get_public_key(session.token, objects[i].label,
						&public_key);
		if (hsm_status == HSM_OK) {
			if (_cli_hsm_key_matches(&public_key, target)) {
				for (size_t j = 0; j < count; j++) {
					if (strcmp(objects[j].label,
						   objects[i].label) == 0)
						matched[j] = true;
				}
			}
			hsm_public_key_free(&public_key);
		} else if (hsm_status != HSM_ERR_OBJECT_NOT_FOUND) {
			cli_hsm_log("hsm_get_public_key", hsm_status);
		}
	}

	for (size_t i = 0; i < count; i++) {
		if (!matched[i])
			continue;
		if (found)
			fputc('\n', stdout);
		if (!_cli_print_key_object(provider->name, options->token,
					   &objects[i], objects, count))
			goto done;
		found = true;
	}
	if (!found)
		printf("No matching key found.\n");
	if (pin == nullptr) {
		fflush(stdout);
		fprintf(stderr,
			"anyca_cli: no PIN supplied; matching private keys were "
			"not searched (use --pin-source or --pin-value)\n");
	}
	status = EXIT_SUCCESS;

done:
	EVP_PKEY_free(target);
	osal_free(matched);
	hsm_key_object_list_free(objects, count);
	cli_hsm_session_close(&session);
	osal_secure_free(pin_storage);
	config_free(config);
	return status;
}

static int _cli_hsm_keygen(cli_global_options_t *global,
			   const cli_hsm_key_options_t *options)
{
	config_t *config = nullptr;
	cli_hsm_uri_t uri = { 0 };
	const char *key_type;
	const char *ec_curve;
	unsigned int rsa_bits = 3072;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->key_uri, "--key-uri"))
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
	if (strcasecmp(key_type, "rsa") != 0
	    && strcasecmp(key_type, "ec") != 0
	    && strcasecmp(key_type, "ml-dsa-44") != 0
	    && strcasecmp(key_type, "ml-dsa-65") != 0
	    && strcasecmp(key_type, "ml-dsa-87") != 0) {
		fprintf(stderr, "anyca_cli: invalid --key-type: %s\n",
			key_type);
		return EXIT_FAILURE;
	}

	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	if (!_cli_hsm_key_resolve(config, options->key_uri, &uri, "--key-uri"))
		goto done;

	if (!cli_generate_key_pair(config, &uri.key, key_type, rsa_bits,
				   ec_curve)) {
		fprintf(stderr, "anyca_cli: cannot generate the key pair\n");
		goto done;
	}

	if (strcasecmp(key_type, "rsa") == 0)
		printf("Generated RSA key pair: %s (%u bits, provider %s, "
		       "token %s)\n",
		       uri.key.key_label, rsa_bits, uri.key.hsm_provider,
		       uri.key.token_label);
	else if (strcasecmp(key_type, "ec") == 0)
		printf("Generated EC key pair: %s (curve %s, provider %s, "
		       "token %s)\n",
		       uri.key.key_label, ec_curve, uri.key.hsm_provider,
		       uri.key.token_label);
	else
		printf("Generated ML-DSA key pair: %s (%s, provider %s, "
		       "token %s)\n",
		       uri.key.key_label, key_type, uri.key.hsm_provider,
		       uri.key.token_label);
	status = EXIT_SUCCESS;

done:
	cli_hsm_uri_free(&uri);
	config_free(config);
	return status;
}

static int _cli_hsm_keydel(cli_global_options_t *global,
			   const cli_hsm_key_options_t *options)
{
	config_t *config = nullptr;
	cli_hsm_uri_t uri = { 0 };
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->key_uri, "--key-uri"))
		return EXIT_FAILURE;
	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	if (!_cli_hsm_key_resolve(config, options->key_uri, &uri, "--key-uri"))
		goto done;

	if (!cli_delete_key_pair(config, &uri.key)) {
		fprintf(stderr, "anyca_cli: cannot delete the key pair\n");
		goto done;
	}

	printf("Deleted key pair: %s (provider %s, token %s)\n",
	       uri.key.key_label, uri.key.hsm_provider, uri.key.token_label);
	status = EXIT_SUCCESS;

done:
	cli_hsm_uri_free(&uri);
	config_free(config);
	return status;
}

static int _cli_hsm_pin_set(cli_global_options_t *global,
			    const cli_hsm_key_options_t *options)
{
	config_t *config = nullptr;
	cli_hsm_uri_t uri = { 0 };
	cli_hsm_session_t session = { 0 };
	const config_hsm_provider_t *provider;
	hsm_status_t hsm_status;
	int status = EXIT_FAILURE;

	if (!cli_require_option(options->key_uri, "--key-uri")
	    || !cli_require_option(options->new_pin, "--new-pin"))
		return EXIT_FAILURE;
	if (config_load(global->config_path, &config) != CONFIG_OK) {
		fprintf(stderr, "anyca_cli: cannot load configuration: %s\n",
			global->config_path);
		return EXIT_FAILURE;
	}
	if (!_cli_hsm_key_resolve(config, options->key_uri, &uri, "--key-uri"))
		goto done;

	provider = cli_hsm_provider_find(config, uri.key.hsm_provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			uri.key.hsm_provider);
		goto done;
	}
	if (!cli_hsm_session_open(&session, provider, uri.key.token_label,
				  uri.key.pin))
		goto done;

	hsm_status = hsm_token_set_pin(session.token, uri.key.pin,
				       options->new_pin);
	if (hsm_status != HSM_OK) {
		cli_hsm_log("hsm_token_set_pin", hsm_status);
		goto done;
	}

	printf("Changed user PIN: token %s (provider %s)\n",
	       uri.key.token_label, uri.key.hsm_provider);
	status = EXIT_SUCCESS;

done:
	cli_hsm_session_close(&session);
	cli_hsm_uri_free(&uri);
	config_free(config);
	return status;
}

static const cli_option_spec_t _cli_hsm_token_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_token_options_t, provider, "--provider"),
	CLI_OPTION_SPEC(cli_hsm_token_options_t, token, "--token"),
};

static const cli_option_spec_t _cli_hsm_key_list_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_key_list_options_t, provider, "--provider"),
	CLI_OPTION_SPEC(cli_hsm_key_list_options_t, token, "--token"),
	CLI_OPTION_SPEC(cli_hsm_key_list_options_t, pin_source, "--pin-source"),
	CLI_OPTION_SPEC(cli_hsm_key_list_options_t, pin_value, "--pin-value"),
};

static const cli_option_spec_t _cli_hsm_fetch_uri_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_fetch_uri_options_t, provider, "--provider"),
	CLI_OPTION_SPEC(cli_hsm_fetch_uri_options_t, token, "--token"),
	CLI_OPTION_SPEC(cli_hsm_fetch_uri_options_t, label, "--label"),
	CLI_OPTION_SPEC(cli_hsm_fetch_uri_options_t, pin_source, "--pin-source"),
	CLI_OPTION_SPEC(cli_hsm_fetch_uri_options_t, pin_value, "--pin-value"),
};

static const cli_option_spec_t _cli_hsm_search_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_search_options_t, in_path, "--in"),
	CLI_OPTION_SPEC(cli_hsm_search_options_t, provider, "--provider"),
	CLI_OPTION_SPEC(cli_hsm_search_options_t, token, "--token"),
	CLI_OPTION_SPEC(cli_hsm_search_options_t, pin_source, "--pin-source"),
	CLI_OPTION_SPEC(cli_hsm_search_options_t, pin_value, "--pin-value"),
};

static const cli_option_spec_t _cli_hsm_key_info_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_key_options_t, key_uri, "--key-uri"),
};

static const cli_option_spec_t _cli_hsm_keygen_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_key_options_t, key_uri, "--key-uri"),
	CLI_OPTION_SPEC(cli_hsm_key_options_t, key_type, "--key-type"),
	CLI_OPTION_SPEC(cli_hsm_key_options_t, rsa_bits, "--rsa-bits"),
	CLI_OPTION_SPEC(cli_hsm_key_options_t, ec_curve, "--ec-curve"),
};

static const cli_option_spec_t _cli_hsm_pin_set_specs[] = {
	CLI_OPTION_SPEC(cli_hsm_key_options_t, key_uri, "--key-uri"),
	CLI_OPTION_SPEC(cli_hsm_key_options_t, new_pin, "--new-pin"),
};

int cli_cmd_hsm_list(cli_global_options_t *global, int argc, char **argv,
		     int first)
{
	cli_hsm_list_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global, nullptr, 0,
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_list(global);
}

int cli_cmd_hsm_token_info(cli_global_options_t *global, int argc, char **argv,
			   int first)
{
	cli_hsm_token_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_token_specs,
				  CLI_OPTION_COUNT(_cli_hsm_token_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_token_info(global, &options);
}

int cli_cmd_hsm_key_list(cli_global_options_t *global, int argc, char **argv,
			 int first)
{
	cli_hsm_key_list_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_key_list_specs,
				  CLI_OPTION_COUNT(_cli_hsm_key_list_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_key_list(global, &options);
}

int cli_cmd_hsm_fetch_uri(cli_global_options_t *global, int argc, char **argv,
			  int first)
{
	cli_hsm_fetch_uri_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_fetch_uri_specs,
				  CLI_OPTION_COUNT(_cli_hsm_fetch_uri_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_fetch_uri(global, &options);
}

int cli_cmd_hsm_search_key(cli_global_options_t *global, int argc, char **argv,
			   int first)
{
	cli_hsm_search_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_search_specs,
				  CLI_OPTION_COUNT(_cli_hsm_search_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_search_key(global, &options);
}

int cli_cmd_hsm_key_info(cli_global_options_t *global, int argc, char **argv,
			 int first)
{
	cli_hsm_key_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_key_info_specs,
				  CLI_OPTION_COUNT(_cli_hsm_key_info_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_key_info(global, &options);
}

int cli_cmd_hsm_keygen(cli_global_options_t *global, int argc, char **argv,
		       int first)
{
	cli_hsm_key_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_keygen_specs,
				  CLI_OPTION_COUNT(_cli_hsm_keygen_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_keygen(global, &options);
}

int cli_cmd_hsm_keydel(cli_global_options_t *global, int argc, char **argv,
		       int first)
{
	cli_hsm_key_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_key_info_specs,
				  CLI_OPTION_COUNT(_cli_hsm_key_info_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_keydel(global, &options);
}

int cli_cmd_hsm_pin_set(cli_global_options_t *global, int argc, char **argv,
			int first)
{
	cli_hsm_key_options_t options = { 0 };
	cli_parse_result_t parse;

	parse = cli_parse_options(argc, argv, first, global,
				  _cli_hsm_pin_set_specs,
				  CLI_OPTION_COUNT(_cli_hsm_pin_set_specs),
				  &options);
	CLI_PARSE_OR_RETURN(parse, global);
	return _cli_hsm_pin_set(global, &options);
}
