/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

/*
 * Configuration loader.
 *
 * The file is parsed with libyaml's document API.  yaml_parser_load() builds
 * a node tree; the helpers below validate that tree against the AnyCA
 * configuration schema.  Every error identifies the file, line and column of
 * the offending node.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <yaml.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>

#include <anyca/config.h>

struct _parse_context {
	yaml_document_t *document;
	const char *path;
	bool out_of_memory;
};

struct _map_value {
	yaml_node_t *node;
	bool found;
};

/* Diagnostics */

static void _error_at(const struct _parse_context *context,
		      const yaml_node_t *node, const char *format, ...)
{
	char message[512];
	va_list arguments;

	va_start(arguments, format);
	vsnprintf(message, sizeof message, format, arguments);
	va_end(arguments);

	if (node != nullptr)
		LOGE("%s:%zu:%zu: %s", context->path,
		     node->start_mark.line + 1,
		     node->start_mark.column + 1, message);
	else
		LOGE("%s: %s", context->path, message);
}

/* Node helpers */

static bool _is_scalar(const yaml_node_t *node)
{
	return node != nullptr && node->type == YAML_SCALAR_NODE;
}

static bool _scalar_equals(const yaml_node_t *node, const char *text)
{
	size_t length;

	if (!_is_scalar(node))
		return false;

	length = strlen(text);
	return node->data.scalar.length == length
	       && memcmp(node->data.scalar.value, text, length) == 0;
}

/* A plain empty scalar and the usual YAML null spellings mean "no value". */
static bool _scalar_is_null(const yaml_node_t *node)
{
	if (!_is_scalar(node)
	    || node->data.scalar.style != YAML_PLAIN_SCALAR_STYLE)
		return false;

	if (node->data.scalar.length == 0)
		return true;

	return _scalar_equals(node, "~") || _scalar_equals(node, "null")
	       || _scalar_equals(node, "Null") || _scalar_equals(node, "NULL");
}

static bool _expect_mapping(const struct _parse_context *context,
			    yaml_node_t *node, const char *what)
{
	if (node == nullptr || node->type != YAML_MAPPING_NODE) {
		_error_at(context, node, "%s must be a mapping", what);
		return false;
	}
	return true;
}

static bool _map_lookup(const struct _parse_context *context,
			yaml_node_t *mapping, const char *key,
			struct _map_value *result)
{
	result->node = nullptr;
	result->found = false;

	for (yaml_node_pair_t *pair = mapping->data.mapping.pairs.start;
	     pair < mapping->data.mapping.pairs.top; pair++) {
		yaml_node_t *key_node =
			yaml_document_get_node(context->document, pair->key);
		yaml_node_t *value_node =
			yaml_document_get_node(context->document, pair->value);

		if (!_is_scalar(key_node)) {
			_error_at(context, key_node,
				  "mapping keys must be scalars");
			return false;
		}
		if (!_scalar_equals(key_node, key))
			continue;
		if (result->found) {
			_error_at(context, key_node, "duplicate key '%s'", key);
			return false;
		}
		if (value_node == nullptr) {
			_error_at(context, key_node, "key '%s' has no value",
				  key);
			return false;
		}
		result->found = true;
		result->node = value_node;
	}

	return true;
}

static bool _map_check_keys(const struct _parse_context *context,
			    yaml_node_t *mapping,
			    const char *const *keys, size_t key_count)
{
	for (yaml_node_pair_t *pair = mapping->data.mapping.pairs.start;
	     pair < mapping->data.mapping.pairs.top; pair++) {
		yaml_node_t *key_node =
			yaml_document_get_node(context->document, pair->key);
		bool known = false;

		if (!_is_scalar(key_node)) {
			_error_at(context, key_node,
				  "mapping keys must be scalars");
			return false;
		}

		for (size_t i = 0; i < key_count; i++) {
			if (_scalar_equals(key_node, keys[i])) {
				known = true;
				break;
			}
		}
		if (!known) {
			_error_at(context, key_node, "unknown key '%s'",
				  key_node->data.scalar.value);
			return false;
		}
	}

	return true;
}

/* Scalar parsers */

static bool _parse_string(struct _parse_context *context,
			  yaml_node_t *node, const char *what,
			  size_t min_length, bool optional, char **out)
{
	size_t length;
	char *copy;

	*out = nullptr;
	if (node == nullptr)
		return true;
	if (!_is_scalar(node)) {
		_error_at(context, node, "%s must be a string", what);
		return false;
	}
	if (_scalar_is_null(node)) {
		if (optional)
			return true;
		_error_at(context, node, "%s must not be null or empty", what);
		return false;
	}

	length = node->data.scalar.length;
	if (length < min_length) {
		_error_at(context, node, "%s must not be empty", what);
		return false;
	}
	if (memchr(node->data.scalar.value, '\0', length) != nullptr) {
		_error_at(context, node, "%s must not contain NUL bytes", what);
		return false;
	}

	copy = osal_malloc(length + 1);
	if (copy == nullptr) {
		context->out_of_memory = true;
		_error_at(context, node, "%s: out of memory", what);
		return false;
	}
	memcpy(copy, node->data.scalar.value, length);
	copy[length] = '\0';
	*out = copy;
	return true;
}

static bool _parse_uint(const struct _parse_context *context,
			yaml_node_t *node, const char *what,
			unsigned long long maximum, bool optional,
			unsigned long long *out)
{
	size_t length;
	unsigned long long parsed = 0;

	*out = 0;
	if (node == nullptr)
		return true;
	if (!_is_scalar(node)) {
		_error_at(context, node, "%s must be an integer", what);
		return false;
	}
	if (_scalar_is_null(node)) {
		if (optional)
			return true;
		_error_at(context, node, "%s must be an integer", what);
		return false;
	}

	length = node->data.scalar.length;
	if (length == 0) {
		_error_at(context, node, "%s must be an integer", what);
		return false;
	}
	for (size_t i = 0; i < length; i++) {
		unsigned digit;

		if (node->data.scalar.value[i] < '0'
		    || node->data.scalar.value[i] > '9') {
			_error_at(context, node,
				  "%s must be a non-negative integer", what);
			return false;
		}
		digit = (unsigned)(node->data.scalar.value[i] - '0');
		if (parsed > (maximum - digit) / 10) {
			_error_at(context, node, "%s is out of range", what);
			return false;
		}
		parsed = parsed * 10 + digit;
	}

	*out = parsed;
	return true;
}

/* Sequence helpers */

static bool _parse_string_sequence(struct _parse_context *context,
				   yaml_node_t *node, const char *what,
				   size_t minimum, bool optional,
				   char ***out_items, unsigned *out_count)
{
	size_t count;
	char **items;

	*out_items = nullptr;
	*out_count = 0;
	if (node == nullptr)
		return true;
	if (optional && _scalar_is_null(node))
		return true;
	if (node->type != YAML_SEQUENCE_NODE) {
		_error_at(context, node, "%s must be a sequence", what);
		return false;
	}

	count = (size_t)(node->data.sequence.items.top
			 - node->data.sequence.items.start);
	if (count < minimum) {
		_error_at(context, node,
			  "%s must contain at least %zu entries", what,
			  minimum);
		return false;
	}
	if (count > (size_t)UINT_MAX) {
		_error_at(context, node, "%s has too many entries", what);
		return false;
	}
	if (count == 0)
		return true;

	items = osal_calloc(count, sizeof *items);
	if (items == nullptr) {
		context->out_of_memory = true;
		_error_at(context, node, "%s: out of memory", what);
		return false;
	}
	*out_items = items;
	*out_count = (unsigned)count;

	for (size_t i = 0; i < count; i++) {
		yaml_node_t *item = yaml_document_get_node(
			context->document, node->data.sequence.items.start[i]);

		if (item == nullptr) {
			_error_at(context, node, "%s[%zu] is missing", what, i);
			return false;
		}
		if (!_parse_string(context, item, what, 1, false, &items[i]))
			return false;
	}

	return true;
}

typedef bool (*_element_parse_fn)(struct _parse_context *context,
				  yaml_node_t *node, void *element);

static bool _parse_mapping_sequence(struct _parse_context *context,
				    yaml_node_t *node, const char *what,
				    size_t minimum, size_t element_size,
				    _element_parse_fn parse_element,
				    void **out_items, unsigned *out_count)
{
	size_t count;
	char *items;

	*out_items = nullptr;
	*out_count = 0;
	if (node == nullptr)
		return true;
	if (node->type != YAML_SEQUENCE_NODE) {
		_error_at(context, node, "%s must be a sequence", what);
		return false;
	}

	count = (size_t)(node->data.sequence.items.top
			 - node->data.sequence.items.start);
	if (count < minimum) {
		_error_at(context, node,
			  "%s must contain at least %zu entries", what,
			  minimum);
		return false;
	}
	if (count > (size_t)UINT_MAX) {
		_error_at(context, node, "%s has too many entries", what);
		return false;
	}
	if (count == 0)
		return true;

	items = osal_calloc(count, element_size);
	if (items == nullptr) {
		context->out_of_memory = true;
		_error_at(context, node, "%s: out of memory", what);
		return false;
	}
	*out_items = items;
	*out_count = (unsigned)count;

	for (size_t i = 0; i < count; i++) {
		yaml_node_t *item = yaml_document_get_node(
			context->document, node->data.sequence.items.start[i]);

		if (item == nullptr || item->type != YAML_MAPPING_NODE) {
			_error_at(context, item,
				  "%s[%zu] must be a mapping", what, i);
			return false;
		}
		if (!parse_element(context, item,
				   items + i * element_size))
			return false;
	}

	return true;
}

/* Store */

static bool _parse_store(struct _parse_context *context,
			 yaml_node_t *mapping, config_store_t *store)
{
	static const char *const keys[] = { "path" };
	struct _map_value value;

	if (!_map_lookup(context, mapping, "path", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key 'store.path'");
		return false;
	}
	if (!_parse_string(context, value.node, "store.path", 1, false,
			   &store->path))
		return false;

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

/* HTTP Server */

static bool _parse_http(struct _parse_context *context,
			yaml_node_t *mapping, config_http_t *http)
{
	static const char *const keys[] = {
		"address", "port", "max_connections", "requests_per_second",
		"request_burst",
	};
	struct _map_value value;
	unsigned long long number;

	if (!_map_lookup(context, mapping, "address", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key 'http.address'");
		return false;
	}
	if (!_parse_string(context, value.node, "http.address", 1, false,
			   &http->address))
		return false;

	if (!_map_lookup(context, mapping, "port", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping, "missing required key 'http.port'");
		return false;
	}
	if (!_parse_uint(context, value.node, "http.port", UINT16_MAX, false,
			 &number))
		return false;
	if (number == 0) {
		_error_at(context, value.node,
			  "http.port must be between 1 and 65535");
		return false;
	}
	http->port = (uint16_t)number;

	if (!_map_lookup(context, mapping, "max_connections", &value))
		return false;
	if (value.found) {
		if (!_parse_uint(context, value.node,
				 "http.max_connections", UINT32_MAX, true,
				 &number))
			return false;
		http->max_connections = (uint32_t)number;
	}

	if (!_map_lookup(context, mapping, "requests_per_second", &value))
		return false;
	if (value.found) {
		if (!_parse_uint(context, value.node,
				 "http.requests_per_second", UINT32_MAX, true,
				 &number))
			return false;
		http->requests_per_second = (uint32_t)number;
	}

	if (!_map_lookup(context, mapping, "request_burst", &value))
		return false;
	if (value.found) {
		if (!_parse_uint(context, value.node, "http.request_burst",
				 UINT32_MAX, true, &number))
			return false;
		http->request_burst = (uint32_t)number;
	}

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

/* HSM Providers */

static bool _parse_hsm_provider(struct _parse_context *context,
				yaml_node_t *mapping, void *element)
{
	config_hsm_provider_t *provider = element;
	static const char *const keys[] = { "name", "library", "model",
					    "serial" };
	struct _map_value value;

	if (!_map_lookup(context, mapping, "name", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key 'hsm_providers[].name'");
		return false;
	}
	if (!_parse_string(context, value.node, "hsm_providers[].name", 1,
			   false, &provider->name))
		return false;

	if (!_map_lookup(context, mapping, "library", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key 'hsm_providers[].library'");
		return false;
	}
	if (!_parse_string(context, value.node, "hsm_providers[].library", 1,
			   false, &provider->library))
		return false;

	if (!_map_lookup(context, mapping, "model", &value))
		return false;
	if (value.found
	    && !_parse_string(context, value.node, "hsm_providers[].model",
			      1, true, &provider->model))
		return false;

	if (!_map_lookup(context, mapping, "serial", &value))
		return false;
	if (value.found
	    && !_parse_string(context, value.node, "hsm_providers[].serial",
			      1, true, &provider->serial))
		return false;

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

/* Certificate Policies */

static bool _parse_policy_cps(struct _parse_context *context,
			      yaml_node_t *mapping, void *element)
{
	config_certificate_policy_cps_t *cps = element;
	static const char *const keys[] = { "oid", "uri" };
	struct _map_value value;

	if (!_map_lookup(context, mapping, "oid", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key "
			  "'certificate_policies[].cps[].oid'");
		return false;
	}
	if (!_parse_string(context, value.node,
			   "certificate_policies[].cps[].oid", 1, false,
			   &cps->oid))
		return false;

	if (!_map_lookup(context, mapping, "uri", &value))
		return false;
	if (value.found
	    && !_parse_string(context, value.node,
			      "certificate_policies[].cps[].uri", 1, true,
			      &cps->uri))
		return false;

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

static bool _parse_policy(struct _parse_context *context,
			  yaml_node_t *mapping, void *element)
{
	config_certificate_policy_t *policy = element;
	static const char *const keys[] = { "name", "cps" };
	struct _map_value value;

	if (!_map_lookup(context, mapping, "name", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key 'certificate_policies[].name'");
		return false;
	}
	if (!_parse_string(context, value.node,
			   "certificate_policies[].name", 1, false,
			   &policy->name))
		return false;

	if (!_map_lookup(context, mapping, "cps", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_mapping_sequence(
			    context, value.node,
			    "certificate_policies[].cps", 0,
			    sizeof(config_certificate_policy_cps_t),
			    _parse_policy_cps, (void **)&policy->cps,
			    &policy->cps_count))
			return false;
	}

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

/* Certificate Usages */

static bool _parse_usage(struct _parse_context *context,
			 yaml_node_t *mapping, void *element)
{
	config_certificate_usage_t *usage = element;
	static const char *const keys[] = {
		"name", "basic_usages", "enhanced_usage_oids",
	};
	struct _map_value value;

	if (!_map_lookup(context, mapping, "name", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key 'certificate_usages[].name'");
		return false;
	}
	if (!_parse_string(context, value.node,
			   "certificate_usages[].name", 1, false,
			   &usage->name))
		return false;

	if (!_map_lookup(context, mapping, "basic_usages", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_string_sequence(
			    context, value.node,
			    "certificate_usages[].basic_usages", 0, true,
			    &usage->basic_usages,
			    &usage->basic_usages_count))
			return false;
	}

	if (!_map_lookup(context, mapping, "enhanced_usage_oids", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_string_sequence(
			    context, value.node,
			    "certificate_usages[].enhanced_usage_oids", 0,
			    true, &usage->enhanced_usage_oids,
			    &usage->enhanced_usage_oids_count))
			return false;
	}

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

/* Certificate Templates */

static bool _parse_template_aia(struct _parse_context *context,
				yaml_node_t *mapping,
				config_certificate_template_aia_t *aia)
{
	static const char *const keys[] = { "issuer_uris", "ocsp_uris" };
	struct _map_value value;

	if (!_map_lookup(context, mapping, "issuer_uris", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_string_sequence(
			    context, value.node,
			    "certificate_templates[].aia.issuer_uris", 0,
			    true, &aia->issuer_uris,
			    &aia->issuer_uris_count))
			return false;
	}

	if (!_map_lookup(context, mapping, "ocsp_uris", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_string_sequence(
			    context, value.node,
			    "certificate_templates[].aia.ocsp_uris", 0, true,
			    &aia->ocsp_uris, &aia->ocsp_uris_count))
			return false;
	}

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

static bool _parse_template(struct _parse_context *context,
			    yaml_node_t *mapping, void *element)
{
	config_certificate_template_t *template = element;
	static const char *const keys[] = { "name", "aia", "crl_uris" };
	struct _map_value value;

	if (!_map_lookup(context, mapping, "name", &value))
		return false;
	if (!value.found) {
		_error_at(context, mapping,
			  "missing required key "
			  "'certificate_templates[].name'");
		return false;
	}
	if (!_parse_string(context, value.node,
			   "certificate_templates[].name", 1, false,
			   &template->name))
		return false;

	if (!_map_lookup(context, mapping, "aia", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_expect_mapping(context, value.node,
				     "'certificate_templates[].aia'"))
			return false;
		if (!_parse_template_aia(context, value.node,
					 &template->aia))
			return false;
	}

	if (!_map_lookup(context, mapping, "crl_uris", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_string_sequence(
			    context, value.node,
			    "certificate_templates[].crl_uris", 0, true,
			    &template->crl_uris,
			    &template->crl_uris_count))
			return false;
	}

	return _map_check_keys(context, mapping, keys,
			       sizeof keys / sizeof keys[0]);
}

/* Root Configuration */

static bool _parse_configuration(struct _parse_context *context,
				 yaml_node_t *root, config_t *config)
{
	static const char *const keys[] = {
		"store",
		"http",
		"crl_publish_path",
		"cacerts_publish_path",
		"hsm_providers",
		"certificate_policies",
		"certificate_usages",
		"certificate_templates",
	};
	struct _map_value value;

	if (!_expect_mapping(context, root, "the configuration document"))
		return false;

	if (!_map_lookup(context, root, "store", &value))
		return false;
	if (!value.found) {
		_error_at(context, root, "missing required key 'store'");
		return false;
	}
	if (!_expect_mapping(context, value.node, "'store'"))
		return false;
	if (!_parse_store(context, value.node, &config->store))
		return false;

	if (!_map_lookup(context, root, "http", &value))
		return false;
	if (!value.found) {
		_error_at(context, root, "missing required key 'http'");
		return false;
	}
	if (!_expect_mapping(context, value.node, "'http'"))
		return false;
	if (!_parse_http(context, value.node, &config->http))
		return false;

	if (!_map_lookup(context, root, "crl_publish_path", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)
	    && !_parse_string(context, value.node, "crl_publish_path", 0,
			      true, &config->crl_publish_path))
		return false;

	if (!_map_lookup(context, root, "cacerts_publish_path", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)
	    && !_parse_string(context, value.node, "cacerts_publish_path", 0,
			      true, &config->cacerts_publish_path))
		return false;

	if (!_map_lookup(context, root, "hsm_providers", &value))
		return false;
	if (!value.found) {
		_error_at(context, root,
			  "missing required key 'hsm_providers'");
		return false;
	}
	if (!_parse_mapping_sequence(context, value.node, "hsm_providers", 1,
				     sizeof(config_hsm_provider_t),
				     _parse_hsm_provider,
				     (void **)&config->hsm_providers,
				     &config->hsm_providers_count))
		return false;

	if (!_map_lookup(context, root, "certificate_policies", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_mapping_sequence(
			    context, value.node, "certificate_policies", 0,
			    sizeof(config_certificate_policy_t),
			    _parse_policy,
			    (void **)&config->certificate_policies,
			    &config->certificate_policies_count))
			return false;
	}

	if (!_map_lookup(context, root, "certificate_usages", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_mapping_sequence(
			    context, value.node, "certificate_usages", 0,
			    sizeof(config_certificate_usage_t),
			    _parse_usage,
			    (void **)&config->certificate_usages,
			    &config->certificate_usages_count))
			return false;
	}

	if (!_map_lookup(context, root, "certificate_templates", &value))
		return false;
	if (value.found && !_scalar_is_null(value.node)) {
		if (!_parse_mapping_sequence(
			    context, value.node, "certificate_templates", 0,
			    sizeof(config_certificate_template_t),
			    _parse_template,
			    (void **)&config->certificate_templates,
			    &config->certificate_templates_count))
			return false;
	}

	return _map_check_keys(context, root, keys,
			       sizeof keys / sizeof keys[0]);
}

/* Public API */

/* Configuration files are small; bound both the input size and nesting. */
#define CONFIG_MAX_FILE_SIZE (1024 * 1024)
#define CONFIG_MAX_DEPTH 64

/*
 * Validate structural bounds before yaml_parser_load() builds the document
 * tree.  Deeply nested input makes the document builder superlinear, and
 * aliases let a small file expand into an arbitrarily large tree, so both are
 * rejected here.
 */
static bool _yaml_preflight(FILE *file, const char *path)
{
	yaml_parser_t parser;
	yaml_event_t event;
	size_t depth = 0;
	bool ok = true;

	if (!yaml_parser_initialize(&parser)) {
		LOGE("cannot initialize the YAML parser");
		return false;
	}
	yaml_parser_set_input_file(&parser, file);

	for (;;) {
		bool stream_end;

		if (!yaml_parser_parse(&parser, &event)) {
			LOGE("%s: cannot parse YAML", path);
			ok = false;
			break;
		}

		stream_end = event.type == YAML_STREAM_END_EVENT;

		switch (event.type) {
		case YAML_SEQUENCE_START_EVENT:
		case YAML_MAPPING_START_EVENT:
			if (++depth > CONFIG_MAX_DEPTH) {
				LOGE("%s: YAML nesting exceeds %d levels", path,
				     CONFIG_MAX_DEPTH);
				ok = false;
			}
			break;
		case YAML_SEQUENCE_END_EVENT:
		case YAML_MAPPING_END_EVENT:
			if (depth > 0)
				depth--;
			break;
		case YAML_ALIAS_EVENT:
			LOGE("%s: YAML aliases are not supported", path);
			ok = false;
			break;
		case YAML_STREAM_END_EVENT:
			break;
		default:
			break;
		}

		yaml_event_delete(&event);
		if (!ok || stream_end)
			break;
	}

	yaml_parser_delete(&parser);
	rewind(file);
	return ok;
}

config_err_t config_load(const char *path, config_t **out)
{
	FILE *file;
	yaml_parser_t parser;
	yaml_document_t document;
	yaml_node_t *root;
	config_t *config;
	struct _parse_context context;
	config_err_t result;

	if (path == nullptr || out == nullptr)
		return CONFIG_ERR_ARGUMENT;

	*out = nullptr;

	file = fopen(path, "rb");
	if (file == nullptr) {
		LOGE("cannot open configuration file %s: %s", path,
		     strerror(errno));
		return CONFIG_ERR_FILE_OPEN;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		LOGE("%s: cannot determine the configuration file size", path);
		fclose(file);
		return CONFIG_ERR_LOAD_FAILED;
	}
	{
		long size = ftell(file);

		if (size < 0 || (unsigned long) size > CONFIG_MAX_FILE_SIZE) {
			LOGE("%s: configuration file exceeds %d bytes", path,
			     CONFIG_MAX_FILE_SIZE);
			fclose(file);
			return CONFIG_ERR_LOAD_FAILED;
		}
	}
	rewind(file);

	if (!_yaml_preflight(file, path)) {
		fclose(file);
		return CONFIG_ERR_LOAD_FAILED;
	}

	if (!yaml_parser_initialize(&parser)) {
		LOGE("cannot initialize the YAML parser");
		fclose(file);
		return CONFIG_ERR_MEMORY;
	}
	yaml_parser_set_input_file(&parser, file);

	if (!yaml_parser_load(&parser, &document)) {
		if (parser.problem != nullptr)
			LOGE("%s:%zu:%zu: %s", path,
			     parser.problem_mark.line + 1,
			     parser.problem_mark.column + 1,
			     parser.problem);
		else
			LOGE("%s: cannot parse YAML", path);
		if (parser.context != nullptr)
			LOGE("%s: %s", path, parser.context);

		result = parser.error == YAML_MEMORY_ERROR
				 ? CONFIG_ERR_MEMORY
				 : CONFIG_ERR_LOAD_FAILED;
		yaml_parser_delete(&parser);
		fclose(file);
		return result;
	}

	/*
	 * A second document (anything after "---") is rejected instead of
	 * being silently ignored: a stray duplicate configuration must not
	 * leave the service running with the first one.
	 */
	{
		yaml_document_t extra_document;
		bool extra_root;

		if (!yaml_parser_load(&parser, &extra_document)) {
			LOGE("%s: cannot parse the YAML stream", path);
			result = parser.error == YAML_MEMORY_ERROR
					 ? CONFIG_ERR_MEMORY
					 : CONFIG_ERR_LOAD_FAILED;
			yaml_document_delete(&document);
			yaml_parser_delete(&parser);
			fclose(file);
			return result;
		}
		extra_root = yaml_document_get_root_node(&extra_document)
			     != nullptr;
		yaml_document_delete(&extra_document);
		if (extra_root) {
			LOGE("%s: multiple YAML documents are not supported",
			     path);
			yaml_document_delete(&document);
			yaml_parser_delete(&parser);
			fclose(file);
			return CONFIG_ERR_LOAD_FAILED;
		}
	}

	root = yaml_document_get_root_node(&document);
	if (root == nullptr) {
		LOGE("configuration file %s is empty", path);
		yaml_document_delete(&document);
		yaml_parser_delete(&parser);
		fclose(file);
		return CONFIG_ERR_LOAD_FAILED;
	}

	config = osal_calloc(1, sizeof *config);
	if (config == nullptr) {
		LOGE("out of memory while loading %s", path);
		yaml_document_delete(&document);
		yaml_parser_delete(&parser);
		fclose(file);
		return CONFIG_ERR_MEMORY;
	}

	context = (struct _parse_context){
		.document = &document,
		.path = path,
		.out_of_memory = false,
	};

	if (!_parse_configuration(&context, root, config)) {
		result = context.out_of_memory ? CONFIG_ERR_MEMORY
					       : CONFIG_ERR_LOAD_FAILED;
		config_free(config);
	} else {
		*out = config;
		result = CONFIG_OK;
	}

	yaml_document_delete(&document);
	yaml_parser_delete(&parser);
	fclose(file);

	return result;
}

static void _free_strings(char **items, unsigned count)
{
	if (items == nullptr)
		return;

	for (unsigned i = 0; i < count; i++)
		osal_free(items[i]);
	osal_free(items);
}

void config_free(config_t *config)
{
	if (config == nullptr)
		return;

	osal_free(config->store.path);
	osal_free(config->http.address);
	osal_free(config->crl_publish_path);
	osal_free(config->cacerts_publish_path);

	for (unsigned i = 0; i < config->hsm_providers_count; i++) {
		config_hsm_provider_t *provider = &config->hsm_providers[i];

		osal_free(provider->name);
		osal_free(provider->library);
		osal_free(provider->model);
		osal_free(provider->serial);
	}
	osal_free(config->hsm_providers);

	for (unsigned i = 0; i < config->certificate_policies_count; i++) {
		config_certificate_policy_t *policy =
			&config->certificate_policies[i];

		osal_free(policy->name);
		for (unsigned j = 0; j < policy->cps_count; j++) {
			osal_free(policy->cps[j].oid);
			osal_free(policy->cps[j].uri);
		}
		osal_free(policy->cps);
	}
	osal_free(config->certificate_policies);

	for (unsigned i = 0; i < config->certificate_usages_count; i++) {
		config_certificate_usage_t *usage =
			&config->certificate_usages[i];

		osal_free(usage->name);
		_free_strings(usage->basic_usages,
			      usage->basic_usages_count);
		_free_strings(usage->enhanced_usage_oids,
			      usage->enhanced_usage_oids_count);
	}
	osal_free(config->certificate_usages);

	for (unsigned i = 0; i < config->certificate_templates_count; i++) {
		config_certificate_template_t *template =
			&config->certificate_templates[i];

		osal_free(template->name);
		_free_strings(template->aia.issuer_uris,
			      template->aia.issuer_uris_count);
		_free_strings(template->aia.ocsp_uris,
			      template->aia.ocsp_uris_count);
		_free_strings(template->crl_uris,
			      template->crl_uris_count);
	}
	osal_free(config->certificate_templates);

	osal_free(config);
}
