/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <threads.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <anyca/osal/file.h>
#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>
#include <anyca/osal/thread.h>

#include <anyca/ossl/x509.h>

#include <anyca/ca.h>
#include <anyca/config.h>
#include <anyca/crl.h>
#include <anyca/hsm.h>
#include <anyca/store.h>
#include <anyca/version.h>

#include <anyca/core.h>

static bool g_initialized;
static char *g_crl_publish_path;
static char *g_cacerts_publish_path;

/*
 * nextUpdate used when a CA disables periodic publication.  The CRL must
 * still expire so clients stop trusting it; the scheduler stays off.
 */
#define CORE_CRL_DEFAULT_PERIOD_MIN (7U * 24U * 60U)

/* Configuration passed to core_init(); read again by the session refresh. */
static const config_t *g_config;

/* Store data version observed at the last successful CA load.  Atomic because
 * it is read before the session lock is taken. */
static _Atomic uint64_t g_store_data_version;
static _Atomic bool g_store_data_version_valid;

/*
 * Serializes core and store access in a multi-threaded program.
 *
 * Sessions normally share the lock: readers only inspect the stable CA
 * objects, so OCSP signing and CRL publication can run concurrently.  The
 * session that notices a changed store version upgrades to exclusive access
 * and rebuilds the CA list; g_refresh_lock serializes that decision.
 */
#if defined(_WIN32)
static SRWLOCK g_session_lock = SRWLOCK_INIT;
#else
static pthread_rwlock_t g_session_lock;
#endif
static mtx_t g_refresh_lock;
static bool g_session_lock_initialized;

/* Which lock the current thread took in core_session_begin(). */
static OSAL_THREAD_LOCAL bool g_session_held;
static OSAL_THREAD_LOCAL bool g_session_exclusive;

/* One loaded PKCS #11 module, shared by every CA using that provider. */
typedef struct core_hsm_module {
	char *library;
	hsm_module_t *module;
} core_hsm_module_t;

static core_hsm_module_t *g_hsm_modules;
static size_t g_hsm_module_count;

/*
 * A loaded CA and the token handles opened for it.  An entry stays valid
 * until the next session reload replaces it or the core is released.
 */
typedef struct core_ca {
	ca_t *ca;
	hsm_token_t *token;
	hsm_token_t *ocsp_signer_token;
	/* CA identity in the store, assigned by core_init(). */
	store_ca_id_t store_id;
} core_ca_t;

static core_ca_t *g_cas;
static unsigned g_ca_count;

static bool _core_string_is_set(const char *value);

/* Report an HSM failure together with its thread-local detail. */
static void _core_log_hsm_failure(const char *what, hsm_status_t status)
{
	const struct hsm_error *error = hsm_get_last_error();

	LOGE("%s failed: %s: %s", what, hsm_status_to_string(status),
		   error->message);
}

/* Find the HSM provider referenced by a CA. */
static const config_hsm_provider_t *
_core_find_hsm_provider(const config_t *config, const char *name)
{
	if (name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < config->hsm_providers_count; i++) {
		if (config->hsm_providers[i].name != nullptr
		    && strcmp(config->hsm_providers[i].name, name) == 0)
			return &config->hsm_providers[i];
	}
	return nullptr;
}

/*
 * Return the PKCS #11 module configured for a provider, opening it on first
 * use.  Providers sharing a library path share one module instance.
 */
static hsm_module_t *_core_hsm_module_get(const config_t *config,
					  const char *provider_name)
{
	const config_hsm_provider_t *provider =
		_core_find_hsm_provider(config, provider_name);
	const struct hsm_config hsm_config = {
		.max_sessions_per_token = HSM_DEFAULT_MAX_SESSIONS,
	};
	struct hsm_config configured;
	core_hsm_module_t *grown;
	hsm_module_t *module = nullptr;
	char *library;
	hsm_status_t status;

	if (provider == nullptr) {
		LOGE("CA references unknown HSM provider \"%s\"",
		     provider_name != nullptr ? provider_name : "<unset>");
		return nullptr;
	}
	if (provider->library == nullptr || provider->library[0] == '\0') {
		LOGE("HSM provider \"%s\" has no library path",
		     provider_name);
		return nullptr;
	}

	for (size_t i = 0; i < g_hsm_module_count; i++) {
		if (strcmp(g_hsm_modules[i].library, provider->library) == 0)
			return g_hsm_modules[i].module;
	}

	configured = hsm_config;
	configured.module_path = provider->library;
	status = hsm_module_open(&configured, &module);
	if (status != HSM_OK) {
		_core_log_hsm_failure("hsm_module_open", status);
		return nullptr;
	}

	library = osal_malloc(strlen(provider->library) + 1);
	if (library == nullptr) {
		LOGE("Out of memory while recording an HSM module");
		(void) hsm_module_close(module);
		return nullptr;
	}
	strcpy(library, provider->library);

	grown = osal_realloc(g_hsm_modules,
			     (g_hsm_module_count + 1) * sizeof *grown);
	if (grown == nullptr) {
		LOGE("Out of memory while recording an HSM module");
		osal_free(library);
		(void) hsm_module_close(module);
		return nullptr;
	}
	g_hsm_modules = grown;
	g_hsm_modules[g_hsm_module_count].library = library;
	g_hsm_modules[g_hsm_module_count].module = module;
	g_hsm_module_count++;

	LOGI("Loaded HSM module: %s", provider->library);
	return module;
}

static void _core_hsm_shutdown(void)
{
	for (size_t i = 0; i < g_hsm_module_count; i++) {
		hsm_status_t status =
			hsm_module_close(g_hsm_modules[i].module);

		if (status != HSM_OK)
			_core_log_hsm_failure("hsm_module_close", status);
		osal_free(g_hsm_modules[i].library);
	}
	osal_free(g_hsm_modules);
	g_hsm_modules = nullptr;
	g_hsm_module_count = 0;
}

/*
 * Verify that a token key belongs to a certificate by signing fixed data and
 * checking the signature with the certificate public key.
 */
static bool _core_key_matches_certificate(hsm_token_t *token,
					  const char *key_label,
					  const char *pin,
					  X509 *certificate,
					  const char *name, const char *what)
{
	static const unsigned char challenge[] =
		"AnyCA startup key/certificate consistency check";
	hsm_public_key_t public_key = { 0 };
	hsm_sign_alg_t algorithm;
	unsigned char *signature = nullptr;
	size_t signature_length = 0;
	hsm_status_t status;
	bool matches;

	if (token == nullptr || key_label == nullptr || certificate == nullptr)
		return false;

	status = hsm_get_public_key(token, key_label, &public_key);
	if (status != HSM_OK) {
		_core_log_hsm_failure("hsm_get_public_key", status);
		return false;
	}

	switch (public_key.type) {
	case HSM_KEY_TYPE_RSA:
		algorithm = HSM_SIGN_RSA_PKCS1_SHA256;
		break;
	case HSM_KEY_TYPE_EC:
		algorithm = HSM_SIGN_ECDSA_SHA256;
		break;
	case HSM_KEY_TYPE_ML_DSA:
		switch (public_key.ml_dsa_parameter_set) {
		case HSM_ML_DSA_44:
			algorithm = HSM_SIGN_ML_DSA_44;
			break;
		case HSM_ML_DSA_65:
			algorithm = HSM_SIGN_ML_DSA_65;
			break;
		case HSM_ML_DSA_87:
			algorithm = HSM_SIGN_ML_DSA_87;
			break;
		default:
			LOGE("CA %s: unsupported ML-DSA parameter set for %s "
			     "key \"%s\"",
			     name, what, key_label);
			hsm_public_key_free(&public_key);
			return false;
		}
		break;
	default:
		LOGE("CA %s: unsupported key type for %s key \"%s\"", name,
		     what, key_label);
		hsm_public_key_free(&public_key);
		return false;
	}
	hsm_public_key_free(&public_key);

	status = hsm_sign_with_pin(token, algorithm, key_label, pin, challenge,
				   sizeof challenge - 1, nullptr, 0,
				   &signature_length);
	if (status != HSM_OK) {
		_core_log_hsm_failure("hsm_sign", status);
		return false;
	}
	signature = osal_malloc(signature_length);
	if (signature == nullptr) {
		LOGE("CA %s: out of memory while verifying %s key", name,
		     what);
		return false;
	}

	status = hsm_sign_with_pin(token, algorithm, key_label, pin, challenge,
				   sizeof challenge - 1, signature,
				   signature_length, &signature_length);
	if (status != HSM_OK) {
		_core_log_hsm_failure("hsm_sign", status);
		osal_free(signature);
		return false;
	}

	matches = ossl_x509_verify_data(certificate, challenge,
					sizeof challenge - 1, signature,
					signature_length);
	osal_free(signature);

	if (!matches)
		LOGE("CA %s: %s key \"%s\" does not match its certificate", name,
		     what, key_label);
	return matches;
}

/* Close the token handles held for one CA. */
static void _core_close_tokens(core_ca_t *runtime)
{
	hsm_token_close(runtime->ocsp_signer_token);
	hsm_token_close(runtime->token);
	runtime->ocsp_signer_token = nullptr;
	runtime->token = nullptr;
}

/*
 * Open and log in the CA and OCSP signing tokens, closing anything opened on
 * failure.  The OCSP signer key may use a different PKCS #11 module.
 */
static bool _core_open_ca_tokens(core_ca_t *runtime, const config_t *config)
{
	ca_t *ca = runtime->ca;
	const char *name = ca->name != nullptr ? ca->name : "<unnamed>";
	const char *ocsp_provider = _core_string_is_set(
					    ca->ocsp_signer_hsm_provider)
					    ? ca->ocsp_signer_hsm_provider
					    : ca->hsm_provider;
	const struct hsm_error *error;
	hsm_module_t *module;
	hsm_module_t *ocsp_module;
	hsm_status_t status;

	module = _core_hsm_module_get(config, ca->hsm_provider);
	if (module == nullptr)
		return false;

	status = hsm_token_open(module, ca->token_label, &runtime->token);
	if (status != HSM_OK) {
		error = hsm_get_last_error();
		LOGE("Cannot open HSM token \"%s\" for CA %s: %s: %s",
			   ca->token_label != nullptr ? ca->token_label
						      : "<unset>",
			   name, hsm_status_to_string(status), error->message);
		goto fail;
	}

	status = hsm_token_login(runtime->token, ca->pin);
	if (status != HSM_OK) {
		error = hsm_get_last_error();
		LOGE("Cannot log in to HSM token \"%s\" for CA %s: "
			   "%s: %s",
			   ca->token_label, name,
			   hsm_status_to_string(status), error->message);
		goto fail;
	}

	ocsp_module = _core_hsm_module_get(config, ocsp_provider);
	if (ocsp_module == nullptr)
		goto fail;

	status = hsm_token_open(ocsp_module, ca->ocsp_signer_token_label,
				&runtime->ocsp_signer_token);
	if (status != HSM_OK) {
		error = hsm_get_last_error();
		LOGE("Cannot open OCSP signer token \"%s\" for CA %s: "
			   "%s: %s",
			   ca->ocsp_signer_token_label != nullptr
				   ? ca->ocsp_signer_token_label
				   : "<unset>",
			   name, hsm_status_to_string(status), error->message);
		goto fail;
	}

	status = hsm_token_login(runtime->ocsp_signer_token,
				 ca->ocsp_signer_pin);
	if (status != HSM_OK) {
		error = hsm_get_last_error();
		LOGE("Cannot log in to OCSP signer token \"%s\" for "
			   "CA %s: %s: %s",
			   ca->ocsp_signer_token_label, name,
			   hsm_status_to_string(status), error->message);
		goto fail;
	}

	return true;

fail:
	_core_close_tokens(runtime);
	return false;
}

/* Allocate a copy of source in *destination.  NULL stays NULL. */
static bool _core_strdup(char **destination, const char *source)
{
	size_t length;

	*destination = nullptr;
	if (source == nullptr)
		return true;

	length = strlen(source) + 1;
	*destination = osal_malloc(length);
	if (*destination == nullptr)
		return false;
	memcpy(*destination, source, length);
	return true;
}

/* Duplicate a secret string into locked, wipe-on-free memory. */
static bool _core_secure_strdup(char **destination, const char *source)
{
	size_t length;

	*destination = nullptr;
	if (source == nullptr)
		return true;

	length = strlen(source) + 1;
	*destination = osal_secure_malloc(length);
	if (*destination == nullptr)
		return false;
	memcpy(*destination, source, length);
	return true;
}

/* Tell whether a required configuration string is present. */
static bool _core_string_is_set(const char *value)
{
	return value != nullptr && value[0] != '\0';
}

/*
 * Validate the YAML configuration.  CA records live in the store and are
 * checked separately by _core_apply_ca_configs().
 */
static bool _core_validate_config(const config_t *config)
{
	if (!_core_string_is_set(config->store.path)) {
		LOGE("Store path is not set");
		return false;
	}

	for (unsigned i = 0; i < config->hsm_providers_count; i++) {
		const config_hsm_provider_t *provider =
			&config->hsm_providers[i];

		if (!_core_string_is_set(provider->name)
		    || !_core_string_is_set(provider->library)) {
			LOGE("HSM provider %u has an empty name or "
				   "library",
				   i);
			return false;
		}

		for (unsigned j = 0; j < i; j++) {
			if (strcmp(provider->name,
				   config->hsm_providers[j].name) == 0) {
				LOGE("Duplicate HSM provider name \"%s\"",
					   provider->name);
				return false;
			}
		}
	}

	return true;
}

/*
 * CA settings copied from a store record and compared on reload.  The copy,
 * comparison and required-field checks are generated from these lists.
 *
 *   string: X(ca_field, store_field, required)
 *   blob:   X(ca_field, store_field, store_length_field)
 *   uint32: X(ca_field, store_field)
 *
 * Store-only fields (ocsp_signer_digest) and publication state (crl_number)
 * are deliberately absent.
 */
#define CORE_CA_STRING_SETTINGS(X) \
	X(name, name, true) \
	X(hsm_provider, hsm_provider, true) \
	X(token_label, token_label, true) \
	X(key_label, key_label, true) \
	X(ocsp_signer_hsm_provider, ocsp_signer_hsm_provider, false) \
	X(ocsp_signer_token_label, ocsp_signer_token_label, true) \
	X(ocsp_signer_key_label, ocsp_signer_key_label, true) \
	X(ocsp_responder_endpoint, ocsp_responder_endpoint, true)

/* PINs live in secure memory; they are copied and released separately. */
#define CORE_CA_PIN_SETTINGS(X) \
	X(pin, pin) \
	X(ocsp_signer_pin, ocsp_signer_pin)

#define CORE_CA_BLOB_SETTINGS(X) \
	X(ca_cert_der, ca_cert, ca_cert_length) \
	X(ocsp_signer_cert_der, ocsp_signer_cert, ocsp_signer_cert_length)

#define CORE_CA_UINT32_SETTINGS(X) \
	X(crl_publish_period_min, crl_publish_period_min) \
	X(ocsp_update_period_min, ocsp_update_period_min)

/* Tell whether the settings required to load a CA are present. */
static bool _core_required_ca_settings_present(
	const store_ca_config_t *source)
{
	bool present = true;

#define _CORE_REQUIRED_STRING(ca_field, store_field, required) \
	present = present \
		  && (!(required) || _core_string_is_set(source->store_field));
#define _CORE_REQUIRED_PIN(ca_field, store_field) \
	present = present && _core_string_is_set(source->store_field);
#define _CORE_REQUIRED_BLOB(ca_field, store_field, length_field) \
	present = present && source->store_field != nullptr \
		  && source->length_field != 0;

	CORE_CA_STRING_SETTINGS(_CORE_REQUIRED_STRING);
	CORE_CA_PIN_SETTINGS(_CORE_REQUIRED_PIN);
	CORE_CA_BLOB_SETTINGS(_CORE_REQUIRED_BLOB);

#undef _CORE_REQUIRED_STRING
#undef _CORE_REQUIRED_PIN
#undef _CORE_REQUIRED_BLOB

	return present;
}

/*
 * Validate one CA record loaded from the store.  A failing CA is reported and
 * skipped; other CAs keep starting.
 */
static bool _core_validate_ca(const config_t *config,
			      const store_ca_config_t *ca)
{
	if (!ca_name_is_valid(ca->name)) {
		LOGE("CA name is not valid: \"%s\"",
		     ca->name != nullptr ? ca->name : "");
		return false;
	}

	if (!_core_required_ca_settings_present(ca)) {
		LOGE("CA %s has incomplete settings",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		return false;
	}

	if (_core_find_hsm_provider(config, ca->hsm_provider) == nullptr) {
		LOGE("CA %s references unknown HSM provider \"%s\"", ca->name,
		     ca->hsm_provider);
		return false;
	}

	if (_core_string_is_set(ca->ocsp_signer_hsm_provider)
	    && _core_find_hsm_provider(config,
				       ca->ocsp_signer_hsm_provider) == nullptr) {
		LOGE("CA %s references unknown OCSP signer HSM provider \"%s\"",
		     ca->name, ca->ocsp_signer_hsm_provider);
		return false;
	}

	if (!ca_ocsp_responder_endpoint_is_valid(ca->ocsp_responder_endpoint)) {
		LOGE("CA %s has an invalid OCSP responder endpoint: \"%s\"",
		     ca->name,
		     ca->ocsp_responder_endpoint != nullptr
			     ? ca->ocsp_responder_endpoint
			     : "");
		return false;
	}

	return true;
}

/* Copy one byte buffer into an owned ca_blob_t. */
static bool _core_copy_blob(ca_blob_t *destination,
			    const unsigned char *source, size_t length)
{
	destination->data = nullptr;
	destination->length = 0;
	if (source == nullptr || length == 0)
		return true;

	destination->data = osal_malloc(length);
	if (destination->data == nullptr)
		return false;
	memcpy(destination->data, source, length);
	destination->length = length;
	return true;
}

/* Copy one CA record loaded from the store into its runtime object. */
static bool _core_copy_ca_settings(ca_t *ca,
				   const store_ca_config_t *source)
{
	bool ok = true;

#define _CORE_COPY_STRING(ca_field, store_field, required) \
	ok = _core_strdup(&ca->ca_field, source->store_field) && ok;
#define _CORE_COPY_PIN(ca_field, store_field) \
	ok = _core_secure_strdup(&ca->ca_field, source->store_field) && ok;
#define _CORE_COPY_BLOB(ca_field, store_field, length_field) \
	ok = _core_copy_blob(&ca->ca_field, source->store_field, \
			     source->length_field) \
	     && ok;
#define _CORE_COPY_UINT32(ca_field, store_field) \
	ca->ca_field = source->store_field;

	CORE_CA_STRING_SETTINGS(_CORE_COPY_STRING);
	CORE_CA_PIN_SETTINGS(_CORE_COPY_PIN);
	CORE_CA_BLOB_SETTINGS(_CORE_COPY_BLOB);
	CORE_CA_UINT32_SETTINGS(_CORE_COPY_UINT32);

#undef _CORE_COPY_STRING
#undef _CORE_COPY_PIN
#undef _CORE_COPY_BLOB
#undef _CORE_COPY_UINT32

	/* Mutable publication state, not part of the setting comparison. */
	ca->crl_number = source->crl_number;
	return ok;
}

/* Release the tokens and CA object held by one runtime entry. */
static void _core_release_ca_runtime(core_ca_t *runtime)
{
	if (runtime == nullptr)
		return;

	_core_close_tokens(runtime);
	ca_free(runtime->ca);
	runtime->ca = nullptr;
}

/*
 * Create one runtime CA from a store record, opening tokens and verifying
 * keys.  On failure the partial runtime is released and the CA is skipped.
 */
static bool _core_create_ca(const config_t *config,
			    const store_ca_config_t *source,
			    core_ca_t *runtime)
{
	const char *name = source->name != nullptr ? source->name : "<unnamed>";
	ca_t *ca;

	memset(runtime, 0, sizeof *runtime);

	if (!_core_validate_ca(config, source)) {
		LOGE("Skipping CA %s", name);
		return false;
	}

	ca = ca_new();
	if (ca == nullptr) {
		LOGE("Failed to allocate CA %s; skipping it", name);
		return false;
	}
	runtime->ca = ca;
	if (!_core_copy_ca_settings(ca, source)) {
		LOGE("Failed to copy the settings of CA %s; skipping it", name);
		goto fail;
	}
	if (!_core_open_ca_tokens(runtime, config)) {
		LOGE("Skipping CA %s", name);
		goto fail;
	}
	if (!ca_load_certificate(ca)) {
		LOGE("Failed to load CA %s; skipping it", name);
		goto fail;
	}
	if (!_core_key_matches_certificate(runtime->token, ca->key_label,
					   ca->pin, ca->certificate, name,
					   "CA")) {
		LOGE("Skipping CA %s", name);
		goto fail;
	}
	if (!_core_key_matches_certificate(
		    runtime->ocsp_signer_token, ca->ocsp_signer_key_label,
		    ca->ocsp_signer_pin, ca->ocsp_signer_certificate, name,
		    "OCSP signer")) {
		LOGE("Skipping CA %s", name);
		goto fail;
	}
	if (store_ca_register(ca->name, ca->spki_hash_sha256.data,
			      ca->spki_hash_sha256.length,
			      &runtime->store_id) != STORE_OK) {
		LOGE("Failed to register CA %s in the store; skipping it", name);
		goto fail;
	}

	LOGI("Loaded CA: %s (store id %lld)", ca->name,
	     (long long) runtime->store_id);
	return true;

fail:
	_core_close_tokens(runtime);
	ca_free(ca);
	runtime->ca = nullptr;
	return false;
}

/* Find the runtime entry for a CA name. */
static core_ca_t *_core_find_runtime_by_name(const char *name)
{
	if (name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < g_ca_count; i++) {
		if (g_cas[i].ca != nullptr && g_cas[i].ca->name != nullptr
		    && strcmp(g_cas[i].ca->name, name) == 0)
			return &g_cas[i];
	}
	return nullptr;
}

/* Compare two optional settings strings; NULL and "" are equivalent. */
static bool _core_strings_equal(const char *left, const char *right)
{
	if (left == nullptr)
		left = "";
	if (right == nullptr)
		right = "";
	return strcmp(left, right) == 0;
}

/* Compare a stored DER blob with a store record field. */
static bool _core_blob_equal(const ca_blob_t *blob,
			     const unsigned char *data, size_t length)
{
	if (blob->length != length)
		return false;
	if (length == 0)
		return true;
	return blob->data != nullptr && data != nullptr
		&& memcmp(blob->data, data, length) == 0;
}

/* Tell whether a runtime CA already holds the settings in a store record. */
static bool _core_settings_equal(const ca_t *ca,
				 const store_ca_config_t *source)
{
#define _CORE_EQ_STRING(ca_field, store_field, required) \
	&& _core_strings_equal(ca->ca_field, source->store_field)
#define _CORE_EQ_PIN(ca_field, store_field) \
	&& _core_strings_equal(ca->ca_field, source->store_field)
#define _CORE_EQ_BLOB(ca_field, store_field, length_field) \
	&& _core_blob_equal(&ca->ca_field, source->store_field, \
			    source->length_field)
#define _CORE_EQ_UINT32(ca_field, store_field) \
	&& ca->ca_field == source->store_field

	return true
		CORE_CA_STRING_SETTINGS(_CORE_EQ_STRING)
		CORE_CA_PIN_SETTINGS(_CORE_EQ_PIN)
		CORE_CA_BLOB_SETTINGS(_CORE_EQ_BLOB)
		CORE_CA_UINT32_SETTINGS(_CORE_EQ_UINT32)
		;

#undef _CORE_EQ_STRING
#undef _CORE_EQ_PIN
#undef _CORE_EQ_BLOB
#undef _CORE_EQ_UINT32
}

/*
 * Replace the runtime CA list with the store records.
 *
 * Unchanged CAs keep their runtime objects and token handles; changed CAs are
 * rebuilt, and a failed rebuild keeps the previous runtime.  Entries with no
 * store record are released.  Returns false only when the new array cannot be
 * allocated, leaving the current state untouched.
 */
static bool _core_apply_ca_configs(const config_t *config,
				   const store_ca_config_t *sources,
				   size_t source_count, bool *complete)
{
	core_ca_t *cas = nullptr;
	unsigned loaded = 0;
	bool all_loaded = true;

	if (source_count > UINT_MAX) {
		LOGE("Too many CA configurations: %zu", source_count);
		return false;
	}
	if (source_count != 0) {
		cas = osal_calloc(source_count, sizeof *cas);
		if (cas == nullptr) {
			LOGE("Failed to allocate the CA array");
			return false;
		}
	}

	for (size_t i = 0; i < source_count; i++) {
		const store_ca_config_t *source = &sources[i];
		const char *name = source->name != nullptr ? source->name
							   : "<unnamed>";
		core_ca_t *previous = _core_find_runtime_by_name(source->name);
		core_ca_t runtime = { 0 };
		bool certificate_changed;

		if (previous != nullptr
		    && _core_settings_equal(previous->ca, source)) {
			/* crl_number is not a setting; publish updates it. */
			previous->ca->crl_number = source->crl_number;
			cas[loaded++] = *previous;
			*previous = (core_ca_t) { 0 };
			continue;
		}

		certificate_changed = previous == nullptr
			|| !_core_blob_equal(&previous->ca->ca_cert_der,
					     source->ca_cert,
					     source->ca_cert_length);

		if (_core_create_ca(config, source, &runtime)) {
			if (previous != nullptr)
				_core_release_ca_runtime(previous);
			cas[loaded++] = runtime;
			if (certificate_changed
			    && g_cacerts_publish_path != nullptr)
				(void) core_publish_ca_certificate(runtime.ca);
		} else if (previous != nullptr) {
			LOGW("CA %s: keeping the previous configuration", name);
			cas[loaded++] = *previous;
			*previous = (core_ca_t) { 0 };
			all_loaded = false;
		} else {
			all_loaded = false;
		}
	}

	for (unsigned i = 0; i < g_ca_count; i++)
		_core_release_ca_runtime(&g_cas[i]);
	osal_free(g_cas);
	g_cas = cas;
	g_ca_count = loaded;
	if (complete != nullptr)
		*complete = all_loaded;
	return true;
}

const char *core_version(void)
{
	return ANYCA_VERSION_FULL;
}

bool core_init(const config_t *config)
{
	store_ca_config_t *ca_configs = nullptr;
	size_t ca_config_count = 0;
	uint64_t data_version = 0;
	bool ok = false;

	if (config == nullptr) {
		LOGE("Invalid core configuration");
		return false;
	}
	if (g_initialized) {
		LOGE("Core is already initialized");
		return false;
	}
	if (!_core_validate_config(config))
		return false;

	if (!store_init(config->store.path))
		return false;

	/* Read the version before the snapshot so later changes are noticed. */
	if (store_data_version(&data_version) != STORE_OK) {
		LOGE("Failed to read the store data version");
		goto done;
	}

	if (store_ca_config_list(&ca_configs, &ca_config_count) != STORE_OK) {
		LOGE("Failed to load CA configurations from the store");
		goto done;
	}

	if (!_core_apply_ca_configs(config, ca_configs, ca_config_count,
				    nullptr))
		goto done;
	if ((size_t) g_ca_count != ca_config_count)
		LOGW("%u of %zu CA(s) failed and were skipped",
		     (unsigned) (ca_config_count - g_ca_count), ca_config_count);

	/* Publish the state only after every step has succeeded. */
	if ((_core_string_is_set(config->crl_publish_path)
	     && !_core_strdup(&g_crl_publish_path, config->crl_publish_path))
	    || (_core_string_is_set(config->cacerts_publish_path)
		&& !_core_strdup(&g_cacerts_publish_path,
				 config->cacerts_publish_path))) {
		LOGE("Out of memory while recording the publish paths");
		goto done;
	}
	if (!g_session_lock_initialized) {
#if !defined(_WIN32)
		if (pthread_rwlock_init(&g_session_lock, nullptr) != 0) {
			LOGE("Failed to create the core session lock");
			goto done;
		}
#endif
		if (mtx_init(&g_refresh_lock, mtx_plain) != thrd_success) {
			LOGE("Failed to create the core refresh lock");
#if !defined(_WIN32)
			(void) pthread_rwlock_destroy(&g_session_lock);
#endif
			goto done;
		}
		g_session_lock_initialized = true;
	}
	g_config = config;
	g_store_data_version = data_version;
	g_store_data_version_valid = true;
	g_initialized = true;
	ok = true;

done:
	store_ca_config_list_free(ca_configs, ca_config_count);
	if (!ok) {
		for (unsigned i = 0; i < g_ca_count; i++)
			_core_release_ca_runtime(&g_cas[i]);
		osal_free(g_cas);
		g_cas = nullptr;
		g_ca_count = 0;
		_core_hsm_shutdown();
		osal_free(g_crl_publish_path);
		g_crl_publish_path = nullptr;
		osal_free(g_cacerts_publish_path);
		g_cacerts_publish_path = nullptr;
		g_config = nullptr;
		g_store_data_version = 0;
		g_store_data_version_valid = false;
		store_fini();
	}
	return ok;
}

/*
 * Reload the CA configuration when another connection changed the store.
 * Called with the session lock held.
 */
static bool _core_refresh(void)
{
	store_ca_config_t *ca_configs = nullptr;
	size_t ca_config_count = 0;
	uint64_t data_version;
	bool complete = false;
	bool ok = false;

	if (!g_initialized || g_config == nullptr) {
		LOGE("Core is not initialized");
		return false;
	}

	if (store_data_version(&data_version) != STORE_OK)
		return false;
	if (g_store_data_version_valid
	    && data_version == g_store_data_version)
		return true;

	if (store_ca_config_list(&ca_configs, &ca_config_count) != STORE_OK) {
		LOGE("Failed to reload CA configurations from the store");
		return false;
	}

	if (_core_apply_ca_configs(g_config, ca_configs, ca_config_count,
				   &complete)) {
		/*
		 * A failed CA rebuild keeps the previous runtime (or skips the
		 * CA), but the version must not advance: the failure may be
		 * transient, so retry it on the next session.
		 */
		if (complete) {
			g_store_data_version = data_version;
			g_store_data_version_valid = true;
		} else {
			LOGW("Some CA configurations failed to load; retrying "
			     "at the next session");
		}
		LOGI("Reloaded CA configuration from the store: %u CA(s)",
		     g_ca_count);
		ok = true;
	}

	store_ca_config_list_free(ca_configs, ca_config_count);
	return ok;
}

void core_fini(void)
{
	for (unsigned i = 0; i < g_ca_count; i++)
		_core_release_ca_runtime(&g_cas[i]);
	osal_free(g_cas);
	g_cas = nullptr;
	g_ca_count = 0;
	_core_hsm_shutdown();
	osal_free(g_crl_publish_path);
	g_crl_publish_path = nullptr;
	osal_free(g_cacerts_publish_path);
	g_cacerts_publish_path = nullptr;
	g_config = nullptr;
	g_store_data_version = 0;
	g_store_data_version_valid = false;
	store_fini();
	g_initialized = false;
	if (g_session_lock_initialized) {
		mtx_destroy(&g_refresh_lock);
#if !defined(_WIN32)
		(void) pthread_rwlock_destroy(&g_session_lock);
#endif
		g_session_lock_initialized = false;
	}
}

/* Read the store version without touching the CA list. */
static bool _core_store_changed(void)
{
	uint64_t data_version;

	if (!g_initialized || g_config == nullptr)
		return false;
	if (store_data_version(&data_version) != STORE_OK)
		return true; /* let _core_refresh() report the failure */
	return !g_store_data_version_valid
		|| data_version != g_store_data_version;
}

static bool _core_session_lock(bool exclusive)
{
#if defined(_WIN32)
	if (exclusive)
		AcquireSRWLockExclusive(&g_session_lock);
	else
		AcquireSRWLockShared(&g_session_lock);
	return true;
#else
	int result;

	if (exclusive)
		result = pthread_rwlock_wrlock(&g_session_lock);
	else
		result = pthread_rwlock_rdlock(&g_session_lock);
	return result == 0;
#endif
}

static void _core_session_unlock(bool exclusive)
{
#if defined(_WIN32)
	if (exclusive)
		ReleaseSRWLockExclusive(&g_session_lock);
	else
		ReleaseSRWLockShared(&g_session_lock);
#else
	(void) exclusive;
	(void) pthread_rwlock_unlock(&g_session_lock);
#endif
}

void core_session_begin(void)
{
	bool exclusive;

	g_session_held = false;
	if (!g_session_lock_initialized) {
		LOGE("core_session_begin() called before core_init()");
		return;
	}

	/*
	 * Most sessions only read the CA list and can share the lock, so OCSP
	 * requests are not blocked by a CRL build and signature.  A changed
	 * store version needs the exclusive lock for the rebuild, and only for
	 * the rebuild; the session drops back to shared afterwards.
	 */
	(void) mtx_lock(&g_refresh_lock);
	exclusive = _core_store_changed();
	if (!_core_session_lock(exclusive)) {
		(void) mtx_unlock(&g_refresh_lock);
		LOGE("Failed to acquire the core session lock");
		return;
	}
	g_session_exclusive = exclusive;
	g_session_held = true;
	(void) mtx_unlock(&g_refresh_lock);

	if (exclusive) {
		if (!_core_refresh())
			LOGW("Failed to refresh the CA configuration; "
			     "using the current state");

		/*
		 * Only the rebuild needs exclusivity.  Drop back to a shared
		 * session so this caller's work -- for example a scheduler tick
		 * publishing CRLs -- does not block OCSP requests.
		 */
		_core_session_unlock(true);
		g_session_exclusive = false;
		if (!_core_session_lock(false)) {
			g_session_held = false;
			LOGE("Failed to acquire the core session lock");
		}
	}
}

void core_session_end(void)
{
	if (g_session_held && g_session_lock_initialized)
		_core_session_unlock(g_session_exclusive);
	g_session_held = false;
}

unsigned core_ca_count(void)
{
	return g_ca_count;
}

/* Find the runtime entry for a CA returned by a core accessor. */
static core_ca_t *_core_find_ca(const ca_t *ca)
{
	if (ca == nullptr)
		return nullptr;

	for (unsigned i = 0; i < g_ca_count; i++) {
		if (g_cas[i].ca == ca)
			return &g_cas[i];
	}
	return nullptr;
}

ca_t *core_ca_at(unsigned index)
{
	if (index >= g_ca_count)
		return nullptr;
	return g_cas[index].ca;
}

ca_t *core_ca_by_name(const char *name)
{
	if (name == nullptr)
		return nullptr;

	for (unsigned i = 0; i < g_ca_count; i++) {
		if (g_cas[i].ca->name != nullptr
		    && strcmp(g_cas[i].ca->name, name) == 0)
			return g_cas[i].ca;
	}
	return nullptr;
}

ca_t *core_ca_by_ocsp_endpoint(const char *endpoint)
{
	if (endpoint == nullptr)
		return nullptr;

	for (unsigned i = 0; i < g_ca_count; i++) {
		if (g_cas[i].ca->ocsp_responder_endpoint != nullptr
		    && strcmp(g_cas[i].ca->ocsp_responder_endpoint, endpoint)
			       == 0)
			return g_cas[i].ca;
	}
	return nullptr;
}

hsm_token_t *core_ca_token(const ca_t *ca)
{
	core_ca_t *runtime = _core_find_ca(ca);

	return runtime != nullptr ? runtime->token : nullptr;
}

hsm_token_t *core_ca_ocsp_signer_token(const ca_t *ca)
{
	core_ca_t *runtime = _core_find_ca(ca);

	return runtime != nullptr ? runtime->ocsp_signer_token : nullptr;
}

store_ca_id_t core_ca_store_id(const ca_t *ca)
{
	core_ca_t *runtime = _core_find_ca(ca);

	return runtime != nullptr ? runtime->store_id : 0;
}

const char *core_crl_publish_path(void)
{
	return g_crl_publish_path;
}

const char *core_cacerts_publish_path(void)
{
	return g_cacerts_publish_path;
}

/* Reject CA names that cannot be used as one file or directory component. */
static bool _core_publish_name_is_safe(const char *name)
{
	if (!ca_name_is_valid(name)) {
		LOGE("CA name is not valid as a file name");
		return false;
	}
	return true;
}

/*
 * Write data atomically to <directory>/<name><suffix>, creating the directory
 * when needed.  Returns the osal_malloc()ed file path on success, or NULL.
 */
static char *_core_publish_file(const char *directory, const char *name,
				const char *suffix,
				const unsigned char *data, size_t length)
{
	size_t path_length = strlen(directory) + strlen(name)
		+ strlen(suffix) + 2;
	char *path = osal_malloc(path_length);

	if (path == nullptr) {
		LOGE("Cannot allocate the publish file path");
		return nullptr;
	}
	snprintf(path, path_length, "%s/%s%s", directory, name, suffix);

	if (!osal_file_make_dirs(directory)) {
		LOGE("Cannot create %s: %s", directory, osal_file_error());
		goto fail;
	}
	if (!osal_file_write_atomic(path, data, length, 0644)) {
		LOGE("Cannot write %s: %s", path, osal_file_error());
		goto fail;
	}
	return path;

fail:
	osal_free(path);
	return nullptr;
}

static bool _core_crl_sign_algorithm(crl_signature_scheme_t scheme,
				     hsm_sign_alg_t *algorithm)
{
	switch (scheme) {
	case CRL_SIGNATURE_RSA:
		*algorithm = HSM_SIGN_RSA_PKCS1_SHA384;
		return true;
	case CRL_SIGNATURE_ECDSA:
		*algorithm = HSM_SIGN_ECDSA_SHA384;
		return true;
	case CRL_SIGNATURE_ML_DSA_44:
		*algorithm = HSM_SIGN_ML_DSA_44;
		return true;
	case CRL_SIGNATURE_ML_DSA_65:
		*algorithm = HSM_SIGN_ML_DSA_65;
		return true;
	case CRL_SIGNATURE_ML_DSA_87:
		*algorithm = HSM_SIGN_ML_DSA_87;
		return true;
	default:
		return false;
	}
}

static bool _core_crl_signature_scheme(const ca_t *ca,
				       crl_signature_scheme_t *scheme)
{
	hsm_token_t *token = core_ca_token(ca);
	hsm_public_key_t key = { 0 };
	hsm_status_t status;
	bool supported = false;

	if (token == nullptr) {
		LOGE("CA %s: no token for the CA key", ca->name);
		return false;
	}

	status = hsm_get_public_key(token, ca->key_label, &key);
	if (status != HSM_OK) {
		_core_log_hsm_failure("hsm_get_public_key", status);
		return false;
	}

	if (key.type == HSM_KEY_TYPE_RSA) {
		*scheme = CRL_SIGNATURE_RSA;
		supported = true;
	} else if (key.type == HSM_KEY_TYPE_EC) {
		*scheme = CRL_SIGNATURE_ECDSA;
		supported = true;
	} else if (key.type == HSM_KEY_TYPE_ML_DSA) {
		switch (key.ml_dsa_parameter_set) {
		case HSM_ML_DSA_44:
			*scheme = CRL_SIGNATURE_ML_DSA_44;
			supported = true;
			break;
		case HSM_ML_DSA_65:
			*scheme = CRL_SIGNATURE_ML_DSA_65;
			supported = true;
			break;
		case HSM_ML_DSA_87:
			*scheme = CRL_SIGNATURE_ML_DSA_87;
			supported = true;
			break;
		default:
			LOGE("CA %s: unsupported ML-DSA parameter set for a "
			     "CRL",
			     ca->name);
			break;
		}
	} else {
		LOGE("CA %s: unsupported key type for a CRL", ca->name);
	}

	hsm_public_key_free(&key);
	return supported;
}

static bool _core_crl_sign(const ca_t *ca, const crl_blob_t *tbs,
			   hsm_sign_alg_t algorithm,
			   unsigned char **signature,
			   size_t *signature_length)
{
	hsm_token_t *token = core_ca_token(ca);
	unsigned char *buffer;
	hsm_status_t status;
	size_t length = 0;

	*signature = nullptr;
	*signature_length = 0;

	if (token == nullptr) {
		LOGE("CA %s: no token for the CA key", ca->name);
		return false;
	}

	status = hsm_sign_with_pin(token, algorithm, ca->key_label, ca->pin,
				   tbs->data, tbs->length, nullptr, 0,
				   &length);
	if (status != HSM_OK || length == 0) {
		_core_log_hsm_failure("hsm_sign", status);
		return false;
	}

	buffer = osal_malloc(length);
	if (buffer == nullptr) {
		LOGE("CA %s: cannot allocate the CRL signature", ca->name);
		return false;
	}

	status = hsm_sign_with_pin(token, algorithm, ca->key_label, ca->pin,
				   tbs->data, tbs->length, buffer, length,
				   &length);
	if (status != HSM_OK) {
		_core_log_hsm_failure("hsm_sign", status);
		osal_free(buffer);
		return false;
	}

	*signature = buffer;
	*signature_length = length;
	return true;
}

bool core_publish_crl(ca_t *ca)
{
	crl_builder_t *builder = nullptr;
	store_revocation_t *revocations = nullptr;
	size_t revocation_count = 0;
	store_ca_id_t ca_id;
	store_result_t store_status;
	crl_signature_scheme_t scheme;
	hsm_sign_alg_t sign_algorithm;
	crl_blob_t tbs = { 0 };
	crl_blob_t crl = { 0 };
	unsigned char *signature = nullptr;
	size_t signature_length = 0;
	osal_file_lock_t *file_lock = nullptr;
	char *directory = nullptr;
	char *path = nullptr;
	char *lock_path = nullptr;
	size_t directory_length = 0;
	uint64_t number = 0;
	int64_t now = (int64_t) time(nullptr);
	int64_t next_update;
	const crl_digest_algorithm_t digest = CRL_DIGEST_DEFAULT;
	bool ok = false;

	if (ca == nullptr)
		return false;
	ca_id = core_ca_store_id(ca);
	if (ca_id == 0) {
		LOGE("CA %s: no store id", ca->name);
		return false;
	}
	if (!_core_string_is_set(g_crl_publish_path)) {
		LOGE("CA %s: no CRL publish path is configured", ca->name);
		return false;
	}
	if (!_core_publish_name_is_safe(ca->name))
		return false;

	directory_length = strlen(g_crl_publish_path) + strlen(ca->name) + 2;
	directory = osal_malloc(directory_length);
	if (directory == nullptr) {
		LOGE("CA %s: cannot allocate the CRL directory path", ca->name);
		return false;
	}
	snprintf(directory, directory_length, "%s/%s", g_crl_publish_path,
		 ca->name);
	if (!osal_file_make_dirs(directory)) {
		LOGE("CA %s: cannot create the CRL directory %s: %s", ca->name,
		     directory, osal_file_error());
		goto done;
	}

	/*
	 * Serialize number reservation, build, and publication across processes
	 * (server scheduler and CLI).  Without this, a publish that reserved a
	 * lower number could overwrite the file written by a later publish.
	 */
	size_t lock_path_length = strlen(directory) + strlen("/.crl.lock") + 1;
	lock_path = osal_malloc(lock_path_length);
	if (lock_path == nullptr) {
		LOGE("CA %s: cannot allocate the CRL lock path", ca->name);
		goto done;
	}
	snprintf(lock_path, lock_path_length, "%s/.crl.lock", directory);
	file_lock = osal_file_lock_acquire(lock_path);
	if (file_lock == nullptr) {
		LOGE("CA %s: cannot lock %s: %s", ca->name, lock_path,
		     osal_file_error());
		goto done;
	}

	store_status = store_revocation_list(ca_id, 0, &revocations,
					     &revocation_count);
	if (store_status != STORE_OK) {
		LOGE("CA %s: cannot read the revocations: %d", ca->name,
		     (int) store_status);
		goto done;
	}

	if (!_core_crl_signature_scheme(ca, &scheme)
	    || !_core_crl_sign_algorithm(scheme, &sign_algorithm))
		goto done;

	store_status = store_crl_number_reserve(ca_id, &number);
	if (store_status != STORE_OK) {
		LOGE("CA %s: cannot reserve a CRL number: %d", ca->name,
		     (int) store_status);
		goto done;
	}

	builder = crl_builder_new();
	if (builder == nullptr) {
		LOGE("CA %s: cannot create the CRL builder", ca->name);
		goto done;
	}

	next_update = ca->crl_publish_period_min != 0
		? now + (int64_t) ca->crl_publish_period_min * 60
		: now + (int64_t) CORE_CRL_DEFAULT_PERIOD_MIN * 60;
	if (!crl_builder_set_issuer_certificate(builder, ca->ca_cert_der.data,
						ca->ca_cert_der.length)) {
		LOGE("CA %s: cannot set the CRL issuer", ca->name);
		goto done;
	}
	if (!crl_builder_set_update_times(builder, now, next_update)) {
		LOGE("CA %s: cannot set the CRL update times", ca->name);
		goto done;
	}

	for (size_t i = 0; i < revocation_count; i++) {
		if (!crl_builder_add_revoked_certificate(
			    builder, revocations[i].serial,
			    revocations[i].serial_length,
			    revocations[i].revoked_at, revocations[i].reason)) {
			LOGE("CA %s: cannot add the revoked certificate %zu",
			     ca->name, i);
			goto done;
		}
	}

	if (!crl_builder_add_crl_number(builder, number)
	    || !crl_builder_add_authority_key_identifier(builder)) {
		LOGE("CA %s: cannot add the CRL extensions", ca->name);
		goto done;
	}

	if (!crl_builder_tbs(builder, scheme, digest, &tbs)) {
		LOGE("CA %s: cannot encode the CRL TBS", ca->name);
		goto done;
	}
	if (!_core_crl_sign(ca, &tbs, sign_algorithm, &signature,
			    &signature_length))
		goto done;
	if (!crl_builder_assemble(builder, scheme, digest, tbs.data, tbs.length,
				  signature, signature_length, &crl)) {
		LOGE("CA %s: cannot assemble the CRL", ca->name);
		goto done;
	}

	path = _core_publish_file(directory, ca->name, ".crl", crl.data,
				  crl.length);
	if (path == nullptr) {
		LOGE("CA %s: cannot publish the CRL", ca->name);
		goto done;
	}

	store_status = store_ca_config_set_crl_number(ca->name, number);
	if (store_status != STORE_OK) {
		LOGE("CA %s: cannot record CRL number %llu: %d", ca->name,
		     (unsigned long long) number, (int) store_status);
		goto done;
	}
	ca->crl_number = number;

	LOGI("CA %s: published CRL %llu to %s (%zu revoked, %zu bytes)",
	     ca->name, (unsigned long long) number, path, revocation_count,
	     crl.length);
	ok = true;

done:
	osal_file_lock_release(file_lock);
	osal_free(lock_path);
	osal_free(path);
	osal_free(directory);
	crl_blob_free(&crl);
	crl_blob_free(&tbs);
	osal_free(signature);
	crl_builder_free(builder);
	store_revocation_list_free(revocations, revocation_count);
	return ok;
}

static bool _core_publish_ca_certificate_data(const char *publish_path,
					      const char *ca_name,
					      const unsigned char *der,
					      size_t der_length);

bool core_publish_ca_certificate(const ca_t *ca)
{
	if (ca == nullptr)
		return false;
	if (!_core_string_is_set(g_cacerts_publish_path)) {
		LOGE("CA %s: no CA certificate publish path is configured",
		     ca->name);
		return false;
	}
	if (ca->ca_cert_der.data == nullptr || ca->ca_cert_der.length == 0) {
		LOGE("CA %s: no CA certificate is loaded", ca->name);
		return false;
	}

	return _core_publish_ca_certificate_data(
		g_cacerts_publish_path, ca->name, ca->ca_cert_der.data,
		ca->ca_cert_der.length);
}

static bool _core_publish_ca_certificate_data(const char *publish_path,
					      const char *ca_name,
					      const unsigned char *der,
					      size_t der_length)
{
	char *path;

	if (!_core_string_is_set(publish_path)) {
		LOGE("No CA certificate publish path is configured");
		return false;
	}
	if (!_core_publish_name_is_safe(ca_name))
		return false;
	if (der == nullptr || der_length == 0) {
		LOGE("CA %s: no CA certificate is available", ca_name);
		return false;
	}

	path = _core_publish_file(publish_path, ca_name, ".crt", der, der_length);
	if (path == nullptr) {
		LOGE("CA %s: cannot publish the certificate", ca_name);
		return false;
	}

	LOGI("CA %s: published certificate to %s", ca_name, path);
	osal_free(path);
	return true;
}
