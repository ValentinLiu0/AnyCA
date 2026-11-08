/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

/*
 * PKCS #11 facade.
 *
 * Each module owns one loaded library, its function table and token contexts.
 * module->lock protects module lifecycle and the token list and is never held
 * during token operations.  Each token context has a mutex for login state,
 * its session pool and active operations; a pooled session is owned
 * exclusively by its operation.
 */

#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#include <pkcs11.h>

#include <anyca/osal/dynlib.h>
#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>
#include <anyca/osal/thread.h>

#include <anyca/ossl/asn1.h>

#include <anyca/hsm.h>

#define HSM_ERROR_MAX 512
#define HSM_TOKEN_LABEL_LEN 32
#define HSM_DIGEST_MAX 64 /* SHA-512 */

/*
 * PKCS #11 lengths are CK_ULONG.  On Windows x64 it is 32-bit while size_t is
 * 64-bit, so a length must be range-checked instead of truncated.  The check
 * folds away on LP64 platforms, where CK_ULONG and size_t have equal width.
 */
static bool _size_fits_ck_ulong(size_t value)
{
	return sizeof(CK_ULONG) >= sizeof(size_t)
	       || value <= (size_t)((CK_ULONG)-1);
}

static bool _ck_ulong_from_size(size_t value, CK_ULONG *result)
{
	if (!_size_fits_ck_ulong(value))
		return false;
	*result = (CK_ULONG)value;
	return true;
}

struct hsm_pool_session {
	CK_SESSION_HANDLE handle;
	bool in_use;
};

/*
 * Cryptographic operation state belongs to the provider, not to a wrapper:
 * two modules may be opened on the same shared library, and C_Finalize() must
 * not run while either of them (or anybody else) still uses it.
 */
struct hsm_provider {
	char *path;
	size_t references;
	bool owns_initialize;
	struct hsm_provider *next;
};

/* The opaque public type is defined here so PKCS #11 stays internal. */
struct hsm_module {
	mtx_t lock;
	cnd_t idle;
	_Atomic bool ready;
	bool initialized;
	struct hsm_provider *provider;
	size_t active_calls;
	struct hsm_module *registry_next;
	osal_dynlib_t *library;
	CK_FUNCTION_LIST_PTR functions;
	struct hsm_token *tokens;
	size_t max_sessions;
};

struct hsm_token {
	struct hsm_module *module;
	struct hsm_token *next;
	CK_SLOT_ID slot;
	size_t references; /* protected by module->lock */
	mtx_t lock;
	cnd_t condition;
	bool closing;
	bool logged_in;
	CK_SESSION_HANDLE login_session;
	size_t max_sessions;
	size_t session_count;
	size_t active_operations;
	struct hsm_pool_session *sessions;
};

struct hsm_session_ref {
	size_t index;
	CK_SESSION_HANDLE handle;
	/* Set once C_CloseSession() confirmed that handle was closed. */
	bool closed;
};

static OSAL_THREAD_LOCAL struct hsm_error g_error = {
	.status = HSM_OK,
	.pkcs11_code = 0,
	.operation = nullptr,
	.message = "no error",
};

static void _reset_last_error(void)
{
	g_error.status = HSM_OK;
	g_error.pkcs11_code = 0;
	g_error.operation = nullptr;
	snprintf(g_error.message, sizeof g_error.message, "no error");
}

/*
 * Record a thread-local failure and return its status; arguments format the
 * message.
 */
static hsm_status_t _fail(hsm_status_t status, const char *operation,
			  unsigned long pkcs11_code, const char *format, ...)
{
	va_list arguments;

	g_error.status = status;
	g_error.pkcs11_code = pkcs11_code;
	g_error.operation = operation;
	va_start(arguments, format);
	vsnprintf(g_error.message, sizeof g_error.message, format, arguments);
	va_end(arguments);
	return status;
}

static hsm_status_t _argument_error(const char *operation, const char *message)
{
	return _fail(HSM_ERR_ARGUMENT, operation, 0, "%s", message);
}

static const char *_pkcs11_rv_name(CK_RV rv)
{
	switch (rv) {
	case CKR_OK:
		return "CKR_OK";
	case CKR_CANCEL:
		return "CKR_CANCEL";
	case CKR_HOST_MEMORY:
		return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID:
		return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR:
		return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED:
		return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD:
		return "CKR_ARGUMENTS_BAD";
	case CKR_NO_EVENT:
		return "CKR_NO_EVENT";
	case CKR_NEED_TO_CREATE_THREADS:
		return "CKR_NEED_TO_CREATE_THREADS";
	case CKR_CANT_LOCK:
		return "CKR_CANT_LOCK";
	case CKR_ATTRIBUTE_READ_ONLY:
		return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE:
		return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID:
		return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID:
		return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_ACTION_PROHIBITED:
		return "CKR_ACTION_PROHIBITED";
	case CKR_DATA_INVALID:
		return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE:
		return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR:
		return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY:
		return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED:
		return "CKR_DEVICE_REMOVED";
	case CKR_ENCRYPTED_DATA_INVALID:
		return "CKR_ENCRYPTED_DATA_INVALID";
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	case CKR_FUNCTION_CANCELED:
		return "CKR_FUNCTION_CANCELED";
	case CKR_FUNCTION_NOT_PARALLEL:
		return "CKR_FUNCTION_NOT_PARALLEL";
	case CKR_FUNCTION_NOT_SUPPORTED:
		return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID:
		return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE:
		return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT:
		return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_KEY_NOT_WRAPPABLE:
		return "CKR_KEY_NOT_WRAPPABLE";
	case CKR_KEY_UNEXTRACTABLE:
		return "CKR_KEY_UNEXTRACTABLE";
	case CKR_MECHANISM_INVALID:
		return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID:
		return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID:
		return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE:
		return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED:
		return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT:
		return "CKR_PIN_INCORRECT";
	case CKR_PIN_INVALID:
		return "CKR_PIN_INVALID";
	case CKR_PIN_LEN_RANGE:
		return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_EXPIRED:
		return "CKR_PIN_EXPIRED";
	case CKR_PIN_LOCKED:
		return "CKR_PIN_LOCKED";
	case CKR_SESSION_CLOSED:
		return "CKR_SESSION_CLOSED";
	case CKR_SESSION_COUNT:
		return "CKR_SESSION_COUNT";
	case CKR_SESSION_HANDLE_INVALID:
		return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	case CKR_SESSION_READ_ONLY:
		return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS:
		return "CKR_SESSION_EXISTS";
	case CKR_SESSION_READ_ONLY_EXISTS:
		return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	case CKR_SIGNATURE_INVALID:
		return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE:
		return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE:
		return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT:
		return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT:
		return "CKR_TOKEN_NOT_PRESENT";
	case CKR_TOKEN_NOT_RECOGNIZED:
		return "CKR_TOKEN_NOT_RECOGNIZED";
	case CKR_TOKEN_WRITE_PROTECTED:
		return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_USER_ALREADY_LOGGED_IN:
		return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN:
		return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED:
		return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID:
		return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_USER_TOO_MANY_TYPES:
		return "CKR_USER_TOO_MANY_TYPES";
	case CKR_WRAPPED_KEY_INVALID:
		return "CKR_WRAPPED_KEY_INVALID";
	case CKR_WRAPPED_KEY_LEN_RANGE:
		return "CKR_WRAPPED_KEY_LEN_RANGE";
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		return "CKR_WRAPPING_KEY_HANDLE_INVALID";
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		return "CKR_WRAPPING_KEY_SIZE_RANGE";
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		return "CKR_RANDOM_SEED_NOT_SUPPORTED";
	case CKR_RANDOM_NO_RNG:
		return "CKR_RANDOM_NO_RNG";
	case CKR_BUFFER_TOO_SMALL:
		return "CKR_BUFFER_TOO_SMALL";
	case CKR_SAVED_STATE_INVALID:
		return "CKR_SAVED_STATE_INVALID";
	case CKR_INFORMATION_SENSITIVE:
		return "CKR_INFORMATION_SENSITIVE";
	case CKR_STATE_UNSAVEABLE:
		return "CKR_STATE_UNSAVEABLE";
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	case CKR_MUTEX_BAD:
		return "CKR_MUTEX_BAD";
	case CKR_MUTEX_NOT_LOCKED:
		return "CKR_MUTEX_NOT_LOCKED";
	default:
		return "CKR_UNKNOWN";
	}
}

static hsm_status_t _map_rv_to_status(CK_RV rv, hsm_status_t fallback)
{
	switch (rv) {
	case CKR_OK:
		return HSM_OK;
	case CKR_HOST_MEMORY:
	case CKR_DEVICE_MEMORY:
		return HSM_ERR_MEMORY;
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_REMOVED:
	case CKR_TOKEN_NOT_PRESENT:
		return HSM_ERR_DEVICE;
	case CKR_PIN_INCORRECT:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
	case CKR_PIN_EXPIRED:
	case CKR_PIN_LOCKED:
		return HSM_ERR_PIN_INCORRECT;
	case CKR_USER_NOT_LOGGED_IN:
		return HSM_ERR_TOKEN_NOT_LOGGED_IN;
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
	case CKR_FUNCTION_NOT_SUPPORTED:
		return HSM_ERR_MECHANISM;
	case CKR_BUFFER_TOO_SMALL:
		return HSM_ERR_BUFFER_TOO_SMALL;
	case CKR_SESSION_COUNT:
		return HSM_ERR_SESSION_LIMIT;
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_READ_ONLY:
		return HSM_ERR_SESSION;
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		return HSM_ERR_NOT_INITIALIZED;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return HSM_ERR_ALREADY_INITIALIZED;
	default:
		return fallback;
	}
}

static hsm_status_t _pkcs11_failure(const char *operation, CK_RV rv,
				    hsm_status_t fallback)
{
	return _fail(_map_rv_to_status(rv, fallback), operation,
		     (unsigned long)rv, "%s failed: %s (0x%lx)",
		     operation, _pkcs11_rv_name(rv), (unsigned long)rv);
}

/*
 * Module handle registry.
 *
 * hsm_module_get_info() and hsm_module_is_open() receive a raw handle, so a
 * concurrent hsm_module_close() could otherwise free the module while they
 * dereference it.  Every module stays in this registry until close has
 * finished with it, and close waits for in-flight queries to leave before it
 * releases the structure.  A handle that is no longer registered is reported
 * as closed instead of being dereferenced.
 */
static mtx_t g_module_registry_lock;
static struct hsm_module *g_module_registry;
static _Atomic bool g_module_registry_ready;
static once_flag g_module_registry_once = ONCE_FLAG_INIT;

static void _module_registry_init(void)
{
	if (mtx_init(&g_module_registry_lock, mtx_plain) == thrd_success)
		atomic_store_explicit(&g_module_registry_ready, true,
				      memory_order_release);
}

static bool _module_registry_available(void)
{
	call_once(&g_module_registry_once, _module_registry_init);
	return atomic_load_explicit(&g_module_registry_ready,
				    memory_order_acquire);
}

static struct hsm_module *_module_registry_find(const struct hsm_module *module)
{
	struct hsm_module *candidate;

	for (candidate = g_module_registry; candidate != nullptr;
	     candidate = candidate->registry_next) {
		if (candidate == module)
			return candidate;
	}
	return nullptr;
}

/*
 * Reserve the module for a query that must not race C_Finalize().  The
 * registry lock is held while the call is counted, so close cannot unregister
 * the module between the lookup and the increment.
 */
static hsm_status_t _module_enter(const struct hsm_module *module,
				  const char *operation,
				  struct hsm_module **entered)
{
	struct hsm_module *candidate;

	*entered = nullptr;
	if (module == nullptr)
		return _fail(HSM_ERR_ARGUMENT, operation, 0,
			     "module must not be NULL");
	if (!_module_registry_available())
		return _fail(HSM_ERR_INTERNAL, operation, 0,
			     "the module registry is unavailable");

	mtx_lock(&g_module_registry_lock);
	candidate = _module_registry_find(module);
	if (candidate != nullptr) {
		bool usable;

		mtx_lock(&candidate->lock);
		usable = candidate->initialized
			 && atomic_load_explicit(&candidate->ready,
						 memory_order_acquire);
		if (usable)
			candidate->active_calls++;
		mtx_unlock(&candidate->lock);
		if (!usable)
			candidate = nullptr;
	}
	mtx_unlock(&g_module_registry_lock);

	if (candidate == nullptr)
		return _fail(HSM_ERR_NOT_INITIALIZED, operation, 0,
			     "the HSM module is not open; call "
			     "hsm_module_open() first");
	*entered = candidate;
	return HSM_OK;
}

static void _module_leave(struct hsm_module *module)
{
	mtx_lock(&module->lock);
	if (module->active_calls > 0)
		module->active_calls--;
	cnd_signal(&module->idle);
	mtx_unlock(&module->lock);
}

/*
 * Provider records are rebuilt from the process-wide PKCS #11 state, but the
 * list itself lives in this process.  They are protected by the module
 * registry lock so module open and close cannot race each other.
 */
static struct hsm_provider *g_hsm_providers;

static struct hsm_provider *_provider_acquire(const char *path)
{
	struct hsm_provider *provider;
	size_t length;

	for (provider = g_hsm_providers; provider != nullptr;
	     provider = provider->next) {
		if (strcmp(provider->path, path) == 0)
			break;
	}
	if (provider == nullptr) {
		length = strlen(path) + 1;
		provider = calloc(1, sizeof *provider);
		if (provider == nullptr)
			return nullptr;
		provider->path = osal_malloc(length);
		if (provider->path == nullptr) {
			free(provider);
			return nullptr;
		}
		memcpy(provider->path, path, length);
		provider->next = g_hsm_providers;
		g_hsm_providers = provider;
	}
	provider->references++;
	return provider;
}

/*
 * Drop one module reference.  The caller must hold the module registry lock
 * and must have called C_Finalize() first when this removes the last
 * reference.
 */
static void _provider_release(struct hsm_provider *provider)
{
	struct hsm_provider **link;

	if (provider->references > 0)
		provider->references--;
	if (provider->references > 0)
		return;

	link = &g_hsm_providers;
	while (*link != nullptr && *link != provider)
		link = &(*link)->next;
	if (*link == provider)
		*link = provider->next;
	osal_free(provider->path);
	free(provider);
}

static bool _module_is_ready(const struct hsm_module *module)
{
	return module != nullptr
		&& atomic_load_explicit(&module->ready, memory_order_acquire);
}

static hsm_status_t _require_module_ready(const struct hsm_module *module,
					  const char *operation)
{
	if (!_module_is_ready(module)) {
		return _fail(HSM_ERR_NOT_INITIALIZED, operation, 0,
			     "the HSM module is not open; call "
			     "hsm_module_open() first");
	}
	return HSM_OK;
}

static void _copy_padded_string(char *destination, size_t destination_size,
				const CK_UTF8CHAR *source, size_t source_size)
{
	size_t length = source_size;

	if (destination_size == 0)
		return;
	while (length > 0
	       && (source[length - 1] == ' ' || source[length - 1] == '\0'))
		length--;
	if (length >= destination_size)
		length = destination_size - 1;
	memcpy(destination, source, length);
	destination[length] = '\0';
}

static CK_BYTE_PTR _pkcs11_input_pointer(const void *data, size_t data_len)
{
	/* PKCS #11 does not accept NULL even when the length is zero. */
	static unsigned char empty;

	return data_len == 0 ? &empty : (CK_BYTE_PTR)(void *)data;
}

static struct hsm_token *_find_token_locked(struct hsm_module *module,
					    CK_SLOT_ID slot)
{
	struct hsm_token *token;

	for (token = module->tokens; token != nullptr; token = token->next) {
		if (token->slot == slot)
			return token;
	}
	return nullptr;
}

static void _destroy_token(struct hsm_token *token)
{
	struct hsm_module *module = token->module;
	CK_FUNCTION_LIST_PTR functions = module->functions;

	mtx_lock(&token->lock);
	token->closing = true;

	/*
	 * Wait for late operations so they cannot touch the sessions or the
	 * freed context.
	 */
	while (token->active_operations > 0) {
		if (cnd_wait(&token->condition, &token->lock) != thrd_success)
			break;
	}

	if (token->logged_in && token->login_session != CK_INVALID_HANDLE)
		(void)functions->C_Logout(token->login_session);
	token->logged_in = false;

	for (size_t i = 0; i < token->max_sessions; i++) {
		if (token->sessions[i].handle != CK_INVALID_HANDLE)
			(void)functions->C_CloseSession(
				token->sessions[i].handle);
	}
	if (token->login_session != CK_INVALID_HANDLE)
		(void)functions->C_CloseSession(token->login_session);

	mtx_unlock(&token->lock);
	cnd_destroy(&token->condition);
	mtx_destroy(&token->lock);
	free(token->sessions);
	free(token);
}

static hsm_status_t _list_slots_with_token(struct hsm_module *module,
					   CK_SLOT_ID **slots,
					   CK_ULONG *slot_count)
{
	CK_FUNCTION_LIST_PTR functions = module->functions;
	CK_ULONG count = 0;
	CK_RV rv;

	*slots = nullptr;
	*slot_count = 0;

	rv = functions->C_GetSlotList(CK_TRUE, nullptr, &count);
	if (rv != CKR_OK)
		return _pkcs11_failure("C_GetSlotList", rv, HSM_ERR_DEVICE);
	if (count == 0)
		return HSM_OK;

	for (unsigned int attempt = 0; attempt < 3; attempt++) {
		CK_ULONG available = count;
		CK_SLOT_ID *list;

		list = malloc((size_t)count * sizeof *list);
		if (list == nullptr)
			return _fail(HSM_ERR_MEMORY, "C_GetSlotList", 0,
				     "out of memory while listing slots");

		rv = functions->C_GetSlotList(CK_TRUE, list, &available);
		if (rv == CKR_OK) {
			if (available > count) {
				free(list);
				return _fail(
					HSM_ERR_DEVICE, "C_GetSlotList", 0,
					"token returned more slots than "
					"requested");
			}
			*slots = list;
			*slot_count = available;
			return HSM_OK;
		}

		free(list);
		if (rv != CKR_BUFFER_TOO_SMALL || available == 0)
			return _pkcs11_failure("C_GetSlotList", rv,
					       HSM_ERR_DEVICE);
		count = available;
	}

	return _fail(HSM_ERR_DEVICE, "C_GetSlotList", 0,
		     "C_GetSlotList kept returning CKR_BUFFER_TOO_SMALL");
}

static hsm_status_t _create_token_context(struct hsm_module *module,
					  CK_SLOT_ID slot,
					  struct hsm_token **result)
{
	struct hsm_token *token;
	struct hsm_pool_session *sessions;

	token = calloc(1, sizeof *token);
	if (token == nullptr)
		return _fail(HSM_ERR_MEMORY, "hsm_token_open", 0,
			     "out of memory while creating a token context");

	sessions = calloc(module->max_sessions, sizeof *sessions);
	if (sessions == nullptr) {
		free(token);
		return _fail(HSM_ERR_MEMORY, "hsm_token_open", 0,
			     "out of memory while creating the session pool");
	}
	for (size_t i = 0; i < module->max_sessions; i++)
		sessions[i].handle = CK_INVALID_HANDLE;

	if (mtx_init(&token->lock, mtx_plain) != thrd_success) {
		free(sessions);
		free(token);
		return _fail(HSM_ERR_INTERNAL, "hsm_token_open", 0,
			     "cannot initialize the token lock");
	}
	if (cnd_init(&token->condition) != thrd_success) {
		mtx_destroy(&token->lock);
		free(sessions);
		free(token);
		return _fail(HSM_ERR_INTERNAL, "hsm_token_open", 0,
			     "cannot initialize the token condition variable");
	}

	token->module = module;
	token->slot = slot;
	token->references = 1;
	token->login_session = CK_INVALID_HANDLE;
	token->max_sessions = module->max_sessions;
	token->sessions = sessions;
	token->next = module->tokens;
	module->tokens = token;

	*result = token;
	return HSM_OK;
}

hsm_status_t hsm_module_open(const struct hsm_config *config,
			     hsm_module_t **module)
{
	CK_C_INITIALIZE_ARGS arguments = {
		.CreateMutex = nullptr,
		.DestroyMutex = nullptr,
		.LockMutex = nullptr,
		.UnlockMutex = nullptr,
		.flags = CKF_OS_LOCKING_OK,
		.pReserved = nullptr,
	};
	struct hsm_module *opened;
	osal_dynlib_t *library;
	CK_FUNCTION_LIST_PTR functions = nullptr;
	CK_C_GetFunctionList get_function_list = nullptr;
	CK_RV rv;
	void *symbol;

	_reset_last_error();

	if (module == nullptr)
		return _argument_error("hsm_module_open",
				       "module must not be NULL");
	*module = nullptr;
	if (config == nullptr || config->module_path == nullptr
	    || config->module_path[0] == '\0')
		return _argument_error("hsm_module_open",
				       "a PKCS #11 module path is required");
	if (!_module_registry_available())
		return _fail(HSM_ERR_INTERNAL, "hsm_module_open", 0,
			     "cannot initialize the module registry");

	opened = calloc(1, sizeof *opened);
	if (opened == nullptr)
		return _fail(HSM_ERR_MEMORY, "hsm_module_open", 0,
			     "out of memory while creating a module");

	if (mtx_init(&opened->lock, mtx_plain) != thrd_success) {
		free(opened);
		return _fail(HSM_ERR_INTERNAL, "hsm_module_open", 0,
			     "cannot initialize the module lock");
	}
	if (cnd_init(&opened->idle) != thrd_success) {
		mtx_destroy(&opened->lock);
		free(opened);
		return _fail(HSM_ERR_INTERNAL, "hsm_module_open", 0,
			     "cannot initialize the module condition variable");
	}

	library = osal_dynlib_open(config->module_path);
	if (library == nullptr) {
		cnd_destroy(&opened->idle);
		mtx_destroy(&opened->lock);
		free(opened);
		return _fail(HSM_ERR_MODULE_LOAD, "osal_dynlib_open", 0,
			     "cannot load PKCS #11 module \"%s\": %s",
			     config->module_path, osal_dynlib_error());
	}

	symbol = osal_dynlib_symbol(library, "C_GetFunctionList");
	if (symbol == nullptr) {
		hsm_status_t status = _fail(
			HSM_ERR_MODULE_LOAD, "osal_dynlib_symbol", 0,
			"PKCS #11 module \"%s\" does not export "
			"C_GetFunctionList: %s",
			config->module_path, osal_dynlib_error());
		osal_dynlib_close(library);
		cnd_destroy(&opened->idle);
		mtx_destroy(&opened->lock);
		free(opened);
		return status;
	}

	/*
	 * ISO C does not guarantee a shared object/function pointer
	 * representation; POSIX and Windows do in practice.
	 */
	static_assert(sizeof get_function_list == sizeof symbol,
		      "function and object pointers have different sizes");
	memcpy(&get_function_list, &symbol, sizeof get_function_list);

	rv = get_function_list(&functions);
	if (rv != CKR_OK || functions == nullptr) {
		hsm_status_t status = _fail(
			HSM_ERR_MODULE_INIT, "C_GetFunctionList",
			(unsigned long)rv,
			"C_GetFunctionList failed: %s (0x%lx)",
			_pkcs11_rv_name(rv), (unsigned long)rv);
		osal_dynlib_close(library);
		cnd_destroy(&opened->idle);
		mtx_destroy(&opened->lock);
		free(opened);
		return status;
	}

	mtx_lock(&g_module_registry_lock);
	opened->provider = _provider_acquire(config->module_path);
	if (opened->provider == nullptr) {
		mtx_unlock(&g_module_registry_lock);
		osal_dynlib_close(library);
		cnd_destroy(&opened->idle);
		mtx_destroy(&opened->lock);
		free(opened);
		return _fail(HSM_ERR_MEMORY, "hsm_module_open", 0,
			     "out of memory while tracking the PKCS #11 "
			     "provider");
	}

	rv = functions->C_Initialize(&arguments);
	if (rv == CKR_CANT_LOCK || rv == CKR_ARGUMENTS_BAD)
		rv = functions->C_Initialize(nullptr);

	if (rv == CKR_OK) {
		opened->provider->owns_initialize = true;
	} else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		hsm_status_t status = _fail(
			HSM_ERR_MODULE_INIT, "C_Initialize",
			(unsigned long)rv,
			"C_Initialize failed: %s (0x%lx)",
			_pkcs11_rv_name(rv), (unsigned long)rv);
		_provider_release(opened->provider);
		opened->provider = nullptr;
		mtx_unlock(&g_module_registry_lock);
		osal_dynlib_close(library);
		cnd_destroy(&opened->idle);
		mtx_destroy(&opened->lock);
		free(opened);
		return status;
	}
	/*
	 * CKR_CRYPTOKI_ALREADY_INITIALIZED means another module wrapper (or the
	 * process itself) initialized the provider first; only the last module
	 * closed on this path may finalize it, and only if this process
	 * initialized it through our tracking.
	 */

	opened->library = library;
	opened->functions = functions;
	opened->max_sessions = config->max_sessions_per_token != 0
				      ? config->max_sessions_per_token
				      : HSM_DEFAULT_MAX_SESSIONS;
	opened->initialized = true;
	atomic_store_explicit(&opened->ready, true, memory_order_release);

	opened->registry_next = g_module_registry;
	g_module_registry = opened;
	mtx_unlock(&g_module_registry_lock);

	*module = opened;
	return HSM_OK;
}

hsm_status_t hsm_module_close(hsm_module_t *module)
{
	struct hsm_module **link;
	CK_RV rv;

	_reset_last_error();

	if (module == nullptr)
		return HSM_OK;
	if (!_module_registry_available())
		return _fail(HSM_ERR_INTERNAL, "hsm_module_close", 0,
			     "the module registry is unavailable");

	/*
	 * Keep the registry lock for the whole close: it stops new queries
	 * from entering, and a handle that is not registered is reported as
	 * already closed instead of being dereferenced.
	 */
	mtx_lock(&g_module_registry_lock);
	link = &g_module_registry;
	while (*link != nullptr && *link != module)
		link = &(*link)->registry_next;
	if (*link == nullptr) {
		mtx_unlock(&g_module_registry_lock);
		return HSM_OK;
	}

	mtx_lock(&module->lock);
	if (!module->initialized) {
		*link = module->registry_next;
		mtx_unlock(&module->lock);
		mtx_unlock(&g_module_registry_lock);
		cnd_destroy(&module->idle);
		mtx_destroy(&module->lock);
		free(module);
		return HSM_OK;
	}
	if (module->tokens != nullptr) {
		mtx_unlock(&module->lock);
		mtx_unlock(&g_module_registry_lock);
		return _fail(HSM_ERR_BUSY, "hsm_module_close", 0,
			     "token handles are still open; close them "
			     "before closing the module");
	}

	atomic_store_explicit(&module->ready, false, memory_order_release);
	while (module->active_calls > 0) {
		if (cnd_wait(&module->idle, &module->lock) != thrd_success) {
			atomic_store_explicit(&module->ready, true,
					      memory_order_release);
			mtx_unlock(&module->lock);
			mtx_unlock(&g_module_registry_lock);
			return _fail(HSM_ERR_INTERNAL, "hsm_module_close", 0,
				     "failed to wait for active module "
				     "operations");
		}
	}

	if (module->provider != nullptr) {
		/*
		 * The provider is shared by every module wrapper opened on the
		 * same library.  Finalize it only when this is the last user and
		 * this process performed the matching C_Initialize().
		 */
		if (module->provider->references == 1
		    && module->provider->owns_initialize) {
			rv = module->functions->C_Finalize(nullptr);
			if (rv != CKR_OK) {
				atomic_store_explicit(&module->ready, true,
						      memory_order_release);
				mtx_unlock(&module->lock);
				mtx_unlock(&g_module_registry_lock);
				return _pkcs11_failure("C_Finalize", rv,
						       HSM_ERR_INTERNAL);
			}
			module->provider->owns_initialize = false;
		}
		_provider_release(module->provider);
		module->provider = nullptr;
	}

	module->functions = nullptr;
	module->initialized = false;
	if (module->library != nullptr)
		osal_dynlib_close(module->library);
	module->library = nullptr;
	*link = module->registry_next;

	mtx_unlock(&module->lock);
	mtx_unlock(&g_module_registry_lock);

	cnd_destroy(&module->idle);
	mtx_destroy(&module->lock);
	free(module);
	return HSM_OK;
}

bool hsm_module_is_open(const hsm_module_t *module)
{
	struct hsm_module *candidate;
	bool open = false;

	if (module == nullptr || !_module_registry_available())
		return false;

	mtx_lock(&g_module_registry_lock);
	candidate = _module_registry_find(module);
	if (candidate != nullptr) {
		mtx_lock(&candidate->lock);
		open = candidate->initialized
		       && atomic_load_explicit(&candidate->ready,
					       memory_order_acquire);
		mtx_unlock(&candidate->lock);
	}
	mtx_unlock(&g_module_registry_lock);
	return open;
}

hsm_status_t hsm_module_get_info(const hsm_module_t *module,
				 struct hsm_module_info *info)
{
	struct hsm_module *entered;
	CK_INFO ck_info;
	CK_RV rv;
	hsm_status_t status;

	_reset_last_error();

	if (module == nullptr)
		return _argument_error("hsm_module_get_info",
				       "module must not be NULL");
	if (info == nullptr)
		return _argument_error("hsm_module_get_info",
				       "info must not be NULL");
	status = _module_enter(module, "hsm_module_get_info", &entered);
	if (status != HSM_OK)
		return status;

	rv = entered->functions->C_GetInfo(&ck_info);
	_module_leave(entered);
	if (rv != CKR_OK)
		return _pkcs11_failure("C_GetInfo", rv, HSM_ERR_INTERNAL);

	memset(info, 0, sizeof *info);
	_copy_padded_string(info->manufacturer, sizeof info->manufacturer,
			    ck_info.manufacturerID,
			    sizeof ck_info.manufacturerID);
	_copy_padded_string(info->description, sizeof info->description,
			    ck_info.libraryDescription,
			    sizeof ck_info.libraryDescription);
	info->cryptoki_version_major = ck_info.cryptokiVersion.major;
	info->cryptoki_version_minor = ck_info.cryptokiVersion.minor;
	info->library_version_major = ck_info.libraryVersion.major;
	info->library_version_minor = ck_info.libraryVersion.minor;
	return HSM_OK;
}

hsm_status_t hsm_token_open(hsm_module_t *module, const char *token_label,
			    hsm_token_t **token)
{
	struct hsm_module *entered;
	CK_SLOT_ID *slots = nullptr;
	CK_ULONG slot_count = 0;
	hsm_status_t status;
	size_t label_length;

	_reset_last_error();

	if (module == nullptr)
		return _argument_error("hsm_token_open",
				       "module must not be NULL");
	if (token == nullptr)
		return _argument_error("hsm_token_open",
				       "token must not be NULL");
	*token = nullptr;
	if (token_label == nullptr || token_label[0] == '\0')
		return _argument_error("hsm_token_open",
				       "token label must not be NULL or empty");

	label_length = strlen(token_label);
	if (label_length > HSM_TOKEN_LABEL_LEN)
		return _argument_error("hsm_token_open",
				       "token label is longer than 32 bytes");

	/*
	 * Entering the module keeps hsm_module_close() from finalizing and
	 * freeing it while this call queries slots and creates the context.
	 */
	status = _module_enter(module, "hsm_token_open", &entered);
	if (status != HSM_OK)
		return status;

	mtx_lock(&entered->lock);

	status = _list_slots_with_token(entered, &slots, &slot_count);
	if (status != HSM_OK) {
		mtx_unlock(&entered->lock);
		_module_leave(entered);
		return status;
	}

	for (CK_ULONG i = 0; i < slot_count; i++) {
		CK_TOKEN_INFO info;
		char label[HSM_TOKEN_LABEL_LEN + 1];
		struct hsm_token *existing;

		if (entered->functions->C_GetTokenInfo(slots[i], &info)
		    != CKR_OK)
			continue;
		if ((info.flags & CKF_TOKEN_INITIALIZED) == 0)
			continue;

		_copy_padded_string(label, sizeof label, info.label,
				    sizeof info.label);
		if (strcmp(label, token_label) != 0)
			continue;

		existing = _find_token_locked(entered, slots[i]);
		if (existing != nullptr) {
			existing->references++;
			*token = existing;
			free(slots);
			mtx_unlock(&entered->lock);
			_module_leave(entered);
			return HSM_OK;
		}

		status = _create_token_context(entered, slots[i], token);
		free(slots);
		mtx_unlock(&entered->lock);
		_module_leave(entered);
		return status;
	}

	free(slots);
	mtx_unlock(&entered->lock);
	_module_leave(entered);
	return _fail(HSM_ERR_TOKEN_NOT_FOUND, "hsm_token_open", 0,
		     "no initialized token with label \"%s\" was found",
		     token_label);
}

void hsm_token_close(hsm_token_t *token)
{
	struct hsm_module *module;
	struct hsm_token **link;

	if (token == nullptr)
		return;

	module = token->module;
	if (module == nullptr)
		return;

	mtx_lock(&module->lock);
	link = &module->tokens;
	while (*link != nullptr && *link != token)
		link = &(*link)->next;
	if (*link == nullptr) {
		mtx_unlock(&module->lock);
		return;
	}
	if (--token->references > 0) {
		mtx_unlock(&module->lock);
		return;
	}

	*link = token->next;
	_destroy_token(token);
	mtx_unlock(&module->lock);
}

static size_t _count_pooled_sessions_locked(const struct hsm_token *token)
{
	size_t count = 0;

	for (size_t i = 0; i < token->max_sessions; i++) {
		if (token->sessions[i].handle != CK_INVALID_HANDLE)
			count++;
	}
	return count;
}

hsm_status_t hsm_get_token_info(hsm_token_t *token, struct hsm_token_info *info)
{
	CK_TOKEN_INFO ck_info;
	CK_RV rv;
	hsm_status_t status;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_get_token_info",
				       "token must not be NULL");
	if (info == nullptr)
		return _argument_error("hsm_get_token_info",
				       "info must not be NULL");
	status = _require_module_ready(token->module, "hsm_get_token_info");
	if (status != HSM_OK)
		return status;

	mtx_lock(&token->lock);
	if (token->closing) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_SESSION, "hsm_get_token_info", 0,
			     "the token is closing");
	}

	rv = token->module->functions->C_GetTokenInfo(token->slot, &ck_info);
	if (rv != CKR_OK) {
		mtx_unlock(&token->lock);
		return _pkcs11_failure("C_GetTokenInfo", rv, HSM_ERR_DEVICE);
	}

	memset(info, 0, sizeof *info);
	_copy_padded_string(info->label, sizeof info->label, ck_info.label,
			    sizeof ck_info.label);
	_copy_padded_string(info->manufacturer, sizeof info->manufacturer,
			    ck_info.manufacturerID,
			    sizeof ck_info.manufacturerID);
	_copy_padded_string(info->model, sizeof info->model, ck_info.model,
			    sizeof ck_info.model);
	_copy_padded_string(info->serial, sizeof info->serial,
			    ck_info.serialNumber,
			    sizeof ck_info.serialNumber);
	info->flags = (unsigned long)ck_info.flags;
	info->logged_in = token->logged_in;
	info->session_count = _count_pooled_sessions_locked(token);

	mtx_unlock(&token->lock);
	return HSM_OK;
}

static hsm_status_t _ensure_login_session_locked(struct hsm_token *token)
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv;

	if (token->login_session != CK_INVALID_HANDLE)
		return HSM_OK;

	/*
	 * Use a read-write session for C_SetPIN(), falling back to read-only
	 * for write-protected tokens.
	 */
	rv = token->module->functions->C_OpenSession(
		token->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
		nullptr, &session);
	if (rv == CKR_TOKEN_WRITE_PROTECTED)
		rv = token->module->functions->C_OpenSession(
			token->slot, CKF_SERIAL_SESSION, nullptr, nullptr,
			&session);
	if (rv != CKR_OK)
		return _pkcs11_failure("C_OpenSession", rv, HSM_ERR_SESSION);

	token->login_session = session;
	return HSM_OK;
}

hsm_status_t hsm_token_login(hsm_token_t *token, const char *pin)
{
	CK_RV rv;
	hsm_status_t status;
	CK_ULONG ck_pin_len;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_token_login",
				       "token must not be NULL");
	if (pin == nullptr)
		return _argument_error("hsm_token_login",
				       "pin must not be NULL");
	status = _require_module_ready(token->module, "hsm_token_login");
	if (status != HSM_OK)
		return status;

	if (!_ck_ulong_from_size(strlen(pin), &ck_pin_len))
		return _argument_error("hsm_token_login",
				       "pin is too long for PKCS #11");

	mtx_lock(&token->lock);
	if (token->closing) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_SESSION, "hsm_token_login", 0,
			     "the token is closing");
	}
	if (token->logged_in) {
		mtx_unlock(&token->lock);
		return HSM_OK;
	}

	status = _ensure_login_session_locked(token);
	if (status != HSM_OK) {
		mtx_unlock(&token->lock);
		return status;
	}

	rv = token->module->functions->C_Login(
		token->login_session, CKU_USER, (CK_UTF8CHAR_PTR)(void *)pin,
		ck_pin_len);
	if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
		token->logged_in = true;
		mtx_unlock(&token->lock);
		return HSM_OK;
	}

	mtx_unlock(&token->lock);
	return _pkcs11_failure("C_Login", rv, HSM_ERR_PIN_INCORRECT);
}

hsm_status_t hsm_token_logout(hsm_token_t *token)
{
	CK_RV rv;
	hsm_status_t status;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_token_logout",
				       "token must not be NULL");
	status = _require_module_ready(token->module, "hsm_token_logout");
	if (status != HSM_OK)
		return status;

	mtx_lock(&token->lock);
	if (!token->logged_in) {
		mtx_unlock(&token->lock);
		return HSM_OK;
	}

	while (token->active_operations > 0) {
		if (cnd_wait(&token->condition, &token->lock)
		    != thrd_success) {
			mtx_unlock(&token->lock);
			return _fail(HSM_ERR_INTERNAL, "hsm_token_logout", 0,
				     "failed to wait for active operations");
		}
	}

	if (token->login_session != CK_INVALID_HANDLE) {
		rv = token->module->functions->C_Logout(token->login_session);
		if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
			mtx_unlock(&token->lock);
			return _pkcs11_failure("C_Logout", rv,
					       HSM_ERR_INTERNAL);
		}
	}

	token->logged_in = false;
	mtx_unlock(&token->lock);
	return HSM_OK;
}

hsm_status_t hsm_token_set_pin(hsm_token_t *token, const char *old_pin,
			       const char *new_pin)
{
	CK_RV rv;
	hsm_status_t status;
	CK_ULONG ck_old_pin_len;
	CK_ULONG ck_new_pin_len;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_token_set_pin",
				       "token must not be NULL");
	if (old_pin == nullptr || new_pin == nullptr)
		return _argument_error("hsm_token_set_pin",
				       "old_pin and new_pin must not be NULL");
	status = _require_module_ready(token->module, "hsm_token_set_pin");
	if (status != HSM_OK)
		return status;

	if (!_ck_ulong_from_size(strlen(old_pin), &ck_old_pin_len)
	    || !_ck_ulong_from_size(strlen(new_pin), &ck_new_pin_len))
		return _argument_error("hsm_token_set_pin",
				       "pin is too long for PKCS #11");

	mtx_lock(&token->lock);
	if (token->closing) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_SESSION, "hsm_token_set_pin", 0,
			     "the token is closing");
	}
	if (!token->logged_in) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_TOKEN_NOT_LOGGED_IN,
			     "hsm_token_set_pin", 0,
			     "the token must be logged in to change its PIN");
	}

	status = _ensure_login_session_locked(token);
	if (status != HSM_OK) {
		mtx_unlock(&token->lock);
		return status;
	}

	rv = token->module->functions->C_SetPIN(
		token->login_session, (CK_UTF8CHAR_PTR)(void *)old_pin,
		ck_old_pin_len, (CK_UTF8CHAR_PTR)(void *)new_pin,
		ck_new_pin_len);
	mtx_unlock(&token->lock);

	if (rv != CKR_OK)
		return _pkcs11_failure("C_SetPIN", rv, HSM_ERR_PIN_INCORRECT);
	return HSM_OK;
}

static hsm_status_t _acquire_session(struct hsm_token *token,
				     bool require_login,
				     const char *operation,
				     struct hsm_session_ref *reference)
{
	hsm_status_t status = HSM_OK;

	mtx_lock(&token->lock);
	for (;;) {
		size_t index = token->max_sessions;

		if (token->closing) {
			status = _fail(HSM_ERR_SESSION, operation, 0,
				       "the token is closing");
			break;
		}
		if (require_login && !token->logged_in) {
			status = _fail(HSM_ERR_TOKEN_NOT_LOGGED_IN,
				       operation, 0,
				       "the token is not logged in; call "
				       "hsm_token_login() first");
			break;
		}

		for (size_t i = 0; i < token->max_sessions; i++) {
			if (!token->sessions[i].in_use
			    && token->sessions[i].handle
				       != CK_INVALID_HANDLE) {
				index = i;
				break;
			}
		}

		if (index != token->max_sessions) {
			token->sessions[index].in_use = true;
			token->active_operations++;
			reference->index = index;
			reference->handle = token->sessions[index].handle;
			reference->closed = false;
			break;
		}

		if (token->session_count < token->max_sessions) {
			CK_SESSION_HANDLE handle = CK_INVALID_HANDLE;
			CK_RV rv;

			for (size_t i = 0; i < token->max_sessions; i++) {
				if (!token->sessions[i].in_use
				    && token->sessions[i].handle
					       == CK_INVALID_HANDLE) {
					index = i;
					break;
				}
			}
			if (index == token->max_sessions) {
				status = _fail(HSM_ERR_INTERNAL,
					       operation, 0,
					       "session pool accounting is "
					       "inconsistent");
				break;
			}

			rv = token->module->functions->C_OpenSession(
				token->slot, CKF_SERIAL_SESSION, nullptr,
				nullptr, &handle);
			if (rv != CKR_OK) {
				status = _pkcs11_failure("C_OpenSession", rv,
							 HSM_ERR_SESSION);
				break;
			}

			token->sessions[index].handle = handle;
			token->sessions[index].in_use = true;
			token->session_count++;
			token->active_operations++;
			reference->index = index;
			reference->handle = handle;
			reference->closed = false;
			break;
		}

		if (cnd_wait(&token->condition, &token->lock)
		    != thrd_success) {
			status = _fail(HSM_ERR_INTERNAL, operation, 0,
				       "failed to wait for a free session");
			break;
		}
	}
	mtx_unlock(&token->lock);

	return status;
}

static bool _reset_session(struct hsm_token *token,
			   struct hsm_session_ref *reference)
{
	CK_SESSION_HANDLE fresh = CK_INVALID_HANDLE;
	CK_RV rv;

	/*
	 * A size query or CKR_BUFFER_TOO_SMALL leaves the operation active;
	 * reopen the session to clean up.  If the close fails, do not open a
	 * second session: _release_session() retries the close and accounts
	 * for a session that could not be closed.
	 */
	rv = token->module->functions->C_CloseSession(reference->handle);
	if (rv != CKR_OK && rv != CKR_SESSION_HANDLE_INVALID)
		return false;
	reference->closed = true;

	rv = token->module->functions->C_OpenSession(
		token->slot, CKF_SERIAL_SESSION, nullptr, nullptr, &fresh);
	if (rv != CKR_OK) {
		reference->handle = CK_INVALID_HANDLE;
		return false;
	}

	reference->handle = fresh;
	reference->closed = false;
	return true;
}

/*
 * Keep the cached login state in sync when the token reports that its session
 * or login is gone.  Later operations must ask for a fresh login instead of
 * assuming the cached flag.
 */
static void _note_token_login_failure(struct hsm_token *token, CK_RV rv)
{
	bool lost_login = rv == CKR_USER_NOT_LOGGED_IN
		|| rv == CKR_USER_PIN_NOT_INITIALIZED;
	bool lost_session = rv == CKR_SESSION_HANDLE_INVALID
		|| rv == CKR_SESSION_CLOSED;

	if (!lost_login && !lost_session)
		return;

	mtx_lock(&token->lock);
	token->logged_in = false;
	if (lost_session && token->login_session != CK_INVALID_HANDLE) {
		(void) token->module->functions->C_CloseSession(
			token->login_session);
		token->login_session = CK_INVALID_HANDLE;
	}
	mtx_unlock(&token->lock);
}

static void _release_session(struct hsm_token *token,
			     const struct hsm_session_ref *reference, bool usable)
{
	struct hsm_pool_session *session;
	bool closed = reference->closed
		|| reference->handle == CK_INVALID_HANDLE;

	/*
	 * A failed operation may leave the session unusable.  Close it rather
	 * than dropping the handle, so the token does not accumulate leaked
	 * sessions until C_Finalize().
	 */
	if (!usable && !closed) {
		CK_RV rv = token->module->functions->C_CloseSession(
			reference->handle);

		closed = rv == CKR_OK || rv == CKR_SESSION_HANDLE_INVALID;
		if (!closed)
			LOGW("C_CloseSession failed: %s (0x%lx); the token "
			     "session stays open and its pool slot is retired",
			     _pkcs11_rv_name(rv), (unsigned long) rv);
	}

	mtx_lock(&token->lock);
	session = &token->sessions[reference->index];
	session->handle = usable ? reference->handle : CK_INVALID_HANDLE;
	/*
	 * A session the token refused to close still occupies token capacity.
	 * Keep its slot marked in use and counted, so the pool cannot open
	 * more sessions than the token allows; C_Finalize() cleans it up.
	 */
	session->in_use = !usable && !closed;
	if (!usable && closed && token->session_count > 0)
		token->session_count--;
	if (token->active_operations > 0)
		token->active_operations--;
	cnd_broadcast(&token->condition);
	mtx_unlock(&token->lock);
}

/* Close a session whose operation failed, then return it to the pool. */
static void _release_failed_session(struct hsm_token *token,
				    struct hsm_session_ref *reference)
{
	const struct hsm_error *error = hsm_get_last_error();
	bool usable;

	_note_token_login_failure(token, (CK_RV) error->pkcs11_code);
	usable = _reset_session(token, reference);
	_release_session(token, reference, usable);
}

struct hsm_digest_info {
	CK_MECHANISM_TYPE mechanism;
	size_t size;
};

static bool _lookup_digest_mechanism(hsm_digest_alg_t algorithm,
				     struct hsm_digest_info *info)
{
	switch (algorithm) {
	case HSM_DIGEST_SHA1:
		*info = (struct hsm_digest_info){ CKM_SHA_1, 20 };
		return true;
	case HSM_DIGEST_SHA224:
		*info = (struct hsm_digest_info){ CKM_SHA224, 28 };
		return true;
	case HSM_DIGEST_SHA256:
		*info = (struct hsm_digest_info){ CKM_SHA256, 32 };
		return true;
	case HSM_DIGEST_SHA384:
		*info = (struct hsm_digest_info){ CKM_SHA384, 48 };
		return true;
	case HSM_DIGEST_SHA512:
		*info = (struct hsm_digest_info){ CKM_SHA512, 64 };
		return true;
	default:
		return false;
	}
}

size_t hsm_get_digest_size(hsm_digest_alg_t algorithm)
{
	struct hsm_digest_info info;

	return _lookup_digest_mechanism(algorithm, &info) ? info.size : 0;
}

static hsm_status_t _digest_on_session(CK_FUNCTION_LIST_PTR functions,
				       CK_SESSION_HANDLE session,
				       hsm_digest_alg_t algorithm,
				       const void *data, size_t data_len,
				       unsigned char *digest,
				       size_t digest_capacity,
				       size_t *digest_len)
{
	struct hsm_digest_info info;
	CK_MECHANISM mechanism;
	CK_ULONG produced;
	CK_ULONG ck_data_len;
	CK_RV rv;

	if (!_lookup_digest_mechanism(algorithm, &info)) {
		*digest_len = 0;
		return _argument_error("C_Digest",
				       "unsupported digest algorithm");
	}
	if (digest_capacity < info.size) {
		*digest_len = info.size;
		return _fail(HSM_ERR_BUFFER_TOO_SMALL, "C_Digest", 0,
			     "digest buffer too small: need %zu bytes",
			     info.size);
	}
	if (!_ck_ulong_from_size(data_len, &ck_data_len)
	    || !_ck_ulong_from_size(digest_capacity, &produced)) {
		*digest_len = 0;
		return _argument_error(
			"C_Digest",
			"input or output length is too large for PKCS #11");
	}

	mechanism = (CK_MECHANISM){
		.mechanism = info.mechanism,
		.pParameter = nullptr,
		.ulParameterLen = 0,
	};

	rv = functions->C_DigestInit(session, &mechanism);
	if (rv != CKR_OK)
		return _pkcs11_failure("C_DigestInit", rv, HSM_ERR_DIGEST);

	rv = functions->C_Digest(session,
				 _pkcs11_input_pointer(data, data_len),
				 ck_data_len, digest, &produced);
	if (rv != CKR_OK) {
		*digest_len = (size_t)produced;
		return _pkcs11_failure("C_Digest", rv, HSM_ERR_DIGEST);
	}

	*digest_len = (size_t)produced;
	return HSM_OK;
}

struct hsm_sign_mechanism {
	CK_MECHANISM_TYPE type;
	CK_RSA_PKCS_PSS_PARAMS pss;
	bool with_pss;
	bool ecdsa_with_hash;
	hsm_digest_alg_t hash;
	/* Expected CKA_PARAMETER_SET for ML-DSA; 0 when not applicable. */
	CK_ULONG parameter_set;
};

static bool _build_sign_mechanism(hsm_sign_alg_t algorithm,
				  struct hsm_sign_mechanism *result)
{
	*result = (struct hsm_sign_mechanism){ 0 };

	switch (algorithm) {
	case HSM_SIGN_RSA_PKCS1_SHA1:
		result->type = CKM_SHA1_RSA_PKCS;
		return true;
	case HSM_SIGN_RSA_PKCS1_SHA224:
		result->type = CKM_SHA224_RSA_PKCS;
		return true;
	case HSM_SIGN_RSA_PKCS1_SHA256:
		result->type = CKM_SHA256_RSA_PKCS;
		return true;
	case HSM_SIGN_RSA_PKCS1_SHA384:
		result->type = CKM_SHA384_RSA_PKCS;
		return true;
	case HSM_SIGN_RSA_PKCS1_SHA512:
		result->type = CKM_SHA512_RSA_PKCS;
		return true;
	case HSM_SIGN_RSA_PSS_SHA256:
		result->type = CKM_SHA256_RSA_PKCS_PSS;
		result->with_pss = true;
		result->pss.hashAlg = CKM_SHA256;
		result->pss.mgf = CKG_MGF1_SHA256;
		result->pss.sLen = 32;
		return true;
	case HSM_SIGN_RSA_PSS_SHA384:
		result->type = CKM_SHA384_RSA_PKCS_PSS;
		result->with_pss = true;
		result->pss.hashAlg = CKM_SHA384;
		result->pss.mgf = CKG_MGF1_SHA384;
		result->pss.sLen = 48;
		return true;
	case HSM_SIGN_RSA_PSS_SHA512:
		result->type = CKM_SHA512_RSA_PKCS_PSS;
		result->with_pss = true;
		result->pss.hashAlg = CKM_SHA512;
		result->pss.mgf = CKG_MGF1_SHA512;
		result->pss.sLen = 64;
		return true;
	case HSM_SIGN_ECDSA_SHA1:
		result->type = CKM_ECDSA_SHA1;
		result->ecdsa_with_hash = true;
		result->hash = HSM_DIGEST_SHA1;
		return true;
	case HSM_SIGN_ECDSA_SHA224:
		result->type = CKM_ECDSA_SHA224;
		result->ecdsa_with_hash = true;
		result->hash = HSM_DIGEST_SHA224;
		return true;
	case HSM_SIGN_ECDSA_SHA256:
		result->type = CKM_ECDSA_SHA256;
		result->ecdsa_with_hash = true;
		result->hash = HSM_DIGEST_SHA256;
		return true;
	case HSM_SIGN_ECDSA_SHA384:
		result->type = CKM_ECDSA_SHA384;
		result->ecdsa_with_hash = true;
		result->hash = HSM_DIGEST_SHA384;
		return true;
	case HSM_SIGN_ECDSA_SHA512:
		result->type = CKM_ECDSA_SHA512;
		result->ecdsa_with_hash = true;
		result->hash = HSM_DIGEST_SHA512;
		return true;
	case HSM_SIGN_ML_DSA_44:
		result->type = CKM_ML_DSA;
		result->parameter_set = CKP_ML_DSA_44;
		return true;
	case HSM_SIGN_ML_DSA_65:
		result->type = CKM_ML_DSA;
		result->parameter_set = CKP_ML_DSA_65;
		return true;
	case HSM_SIGN_ML_DSA_87:
		result->type = CKM_ML_DSA;
		result->parameter_set = CKP_ML_DSA_87;
		return true;
	default:
		return false;
	}
}

static hsm_status_t _find_key_by_label(CK_FUNCTION_LIST_PTR functions,
				       CK_SESSION_HANDLE session,
				       const char *label,
				       CK_OBJECT_CLASS object_class,
				       CK_OBJECT_HANDLE *key)
{
	CK_OBJECT_CLASS class_value = object_class;
	CK_ATTRIBUTE attributes[] = {
		{
			.type = CKA_CLASS,
			.pValue = &class_value,
			.ulValueLen = (CK_ULONG)sizeof class_value,
		},
		{
			.type = CKA_LABEL,
			.pValue = (void *)label,
			.ulValueLen = 0,
		},
	};
	CK_ULONG found = 0;
	CK_RV rv;
	CK_RV final_rv;

	if (!_ck_ulong_from_size(strlen(label), &attributes[1].ulValueLen))
		return _argument_error("C_FindObjectsInit",
				       "label is too long for PKCS #11");

	rv = functions->C_FindObjectsInit(
		session, attributes,
		(CK_ULONG)(sizeof attributes / sizeof attributes[0]));
	if (rv != CKR_OK)
		return _pkcs11_failure("C_FindObjectsInit", rv,
				       HSM_ERR_INTERNAL);

	rv = functions->C_FindObjects(session, key, 1, &found);
	final_rv = functions->C_FindObjectsFinal(session);

	if (rv == CKR_OK && final_rv != CKR_OK)
		return _pkcs11_failure("C_FindObjectsFinal", final_rv,
				       HSM_ERR_INTERNAL);
	if (rv != CKR_OK)
		return _pkcs11_failure("C_FindObjects", rv, HSM_ERR_INTERNAL);
	if (found == 0)
		return _fail(HSM_ERR_OBJECT_NOT_FOUND, "C_FindObjects", 0,
			     "no %s key with label \"%s\" was found",
			     object_class == CKO_PRIVATE_KEY ? "private"
							     : "public",
			     label);

	return HSM_OK;
}

static hsm_status_t _check_key_parameter_set(CK_FUNCTION_LIST_PTR functions,
					     CK_SESSION_HANDLE session,
					     CK_OBJECT_HANDLE key,
					     CK_ULONG expected,
					     const char *operation)
{
	CK_ULONG parameter_set = 0;
	CK_ATTRIBUTE attribute = {
		.type = CKA_PARAMETER_SET,
		.pValue = &parameter_set,
		.ulValueLen = (CK_ULONG)sizeof parameter_set,
	};
	CK_RV rv;

	rv = functions->C_GetAttributeValue(session, key, &attribute, 1);
	if (rv != CKR_OK)
		return _pkcs11_failure("C_GetAttributeValue", rv,
				       HSM_ERR_MECHANISM);
	if (parameter_set != expected)
		return _fail(HSM_ERR_MECHANISM, operation, 0,
			     "the key parameter set does not match the "
			     "requested algorithm");
	return HSM_OK;
}

static bool _ml_dsa_parameter_set_to_ck(hsm_ml_dsa_parameter_set_t value,
					CK_ULONG *result)
{
	switch (value) {
	case HSM_ML_DSA_44:
		*result = CKP_ML_DSA_44;
		return true;
	case HSM_ML_DSA_65:
		*result = CKP_ML_DSA_65;
		return true;
	case HSM_ML_DSA_87:
		*result = CKP_ML_DSA_87;
		return true;
	}
	return false;
}

static bool _ml_dsa_parameter_set_from_ck(CK_ULONG value,
					  hsm_ml_dsa_parameter_set_t *result)
{
	switch (value) {
	case CKP_ML_DSA_44:
		*result = HSM_ML_DSA_44;
		return true;
	case CKP_ML_DSA_65:
		*result = HSM_ML_DSA_65;
		return true;
	case CKP_ML_DSA_87:
		*result = HSM_ML_DSA_87;
		return true;
	}
	return false;
}

/*
 * Read a CK_BBOOL attribute.  Tokens that do not implement the attribute
 * report CKR_ATTRIBUTE_TYPE_INVALID; that is treated as CK_FALSE.
 */
static hsm_status_t _get_bool_attribute(CK_FUNCTION_LIST_PTR functions,
					CK_SESSION_HANDLE session,
					CK_OBJECT_HANDLE object,
					CK_ATTRIBUTE_TYPE type,
					bool *value)
{
	CK_BBOOL attribute_value = CK_FALSE;
	CK_ATTRIBUTE attribute = {
		.type = type,
		.pValue = &attribute_value,
		.ulValueLen = (CK_ULONG)sizeof attribute_value,
	};
	CK_RV rv;

	*value = false;
	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv == CKR_ATTRIBUTE_TYPE_INVALID
	    || rv == CKR_ATTRIBUTE_SENSITIVE)
		return HSM_OK;
	if (rv != CKR_OK)
		return _pkcs11_failure("C_GetAttributeValue", rv,
				       HSM_ERR_INTERNAL);
	*value = attribute_value != CK_FALSE;
	return HSM_OK;
}

typedef CK_RV (*init_operation_fn)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
				   CK_OBJECT_HANDLE);

static hsm_status_t _init_signature_operation(
	CK_FUNCTION_LIST_PTR functions, CK_SESSION_HANDLE session,
	init_operation_fn init, const char *operation,
	const struct hsm_sign_mechanism *spec, CK_OBJECT_HANDLE key,
	const void *data, size_t data_len, const void **operation_data,
	size_t *operation_len, unsigned char *digest, size_t digest_size)
{
	CK_MECHANISM mechanism = {
		.mechanism = spec->type,
		.pParameter = spec->with_pss ? (void *)&spec->pss : nullptr,
		.ulParameterLen
		= spec->with_pss ? (CK_ULONG)sizeof spec->pss : 0,
	};
	CK_RV rv;

	*operation_data = data;
	*operation_len = data_len;

	rv = init(session, &mechanism, key);
	if (rv != CKR_OK && spec->ecdsa_with_hash
	    && (rv == CKR_MECHANISM_INVALID
		|| rv == CKR_FUNCTION_NOT_SUPPORTED)) {
		/*
		 * Some tokens only expose raw CKM_ECDSA; hash first, then sign
		 * the digest.
		 */
		CK_MECHANISM raw = {
			.mechanism = CKM_ECDSA,
			.pParameter = nullptr,
			.ulParameterLen = 0,
		};
		hsm_status_t status;
		size_t digest_len = 0;

		status = _digest_on_session(functions, session, spec->hash, data,
					    data_len, digest, digest_size,
					    &digest_len);
		if (status != HSM_OK)
			return status;

		rv = init(session, &raw, key);
		if (rv == CKR_OK) {
			*operation_data = digest;
			*operation_len = digest_len;
		}
	}

	if (rv != CKR_OK)
		return _pkcs11_failure(operation, rv, HSM_ERR_MECHANISM);
	return HSM_OK;
}

hsm_status_t hsm_digest(hsm_token_t *token, hsm_digest_alg_t algorithm,
			const void *data, size_t data_len,
			unsigned char *digest, size_t digest_capacity,
			size_t *digest_len)
{
	struct hsm_digest_info info;
	struct hsm_session_ref reference;
	hsm_status_t status;

	_reset_last_error();

	if (digest_len == nullptr)
		return _argument_error("hsm_digest",
				       "digest_len must not be NULL");
	*digest_len = 0;
	if (token == nullptr)
		return _argument_error("hsm_digest",
				       "token must not be NULL");
	if (data == nullptr && data_len != 0)
		return _argument_error(
			"hsm_digest",
			"data must not be NULL when data_len is nonzero");
	if (!_lookup_digest_mechanism(algorithm, &info))
		return _argument_error("hsm_digest",
				       "unsupported digest algorithm");

	if (digest == nullptr) {
		*digest_len = info.size;
		return HSM_OK;
	}
	if (digest_capacity < info.size) {
		*digest_len = info.size;
		return _fail(HSM_ERR_BUFFER_TOO_SMALL, "hsm_digest", 0,
			     "digest buffer too small: need %zu bytes",
			     info.size);
	}

	status = _require_module_ready(token->module, "hsm_digest");
	if (status != HSM_OK)
		return status;

	status = _acquire_session(token, false, "hsm_digest", &reference);
	if (status != HSM_OK)
		return status;

	status = _digest_on_session(token->module->functions, reference.handle,
				    algorithm, data, data_len, digest,
				    digest_capacity, digest_len);
	if (status != HSM_OK)
		_release_failed_session(token, &reference);
	else
		_release_session(token, &reference, true);
	return status;
}

hsm_status_t hsm_sign_with_pin(hsm_token_t *token, hsm_sign_alg_t algorithm,
			       const char *key_label, const char *pin,
			       const void *data, size_t data_len,
			       unsigned char *signature,
			       size_t signature_capacity,
			       size_t *signature_len)
{
	struct hsm_sign_mechanism spec;
	struct hsm_session_ref reference;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	const void *operation_data;
	size_t operation_len;
	unsigned char digest[HSM_DIGEST_MAX];
	CK_ULONG produced;
	CK_ULONG ck_signature_capacity;
	CK_ULONG ck_pin_len;
	CK_RV rv;
	hsm_status_t status;
	bool always_authenticate = false;

	_reset_last_error();

	if (signature_len == nullptr)
		return _argument_error("hsm_sign",
				       "signature_len must not be NULL");
	*signature_len = 0;
	if (token == nullptr)
		return _argument_error("hsm_sign",
				       "token must not be NULL");
	if (key_label == nullptr || key_label[0] == '\0')
		return _argument_error("hsm_sign",
				       "key_label must not be NULL or empty");
	if (data == nullptr && data_len != 0)
		return _argument_error(
			"hsm_sign",
			"data must not be NULL when data_len is nonzero");
	if (!_size_fits_ck_ulong(data_len))
		return _argument_error("hsm_sign",
				       "data is too large for PKCS #11");
	if (!_ck_ulong_from_size(signature_capacity,
				 &ck_signature_capacity))
		return _argument_error(
			"hsm_sign",
			"signature buffer is too large for PKCS #11");
	if (!_build_sign_mechanism(algorithm, &spec))
		return _argument_error("hsm_sign",
				       "unsupported signature algorithm");

	status = _require_module_ready(token->module, "hsm_sign");
	if (status != HSM_OK)
		return status;

	status = _acquire_session(token, true, "hsm_sign", &reference);
	if (status != HSM_OK)
		return status;

	status = _find_key_by_label(token->module->functions,
				    reference.handle, key_label,
				    CKO_PRIVATE_KEY, &key);
	if (status != HSM_OK) {
		_release_failed_session(token, &reference);
		return status;
	}
	if (spec.parameter_set != 0) {
		status = _check_key_parameter_set(
			token->module->functions, reference.handle, key,
			spec.parameter_set, "hsm_sign");
		if (status != HSM_OK) {
			_release_failed_session(token, &reference);
			return status;
		}
	}

	status = _get_bool_attribute(token->module->functions,
				     reference.handle, key,
				     CKA_ALWAYS_AUTHENTICATE,
				     &always_authenticate);
	if (status != HSM_OK) {
		_release_failed_session(token, &reference);
		return status;
	}

	status = _init_signature_operation(
		token->module->functions, reference.handle,
		token->module->functions->C_SignInit, "C_SignInit", &spec, key,
		data, data_len, &operation_data, &operation_len, digest,
		sizeof digest);
	if (status != HSM_OK) {
		_release_failed_session(token, &reference);
		return status;
	}

	/*
	 * PKCS #11 requires C_Login(CKU_CONTEXT_SPECIFIC) after C_SignInit()
	 * for a key with CKA_ALWAYS_AUTHENTICATE, on the same session.  The
	 * login authorizes one operation only.
	 */
	if (always_authenticate) {
		if (pin == nullptr || pin[0] == '\0') {
			_release_failed_session(token, &reference);
			return _fail(
				HSM_ERR_TOKEN_NOT_LOGGED_IN, "C_Login", 0,
				"the key requires context-specific "
				"authentication; a PIN is required");
		}
		if (!_ck_ulong_from_size(strlen(pin), &ck_pin_len)) {
			_release_failed_session(token, &reference);
			return _argument_error("hsm_sign",
					       "pin is too long for PKCS #11");
		}
		rv = token->module->functions->C_Login(
			reference.handle, CKU_CONTEXT_SPECIFIC,
			(CK_UTF8CHAR_PTR)(void *)pin, ck_pin_len);
		if (rv != CKR_OK) {
			status = _pkcs11_failure("C_Login", rv,
						 HSM_ERR_PIN_INCORRECT);
			_release_failed_session(token, &reference);
			return status;
		}
	}

	produced = ck_signature_capacity;
	/*
	 * operation_len is either the caller's data_len, which was range-checked
	 * above, or a digest of at most HSM_DIGEST_MAX bytes.
	 */
	rv = token->module->functions->C_Sign(
		reference.handle,
		_pkcs11_input_pointer(operation_data, operation_len),
		(CK_ULONG)operation_len, signature, &produced);

	if (signature == nullptr) {
		/* A NULL output queries the size; reset the session afterwards. */
		if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
			*signature_len = (size_t)produced;
		else
			status = _pkcs11_failure("C_Sign", rv, HSM_ERR_SIGN);

		_release_failed_session(token, &reference);
		return status;
	}

	if (rv == CKR_BUFFER_TOO_SMALL) {
		*signature_len = (size_t)produced;
		_release_failed_session(token, &reference);
		return _fail(HSM_ERR_BUFFER_TOO_SMALL, "C_Sign",
			     (unsigned long)rv,
			     "signature buffer too small: need %lu bytes",
			     (unsigned long)produced);
	}
	if (rv != CKR_OK) {
		status = _pkcs11_failure("C_Sign", rv, HSM_ERR_SIGN);
		_release_failed_session(token, &reference);
		return status;
	}

	*signature_len = (size_t)produced;
	_release_session(token, &reference, true);
	return HSM_OK;
}

hsm_status_t hsm_sign(hsm_token_t *token, hsm_sign_alg_t algorithm,
		      const char *key_label, const void *data,
		      size_t data_len, unsigned char *signature,
		      size_t signature_capacity, size_t *signature_len)
{
	return hsm_sign_with_pin(token, algorithm, key_label, nullptr, data,
				 data_len, signature, signature_capacity,
				 signature_len);
}

/*
 * Read a variable-length PKCS #11 attribute.  A zero-length attribute yields
 * a NULL buffer and length zero; otherwise the buffer is osal_malloc()ed.
 */
static hsm_status_t _get_attribute_alloc(CK_FUNCTION_LIST_PTR functions,
					 CK_SESSION_HANDLE session,
					 CK_OBJECT_HANDLE object,
					 CK_ATTRIBUTE_TYPE type,
					 const char *operation,
					 unsigned char **data,
					 size_t *length)
{
	CK_ATTRIBUTE attribute = {
		.type = type,
		.pValue = nullptr,
		.ulValueLen = 0,
	};
	CK_ULONG capacity;
	unsigned char *buffer;
	CK_RV rv;

	*data = nullptr;
	*length = 0;

	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK)
		return _pkcs11_failure(operation, rv, HSM_ERR_INTERNAL);
	if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return _fail(HSM_ERR_INTERNAL, operation, 0,
			     "PKCS #11 attribute 0x%lx is unavailable",
			     (unsigned long)type);
	if (attribute.ulValueLen == 0)
		return HSM_OK;

	capacity = attribute.ulValueLen;
	buffer = osal_malloc((size_t)capacity);
	if (buffer == nullptr)
		return _fail(HSM_ERR_MEMORY, operation, 0, "out of memory");

	attribute.pValue = buffer;
	attribute.ulValueLen = capacity;
	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK) {
		osal_free(buffer);
		return _pkcs11_failure(operation, rv, HSM_ERR_INTERNAL);
	}
	if (attribute.ulValueLen > capacity) {
		osal_free(buffer);
		return _fail(HSM_ERR_INTERNAL, operation, 0,
			     "PKCS #11 attribute 0x%lx grew while reading",
			     (unsigned long)type);
	}

	*data = buffer;
	*length = (size_t)attribute.ulValueLen;
	return HSM_OK;
}

/*
 * PKCS #11 wraps CKA_EC_POINT in a DER OCTET STRING.  Return the point
 * octets inside the wrapper.
 */
static bool _ec_point_content(const unsigned char *encoded,
			      size_t encoded_length,
			      const unsigned char **point,
			      size_t *point_length)
{
	const unsigned char *cursor = encoded;
	ossl_asn1_tlv_t tlv;
	size_t header_length;

	if (encoded == nullptr || point == nullptr || point_length == nullptr
	    || encoded_length == 0
	    || encoded_length > (size_t) LONG_MAX)
		return false;

	if (!ossl_asn1_expect_tlv(&cursor, (long) encoded_length,
				  V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL, &tlv)
	    || tlv.constructed)
		return false;

	/* The OCTET STRING must occupy the whole attribute value. */
	header_length = (size_t) (cursor - encoded);
	if (tlv.content_length < 0
	    || (size_t) tlv.content_length != encoded_length - header_length)
		return false;

	*point = tlv.content;
	*point_length = (size_t) tlv.content_length;
	return true;
}

hsm_status_t hsm_get_public_key(hsm_token_t *token, const char *key_label,
				hsm_public_key_t *key)
{
	struct hsm_session_ref reference;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE attribute = {
		.type = CKA_KEY_TYPE,
		.pValue = &key_type,
		.ulValueLen = (CK_ULONG)sizeof key_type,
	};
	hsm_status_t status;
	CK_RV rv;

	_reset_last_error();

	if (key == nullptr)
		return _argument_error("hsm_get_public_key",
				       "key must not be NULL");
	memset(key, 0, sizeof *key);
	if (token == nullptr)
		return _argument_error("hsm_get_public_key",
				       "token must not be NULL");
	if (key_label == nullptr || key_label[0] == '\0')
		return _argument_error(
			"hsm_get_public_key",
			"key_label must not be NULL or empty");

	status = _require_module_ready(token->module, "hsm_get_public_key");
	if (status != HSM_OK)
		return status;

	status = _acquire_session(token, false, "hsm_get_public_key",
				  &reference);
	if (status != HSM_OK)
		return status;

	status = _find_key_by_label(token->module->functions,
				    reference.handle, key_label,
				    CKO_PUBLIC_KEY, &object);
	if (status != HSM_OK)
		goto done;

	rv = token->module->functions->C_GetAttributeValue(
		reference.handle, object, &attribute, 1);
	if (rv != CKR_OK) {
		status = _pkcs11_failure("C_GetAttributeValue", rv,
					 HSM_ERR_INTERNAL);
		goto done;
	}

	switch (key_type) {
	case CKK_RSA:
		key->type = HSM_KEY_TYPE_RSA;
		status = _get_attribute_alloc(
			token->module->functions, reference.handle, object,
			CKA_MODULUS, "hsm_get_public_key", &key->modulus,
			&key->modulus_length);
		if (status != HSM_OK)
			goto done;
		status = _get_attribute_alloc(
			token->module->functions, reference.handle, object,
			CKA_PUBLIC_EXPONENT, "hsm_get_public_key",
			&key->exponent, &key->exponent_length);
		break;
	case CKK_EC: {
		unsigned char *encoded = nullptr;
		size_t encoded_length = 0;
		const unsigned char *point;
		size_t point_length;

		key->type = HSM_KEY_TYPE_EC;
		status = _get_attribute_alloc(
			token->module->functions, reference.handle, object,
			CKA_EC_PARAMS, "hsm_get_public_key", &key->ec_params,
			&key->ec_params_length);
		if (status != HSM_OK)
			goto done;

		status = _get_attribute_alloc(
			token->module->functions, reference.handle, object,
			CKA_EC_POINT, "hsm_get_public_key", &encoded,
			&encoded_length);
		if (status != HSM_OK)
			goto done;

		if (!_ec_point_content(encoded, encoded_length, &point,
				       &point_length) || point_length == 0) {
			osal_free(encoded);
			status = _fail(
				HSM_ERR_MECHANISM, "hsm_get_public_key", 0,
				"CKA_EC_POINT is not a DER OCTET STRING");
			goto done;
		}

		key->ec_point = osal_malloc(point_length);
		if (key->ec_point == nullptr) {
			osal_free(encoded);
			status = _fail(HSM_ERR_MEMORY, "hsm_get_public_key",
				       0, "out of memory");
			goto done;
		}
		memcpy(key->ec_point, point, point_length);
		key->ec_point_length = point_length;
		osal_free(encoded);
		break;
	}
	case CKK_ML_DSA: {
		CK_ULONG parameter_set = 0;
		CK_ATTRIBUTE parameter_attribute = {
			.type = CKA_PARAMETER_SET,
			.pValue = &parameter_set,
			.ulValueLen = (CK_ULONG)sizeof parameter_set,
		};

		key->type = HSM_KEY_TYPE_ML_DSA;
		rv = token->module->functions->C_GetAttributeValue(
			reference.handle, object, &parameter_attribute, 1);
		if (rv != CKR_OK) {
			status = _pkcs11_failure("C_GetAttributeValue", rv,
						 HSM_ERR_MECHANISM);
			goto done;
		}
		if (!_ml_dsa_parameter_set_from_ck(
			    parameter_set, &key->ml_dsa_parameter_set)) {
			status = _fail(HSM_ERR_MECHANISM,
				       "hsm_get_public_key", 0,
				       "unsupported ML-DSA parameter set: "
				       "0x%lx",
				       (unsigned long)parameter_set);
			goto done;
		}
		status = _get_attribute_alloc(
			token->module->functions, reference.handle, object,
			CKA_VALUE, "hsm_get_public_key", &key->ml_dsa_key,
			&key->ml_dsa_key_length);
		break;
	}
	default:
		status = _fail(HSM_ERR_MECHANISM, "hsm_get_public_key", 0,
			       "unsupported public key type: 0x%lx",
			       (unsigned long)key_type);
		break;
	}

done:
	if (status != HSM_OK) {
		hsm_public_key_free(key);
		_release_failed_session(token, &reference);
	} else {
		_release_session(token, &reference, true);
	}
	return status;
}

void hsm_public_key_free(hsm_public_key_t *key)
{
	if (key == nullptr)
		return;

	osal_free(key->modulus);
	osal_free(key->exponent);
	osal_free(key->ec_params);
	osal_free(key->ec_point);
	osal_free(key->ml_dsa_key);
	memset(key, 0, sizeof *key);
}

/*
 * Read an optional variable-length attribute.  *available is false when the
 * token reports the attribute as unavailable; that is not an error.
 */
static hsm_status_t _get_attribute_optional(CK_FUNCTION_LIST_PTR functions,
					    CK_SESSION_HANDLE session,
					    CK_OBJECT_HANDLE object,
					    CK_ATTRIBUTE_TYPE type,
					    unsigned char **data,
					    size_t *length, bool *available)
{
	CK_ATTRIBUTE attribute = {
		.type = type,
		.pValue = nullptr,
		.ulValueLen = 0,
	};
	CK_ULONG capacity;
	unsigned char *buffer;
	CK_RV rv;

	*data = nullptr;
	*length = 0;
	*available = false;

	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_ATTRIBUTE_SENSITIVE)
		return HSM_OK;
	if (rv != CKR_OK)
		return _pkcs11_failure("C_GetAttributeValue", rv,
				       HSM_ERR_INTERNAL);
	if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return HSM_OK;
	if (attribute.ulValueLen == 0) {
		*available = true;
		return HSM_OK;
	}

	capacity = attribute.ulValueLen;
	buffer = osal_malloc((size_t) capacity);
	if (buffer == nullptr)
		return _fail(HSM_ERR_MEMORY, "C_GetAttributeValue", 0,
			     "out of memory");

	attribute.pValue = buffer;
	attribute.ulValueLen = capacity;
	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK || attribute.ulValueLen > capacity) {
		osal_free(buffer);
		if (rv != CKR_OK)
			return _pkcs11_failure("C_GetAttributeValue", rv,
					       HSM_ERR_INTERNAL);
		return _fail(HSM_ERR_INTERNAL, "C_GetAttributeValue", 0,
			     "PKCS #11 attribute 0x%lx grew while reading",
			     (unsigned long) type);
	}

	*data = buffer;
	*length = (size_t) attribute.ulValueLen;
	*available = true;
	return HSM_OK;
}

static hsm_status_t _get_label_copy(CK_FUNCTION_LIST_PTR functions,
				    CK_SESSION_HANDLE session,
				    CK_OBJECT_HANDLE object, char **label)
{
	unsigned char *data = nullptr;
	size_t length = 0;
	bool available;
	char *text;
	hsm_status_t status;

	*label = nullptr;
	status = _get_attribute_optional(functions, session, object, CKA_LABEL,
					 &data, &length, &available);
	if (status != HSM_OK)
		return status;
	if (!available || length == 0) {
		osal_free(data);
		return HSM_OK;
	}

	text = osal_malloc(length + 1);
	if (text == nullptr) {
		osal_free(data);
		return _fail(HSM_ERR_MEMORY, "C_GetAttributeValue", 0,
			     "out of memory");
	}
	memcpy(text, data, length);
	text[length] = '\0';
	osal_free(data);
	*label = text;
	return HSM_OK;
}

static unsigned _integer_bits(const unsigned char *data, size_t length)
{
	unsigned bits;

	while (length > 0 && data[0] == 0) {
		data++;
		length--;
	}
	if (length == 0 || length > (size_t) UINT_MAX / 8)
		return 0;

	bits = (unsigned) (length - 1) * 8;
	for (unsigned char top = data[0]; top != 0; top >>= 1)
		bits++;
	return bits;
}

static hsm_status_t _get_rsa_bits(CK_FUNCTION_LIST_PTR functions,
				  CK_SESSION_HANDLE session,
				  CK_OBJECT_HANDLE object, unsigned int *bits)
{
	CK_ULONG modulus_bits = 0;
	CK_ATTRIBUTE attribute = {
		.type = CKA_MODULUS_BITS,
		.pValue = &modulus_bits,
		.ulValueLen = (CK_ULONG) sizeof modulus_bits,
	};
	unsigned char *modulus = nullptr;
	size_t modulus_length = 0;
	bool available;
	hsm_status_t status;
	CK_RV rv;

	*bits = 0;
	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv == CKR_OK && modulus_bits > 0
	    && modulus_bits <= (CK_ULONG) UINT_MAX) {
		*bits = (unsigned int) modulus_bits;
		return HSM_OK;
	}

	status = _get_attribute_optional(functions, session, object,
					 CKA_MODULUS, &modulus,
					 &modulus_length, &available);
	if (status != HSM_OK)
		return status;
	if (available && modulus_length > 0)
		*bits = _integer_bits(modulus, modulus_length);
	osal_free(modulus);
	return HSM_OK;
}

static hsm_status_t _read_key_object(CK_FUNCTION_LIST_PTR functions,
				     CK_SESSION_HANDLE session,
				     CK_OBJECT_HANDLE object,
				     CK_OBJECT_CLASS object_class,
				     hsm_key_object_t *info, bool *include)
{
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE attribute = {
		.type = CKA_KEY_TYPE,
		.pValue = &key_type,
		.ulValueLen = (CK_ULONG) sizeof key_type,
	};
	bool available;
	hsm_status_t status;
	CK_RV rv;

	memset(info, 0, sizeof *info);
	*include = false;
	info->key_class = object_class == CKO_PRIVATE_KEY
				  ? HSM_KEY_CLASS_PRIVATE
				  : HSM_KEY_CLASS_PUBLIC;

	rv = functions->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK)
		return HSM_OK;

	switch (key_type) {
	case CKK_RSA:
		info->key_type = HSM_KEY_TYPE_RSA;
		status = _get_rsa_bits(functions, session, object,
				       &info->rsa_bits);
		break;
	case CKK_EC:
		info->key_type = HSM_KEY_TYPE_EC;
		status = _get_attribute_optional(
			functions, session, object, CKA_EC_PARAMS,
			&info->ec_params, &info->ec_params_length, &available);
		break;
	case CKK_ML_DSA: {
		CK_ULONG parameter_set = 0;
		CK_ATTRIBUTE parameter_attribute = {
			.type = CKA_PARAMETER_SET,
			.pValue = &parameter_set,
			.ulValueLen = (CK_ULONG) sizeof parameter_set,
		};

		rv = functions->C_GetAttributeValue(session, object,
						    &parameter_attribute, 1);
		if (rv != CKR_OK
		    || !_ml_dsa_parameter_set_from_ck(
			    parameter_set, &info->ml_dsa_parameter_set))
			return HSM_OK;
		info->key_type = HSM_KEY_TYPE_ML_DSA;
		status = HSM_OK;
		break;
	}
	default:
		return HSM_OK;
	}
	if (status != HSM_OK)
		goto fail;

	status = _get_label_copy(functions, session, object, &info->label);
	if (status != HSM_OK)
		goto fail;
	if (info->label == nullptr) {
		osal_free(info->ec_params);
		info->ec_params = nullptr;
		info->ec_params_length = 0;
		return HSM_OK;
	}

	*include = true;
	return HSM_OK;

fail:
	osal_free(info->label);
	info->label = nullptr;
	osal_free(info->ec_params);
	info->ec_params = nullptr;
	info->ec_params_length = 0;
	return status;
}

static bool _append_key_object(hsm_key_object_t **objects, size_t *count,
			       size_t *capacity, hsm_key_object_t *info)
{
	if (*count == *capacity) {
		size_t new_capacity = *capacity == 0 ? 16 : *capacity * 2;
		hsm_key_object_t *grown;

		if (new_capacity < *capacity
		    || new_capacity > (size_t) -1 / sizeof **objects)
			return false;
		grown = osal_realloc(*objects,
				     new_capacity * sizeof **objects);
		if (grown == nullptr)
			return false;
		*objects = grown;
		*capacity = new_capacity;
	}

	(*objects)[(*count)++] = *info;
	return true;
}

static hsm_status_t _find_key_objects(CK_FUNCTION_LIST_PTR functions,
				      CK_SESSION_HANDLE session,
				      CK_OBJECT_CLASS object_class,
				      hsm_key_object_t **objects,
				      size_t *count, size_t *capacity)
{
	CK_OBJECT_CLASS class_value = object_class;
	CK_ATTRIBUTE attributes[] = {
		{
			.type = CKA_CLASS,
			.pValue = &class_value,
			.ulValueLen = (CK_ULONG) sizeof class_value,
		},
	};
	CK_OBJECT_HANDLE batch[32];
	hsm_status_t status = HSM_OK;
	CK_RV final_rv;
	CK_RV rv;

	rv = functions->C_FindObjectsInit(
		session, attributes,
		(CK_ULONG)(sizeof attributes / sizeof attributes[0]));
	if (rv != CKR_OK)
		return _pkcs11_failure("C_FindObjectsInit", rv,
				       HSM_ERR_INTERNAL);

	for (;;) {
		CK_ULONG found = 0;

		rv = functions->C_FindObjects(
			session, batch, (CK_ULONG)(sizeof batch / sizeof batch[0]),
			&found);
		if (rv != CKR_OK) {
			status = _pkcs11_failure("C_FindObjects", rv,
						 HSM_ERR_INTERNAL);
			break;
		}
		if (found == 0)
			break;
		if (found > (CK_ULONG)(sizeof batch / sizeof batch[0])) {
			status = _fail(HSM_ERR_INTERNAL, "C_FindObjects", 0,
				       "token returned more objects than "
				       "requested");
			break;
		}

		for (CK_ULONG i = 0; i < found; i++) {
			hsm_key_object_t info;
			bool include;

			status = _read_key_object(functions, session, batch[i],
						  object_class, &info,
						  &include);
			if (status != HSM_OK)
				break;
			if (!include)
				continue;
			if (!_append_key_object(objects, count, capacity,
						&info)) {
				osal_free(info.label);
				osal_free(info.ec_params);
				status = _fail(HSM_ERR_MEMORY,
					       "hsm_list_key_objects", 0,
					       "out of memory");
				break;
			}
		}
		if (status != HSM_OK)
			break;
	}

	final_rv = functions->C_FindObjectsFinal(session);
	if (status == HSM_OK && final_rv != CKR_OK)
		status = _pkcs11_failure("C_FindObjectsFinal", final_rv,
					 HSM_ERR_INTERNAL);
	return status;
}

hsm_status_t hsm_list_key_objects(hsm_token_t *token, hsm_key_object_t **objects,
				  size_t *count)
{
	struct hsm_session_ref reference;
	hsm_key_object_t *found = nullptr;
	size_t found_count = 0;
	size_t capacity = 0;
	hsm_status_t status;

	_reset_last_error();

	if (objects == nullptr || count == nullptr)
		return _argument_error("hsm_list_key_objects",
				       "objects and count must not be NULL");
	*objects = nullptr;
	*count = 0;
	if (token == nullptr)
		return _argument_error("hsm_list_key_objects",
				       "token must not be NULL");

	status = _require_module_ready(token->module, "hsm_list_key_objects");
	if (status != HSM_OK)
		return status;

	status = _acquire_session(token, false, "hsm_list_key_objects",
				  &reference);
	if (status != HSM_OK)
		return status;

	status = _find_key_objects(token->module->functions, reference.handle,
				   CKO_PRIVATE_KEY, &found, &found_count,
				   &capacity);
	if (status == HSM_ERR_TOKEN_NOT_LOGGED_IN)
		status = HSM_OK;
	if (status == HSM_OK)
		status = _find_key_objects(token->module->functions,
					   reference.handle, CKO_PUBLIC_KEY,
					   &found, &found_count, &capacity);

	if (status != HSM_OK) {
		hsm_key_object_list_free(found, found_count);
		found = nullptr;
		found_count = 0;
	}

	_release_session(token, &reference, status == HSM_OK);
	*objects = found;
	*count = found_count;
	return status;
}

void hsm_key_object_list_free(hsm_key_object_t *objects, size_t count)
{
	if (objects == nullptr)
		return;

	for (size_t i = 0; i < count; i++) {
		osal_free(objects[i].label);
		osal_free(objects[i].ec_params);
	}
	osal_free(objects);
}

hsm_status_t hsm_verify(hsm_token_t *token, hsm_sign_alg_t algorithm,
			const char *key_label, const void *data,
			size_t data_len, const unsigned char *signature,
			size_t signature_len)
{
	struct hsm_sign_mechanism spec;
	struct hsm_session_ref reference;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	const void *operation_data;
	size_t operation_len;
	unsigned char digest[HSM_DIGEST_MAX];
	CK_ULONG ck_signature_len;
	CK_RV rv;
	hsm_status_t status;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_verify",
				       "token must not be NULL");
	if (key_label == nullptr || key_label[0] == '\0')
		return _argument_error("hsm_verify",
				       "key_label must not be NULL or empty");
	if (data == nullptr && data_len != 0)
		return _argument_error(
			"hsm_verify",
			"data must not be NULL when data_len is nonzero");
	if (signature == nullptr || signature_len == 0)
		return _argument_error(
			"hsm_verify",
			"signature must not be NULL or empty");
	if (!_size_fits_ck_ulong(data_len))
		return _argument_error("hsm_verify",
				       "data is too large for PKCS #11");
	if (!_ck_ulong_from_size(signature_len, &ck_signature_len))
		return _argument_error(
			"hsm_verify",
			"signature is too large for PKCS #11");
	if (!_build_sign_mechanism(algorithm, &spec))
		return _argument_error("hsm_verify",
				       "unsupported signature algorithm");

	status = _require_module_ready(token->module, "hsm_verify");
	if (status != HSM_OK)
		return status;

	status = _acquire_session(token, false, "hsm_verify", &reference);
	if (status != HSM_OK)
		return status;

	status = _find_key_by_label(token->module->functions,
				    reference.handle, key_label,
				    CKO_PUBLIC_KEY, &key);
	if (status != HSM_OK) {
		_release_session(token, &reference, true);
		return status;
	}
	if (spec.parameter_set != 0) {
		status = _check_key_parameter_set(
			token->module->functions, reference.handle, key,
			spec.parameter_set, "hsm_verify");
		if (status != HSM_OK) {
			_release_session(token, &reference, true);
			return status;
		}
	}

	status = _init_signature_operation(
		token->module->functions, reference.handle,
		token->module->functions->C_VerifyInit, "C_VerifyInit", &spec,
		key, data, data_len, &operation_data, &operation_len, digest,
		sizeof digest);
	if (status != HSM_OK) {
		_release_failed_session(token, &reference);
		return status;
	}

	/*
	 * operation_len is either the caller's data_len, which was range-checked
	 * above, or a digest of at most HSM_DIGEST_MAX bytes.
	 */
	rv = token->module->functions->C_Verify(
		reference.handle,
		_pkcs11_input_pointer(operation_data, operation_len),
		(CK_ULONG)operation_len, (CK_BYTE_PTR)(void *)signature,
		ck_signature_len);

	if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE) {
		status = _fail(HSM_ERR_VERIFY, "C_Verify", (unsigned long)rv,
			       "signature verification failed: %s (0x%lx)",
			       _pkcs11_rv_name(rv), (unsigned long)rv);
		_release_failed_session(token, &reference);
		return status;
	}
	if (rv != CKR_OK) {
		/*
		 * Only signature-invalid results are business results; other
		 * failures mean verification could not be performed.
		 */
		status = _pkcs11_failure("C_Verify", rv, HSM_ERR_INTERNAL);
		_release_failed_session(token, &reference);
		return status;
	}

	_release_session(token, &reference, true);
	return HSM_OK;
}

hsm_status_t hsm_random(hsm_token_t *token, void *buffer, size_t length)
{
	struct hsm_session_ref reference;
	CK_ULONG ck_length;
	CK_RV rv;
	hsm_status_t status;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_random",
				       "token must not be NULL");
	if (buffer == nullptr && length != 0)
		return _argument_error(
			"hsm_random",
			"buffer must not be NULL when length is nonzero");
	if (length == 0)
		return HSM_OK;
	if (!_ck_ulong_from_size(length, &ck_length))
		return _argument_error("hsm_random",
				       "length is too large for PKCS #11");

	status = _require_module_ready(token->module, "hsm_random");
	if (status != HSM_OK)
		return status;

	status = _acquire_session(token, false, "hsm_random",
				  &reference);
	if (status != HSM_OK)
		return status;

	rv = token->module->functions->C_GenerateRandom(
		reference.handle, (CK_BYTE_PTR)buffer, ck_length);
	_release_session(token, &reference, rv == CKR_OK);

	if (rv != CKR_OK)
		return _pkcs11_failure("C_GenerateRandom", rv, HSM_ERR_DEVICE);
	return HSM_OK;
}

static bool _ec_params(hsm_ec_curve_t curve, const unsigned char **params,
		       CK_ULONG *params_len)
{
	/* DER-encoded namedCurve OIDs: P-256, P-384 and P-521. */
	static const unsigned char p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48,
					      0xce, 0x3d, 0x03, 0x01, 0x07 };
	static const unsigned char p384[] = { 0x06, 0x05, 0x2b, 0x81,
					      0x04, 0x00, 0x22 };
	static const unsigned char p521[] = { 0x06, 0x05, 0x2b, 0x81,
					      0x04, 0x00, 0x23 };

	switch (curve) {
	case HSM_EC_CURVE_P256:
		*params = p256;
		*params_len = sizeof p256;
		return true;
	case HSM_EC_CURVE_P384:
		*params = p384;
		*params_len = sizeof p384;
		return true;
	case HSM_EC_CURVE_P521:
		*params = p521;
		*params_len = sizeof p521;
		return true;
	default:
		return false;
	}
}

static CK_ULONG _key_label_length(const char *key_label)
{
	CK_ULONG length;

	/*
	 * Template construction runs before _generate_key_pair() validates
	 * key_label; avoid dereferencing NULL here.  An oversized label is
	 * rejected by _generate_key_pair() before the templates are used.
	 */
	if (key_label == nullptr)
		return 0;
	return _ck_ulong_from_size(strlen(key_label), &length) ? length : 0;
}

static hsm_status_t _generate_key_pair(hsm_token_t *token,
				       CK_MECHANISM_PTR mechanism,
				       CK_ATTRIBUTE *public_template,
				       CK_ULONG public_count,
				       CK_ATTRIBUTE *private_template,
				       CK_ULONG private_count,
				       const char *key_label,
				       const char *operation)
{
	CK_FUNCTION_LIST_PTR functions;
	CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE existing = CK_INVALID_HANDLE;
	CK_RV rv;
	hsm_status_t status;

	if (token == nullptr)
		return _argument_error(operation, "token must not be NULL");
	if (key_label == nullptr || key_label[0] == '\0')
		return _argument_error(operation,
				       "key_label must not be NULL or empty");
	if (!_size_fits_ck_ulong(strlen(key_label)))
		return _argument_error(operation,
				       "key_label is too long for PKCS #11");

	status = _require_module_ready(token->module, operation);
	if (status != HSM_OK)
		return status;

	functions = token->module->functions;

	mtx_lock(&token->lock);
	if (token->closing) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_SESSION, operation, 0,
			     "the token is closing");
	}
	if (!token->logged_in) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_TOKEN_NOT_LOGGED_IN, operation, 0,
			     "the token must be logged in to generate a key");
	}

	status = _ensure_login_session_locked(token);
	if (status != HSM_OK) {
		mtx_unlock(&token->lock);
		return status;
	}

	/*
	 * PKCS #11 does not make CKA_LABEL unique, and later lookups return
	 * an arbitrary match, so reject an existing private or public key
	 * explicitly.
	 */
	status = _find_key_by_label(functions, token->login_session, key_label,
				    CKO_PRIVATE_KEY, &existing);
	if (status == HSM_OK) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_DUPLICATE, operation, 0,
			     "a private key with label \"%s\" already exists",
			     key_label);
	}
	if (status != HSM_ERR_OBJECT_NOT_FOUND) {
		mtx_unlock(&token->lock);
		return status;
	}

	status = _find_key_by_label(functions, token->login_session, key_label,
				    CKO_PUBLIC_KEY, &existing);
	if (status == HSM_OK) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_DUPLICATE, operation, 0,
			     "a public key with label \"%s\" already exists",
			     key_label);
	}
	if (status != HSM_ERR_OBJECT_NOT_FOUND) {
		mtx_unlock(&token->lock);
		return status;
	}

	rv = functions->C_GenerateKeyPair(
		token->login_session, mechanism, public_template, public_count,
		private_template, private_count, &public_key, &private_key);
	mtx_unlock(&token->lock);

	if (rv != CKR_OK)
		return _pkcs11_failure(operation, rv, HSM_ERR_DEVICE);
	return HSM_OK;
}

hsm_status_t hsm_generate_rsa_key_pair(hsm_token_t *token, unsigned int bits,
				       const char *key_label)
{
	CK_MECHANISM mechanism = {
		.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
		.pParameter = nullptr,
		.ulParameterLen = 0,
	};
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	unsigned char exponent[] = { 0x01, 0x00, 0x01 };
	CK_ULONG modulus_bits = bits;
	CK_ATTRIBUTE public_template[] = {
		{ CKA_TOKEN, &yes, sizeof yes },
		{ CKA_LABEL, (void *)key_label, _key_label_length(key_label) },
		{ CKA_ENCRYPT, &no, sizeof no },
		{ CKA_VERIFY, &yes, sizeof yes },
		{ CKA_WRAP, &no, sizeof no },
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof modulus_bits },
		{ CKA_PUBLIC_EXPONENT, exponent, sizeof exponent },
	};
	CK_ATTRIBUTE private_template[] = {
		{ CKA_TOKEN, &yes, sizeof yes },
		{ CKA_PRIVATE, &yes, sizeof yes },
		{ CKA_SENSITIVE, &yes, sizeof yes },
		{ CKA_EXTRACTABLE, &no, sizeof no },
		{ CKA_LABEL, (void *)key_label, _key_label_length(key_label) },
		{ CKA_DECRYPT, &no, sizeof no },
		{ CKA_SIGN, &yes, sizeof yes },
		{ CKA_UNWRAP, &no, sizeof no },
	};

	_reset_last_error();

	if (bits < 2048)
		return _argument_error("hsm_generate_rsa_key_pair",
				       "RSA key size must be at least 2048 bits");

	return _generate_key_pair(
		token, &mechanism, public_template,
		(CK_ULONG)(sizeof public_template / sizeof public_template[0]),
		private_template,
		(CK_ULONG)(sizeof private_template / sizeof private_template[0]),
		key_label, "C_GenerateKeyPair");
}

hsm_status_t hsm_generate_ec_key_pair(hsm_token_t *token, hsm_ec_curve_t curve,
				      const char *key_label)
{
	CK_MECHANISM mechanism = {
		.mechanism = CKM_EC_KEY_PAIR_GEN,
		.pParameter = nullptr,
		.ulParameterLen = 0,
	};
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	const unsigned char *params;
	CK_ULONG params_len;
	CK_ATTRIBUTE public_template[5];
	CK_ATTRIBUTE private_template[7];

	_reset_last_error();

	if (!_ec_params(curve, &params, &params_len))
		return _argument_error("hsm_generate_ec_key_pair",
				       "unsupported EC curve");

	public_template[0] = (CK_ATTRIBUTE){
		.type = CKA_TOKEN, .pValue = &yes, .ulValueLen = sizeof yes
	};
	public_template[1] = (CK_ATTRIBUTE){
		.type = CKA_LABEL,
		.pValue = (void *)key_label,
		.ulValueLen = _key_label_length(key_label),
	};
	public_template[2] = (CK_ATTRIBUTE){
		.type = CKA_EC_PARAMS,
		.pValue = (void *)params,
		.ulValueLen = params_len,
	};
	public_template[3] = (CK_ATTRIBUTE){
		.type = CKA_VERIFY, .pValue = &yes, .ulValueLen = sizeof yes
	};
	public_template[4] = (CK_ATTRIBUTE){
		.type = CKA_DERIVE, .pValue = &no, .ulValueLen = sizeof no
	};

	private_template[0] = (CK_ATTRIBUTE){
		.type = CKA_TOKEN, .pValue = &yes, .ulValueLen = sizeof yes
	};
	private_template[1] = (CK_ATTRIBUTE){
		.type = CKA_PRIVATE, .pValue = &yes, .ulValueLen = sizeof yes
	};
	private_template[2] = (CK_ATTRIBUTE){
		.type = CKA_SENSITIVE, .pValue = &yes, .ulValueLen = sizeof yes
	};
	private_template[3] = (CK_ATTRIBUTE){
		.type = CKA_EXTRACTABLE, .pValue = &no, .ulValueLen = sizeof no
	};
	private_template[4] = (CK_ATTRIBUTE){
		.type = CKA_LABEL,
		.pValue = (void *)key_label,
		.ulValueLen = _key_label_length(key_label),
	};
	private_template[5] = (CK_ATTRIBUTE){
		.type = CKA_SIGN, .pValue = &yes, .ulValueLen = sizeof yes
	};
	private_template[6] = (CK_ATTRIBUTE){
		.type = CKA_DERIVE, .pValue = &no, .ulValueLen = sizeof no
	};

	return _generate_key_pair(
		token, &mechanism, public_template,
		(CK_ULONG)(sizeof public_template / sizeof public_template[0]),
		private_template,
		(CK_ULONG)(sizeof private_template / sizeof private_template[0]),
		key_label, "C_GenerateKeyPair");
}

hsm_status_t hsm_generate_ml_dsa_key_pair(
	hsm_token_t *token, hsm_ml_dsa_parameter_set_t parameter_set,
	const char *key_label)
{
	CK_MECHANISM mechanism = {
		.mechanism = CKM_ML_DSA_KEY_PAIR_GEN,
		.pParameter = nullptr,
		.ulParameterLen = 0,
	};
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	CK_ULONG ck_parameter_set = 0;
	CK_ATTRIBUTE public_template[] = {
		{ CKA_TOKEN, &yes, sizeof yes },
		{ CKA_LABEL, (void *)key_label, _key_label_length(key_label) },
		{ CKA_VERIFY, &yes, sizeof yes },
		{ CKA_PARAMETER_SET, &ck_parameter_set,
		  sizeof ck_parameter_set },
	};
	CK_ATTRIBUTE private_template[] = {
		{ CKA_TOKEN, &yes, sizeof yes },
		{ CKA_PRIVATE, &yes, sizeof yes },
		{ CKA_SENSITIVE, &yes, sizeof yes },
		{ CKA_EXTRACTABLE, &no, sizeof no },
		{ CKA_LABEL, (void *)key_label, _key_label_length(key_label) },
		{ CKA_SIGN, &yes, sizeof yes },
	};

	_reset_last_error();

	if (!_ml_dsa_parameter_set_to_ck(parameter_set, &ck_parameter_set))
		return _argument_error("hsm_generate_ml_dsa_key_pair",
				       "unsupported ML-DSA parameter set");

	return _generate_key_pair(
		token, &mechanism, public_template,
		(CK_ULONG)(sizeof public_template / sizeof public_template[0]),
		private_template,
		(CK_ULONG)(sizeof private_template / sizeof private_template[0]),
		key_label, "C_GenerateKeyPair");
}

hsm_status_t hsm_delete_key_pair(hsm_token_t *token, const char *key_label)
{
	static const CK_OBJECT_CLASS classes[] = {
		CKO_PRIVATE_KEY,
		CKO_PUBLIC_KEY,
	};
	CK_FUNCTION_LIST_PTR functions;
	hsm_status_t status;

	_reset_last_error();

	if (token == nullptr)
		return _argument_error("hsm_delete_key_pair",
				       "token must not be NULL");
	if (key_label == nullptr || key_label[0] == '\0')
		return _argument_error(
			"hsm_delete_key_pair",
			"key_label must not be NULL or empty");

	status = _require_module_ready(token->module, "hsm_delete_key_pair");
	if (status != HSM_OK)
		return status;

	functions = token->module->functions;

	/*
	 * Token objects can only be destroyed from a read-write session.  The
	 * login session is the only read-write session and is also used for
	 * key generation, so serialize with it.
	 */
	mtx_lock(&token->lock);
	if (token->closing) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_SESSION, "hsm_delete_key_pair", 0,
			     "the token is closing");
	}
	if (!token->logged_in) {
		mtx_unlock(&token->lock);
		return _fail(HSM_ERR_TOKEN_NOT_LOGGED_IN,
			     "hsm_delete_key_pair", 0,
			     "the token must be logged in to delete a key");
	}

	status = _ensure_login_session_locked(token);
	if (status != HSM_OK) {
		mtx_unlock(&token->lock);
		return status;
	}

	status = HSM_OK;
	for (size_t i = 0; i < sizeof classes / sizeof classes[0]; i++) {
		CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
		hsm_status_t found;
		CK_RV rv;

		found = _find_key_by_label(functions, token->login_session,
					   key_label, classes[i], &key);
		if (found == HSM_ERR_OBJECT_NOT_FOUND)
			continue;
		if (found != HSM_OK) {
			if (status == HSM_OK)
				status = found;
			break;
		}

		rv = functions->C_DestroyObject(token->login_session, key);
		if (rv != CKR_OK) {
			hsm_status_t failure = _pkcs11_failure(
				"C_DestroyObject", rv, HSM_ERR_DEVICE);

			if (status == HSM_OK)
				status = failure;
		}
	}
	mtx_unlock(&token->lock);

	return status;
}

const struct hsm_error *hsm_get_last_error(void)
{
	return &g_error;
}

const char *hsm_status_to_string(hsm_status_t status)
{
	switch (status) {
	case HSM_OK:
		return "HSM_OK";
	case HSM_ERR_ARGUMENT:
		return "HSM_ERR_ARGUMENT";
	case HSM_ERR_NOT_INITIALIZED:
		return "HSM_ERR_NOT_INITIALIZED";
	case HSM_ERR_ALREADY_INITIALIZED:
		return "HSM_ERR_ALREADY_INITIALIZED";
	case HSM_ERR_MODULE_LOAD:
		return "HSM_ERR_MODULE_LOAD";
	case HSM_ERR_MODULE_INIT:
		return "HSM_ERR_MODULE_INIT";
	case HSM_ERR_TOKEN_NOT_FOUND:
		return "HSM_ERR_TOKEN_NOT_FOUND";
	case HSM_ERR_TOKEN_NOT_LOGGED_IN:
		return "HSM_ERR_TOKEN_NOT_LOGGED_IN";
	case HSM_ERR_PIN_INCORRECT:
		return "HSM_ERR_PIN_INCORRECT";
	case HSM_ERR_SESSION:
		return "HSM_ERR_SESSION";
	case HSM_ERR_SESSION_LIMIT:
		return "HSM_ERR_SESSION_LIMIT";
	case HSM_ERR_OBJECT_NOT_FOUND:
		return "HSM_ERR_OBJECT_NOT_FOUND";
	case HSM_ERR_MECHANISM:
		return "HSM_ERR_MECHANISM";
	case HSM_ERR_BUFFER_TOO_SMALL:
		return "HSM_ERR_BUFFER_TOO_SMALL";
	case HSM_ERR_SIGN:
		return "HSM_ERR_SIGN";
	case HSM_ERR_DIGEST:
		return "HSM_ERR_DIGEST";
	case HSM_ERR_VERIFY:
		return "HSM_ERR_VERIFY";
	case HSM_ERR_DEVICE:
		return "HSM_ERR_DEVICE";
	case HSM_ERR_MEMORY:
		return "HSM_ERR_MEMORY";
	case HSM_ERR_BUSY:
		return "HSM_ERR_BUSY";
	case HSM_ERR_INTERNAL:
		return "HSM_ERR_INTERNAL";
	case HSM_ERR_DUPLICATE:
		return "HSM_ERR_DUPLICATE";
	default:
		return "HSM_ERR_UNKNOWN";
	}
}
