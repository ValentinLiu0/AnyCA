/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <anyca/osal/dynlib.h>
#include <anyca/osal/thread.h>

#define OSAL_ERROR_MAX 512

#if defined(_WIN32)
typedef HMODULE platform_handle_t;
#else
typedef void *platform_handle_t;
#endif

struct osal_dynlib {
	platform_handle_t handle;
};

static OSAL_THREAD_LOCAL char g_error[OSAL_ERROR_MAX];

static void _clear_error(void) { g_error[0] = '\0'; }

static void _set_error(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	vsnprintf(g_error, sizeof g_error, format, arguments);
	va_end(arguments);
}

const char *osal_dynlib_error(void)
{
	return g_error[0] != '\0' ? g_error : "no error";
}

#if defined(_WIN32)

static void _set_windows_error(const char *operation, const char *subject,
			      DWORD code)
{
	char message[OSAL_ERROR_MAX];
	DWORD length;

	length = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		message, (DWORD)sizeof message, nullptr);
	if (length == 0) {
		snprintf(message, sizeof message, "Windows error %lu",
			 (unsigned long)code);
	} else {
		while (length > 0
		       && (message[length - 1] == '\r'
			   || message[length - 1] == '\n'
			   || message[length - 1] == ' '))
			message[--length] = '\0';
	}

	_set_error("%s \"%s\" failed: %s", operation, subject, message);
}

static bool _platform_open(platform_handle_t *handle, const char *path)
{
	*handle = LoadLibraryA(path);
	if (*handle == nullptr) {
		_set_windows_error("LoadLibraryA", path, GetLastError());
		return false;
	}
	return true;
}

static void *_platform_symbol(platform_handle_t handle, const char *name)
{
	FARPROC address;
	void *symbol = nullptr;

	address = GetProcAddress(handle, name);
	if (address == nullptr) {
		_set_windows_error("GetProcAddress", name, GetLastError());
		return nullptr;
	}

	_Static_assert(sizeof symbol == sizeof address,
		       "function and data pointers must have the same size");
	memcpy(&symbol, &address, sizeof symbol);
	return symbol;
}

static void _platform_close(platform_handle_t handle)
{
	(void)FreeLibrary(handle);
}

#else // POSIX

static bool _platform_open(platform_handle_t *handle, const char *path)
{
	const char *reason;

	*handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (*handle == nullptr) {
		reason = dlerror();
		_set_error("cannot open \"%s\": %s", path,
			  reason != nullptr ? reason : "unknown loader error");
		return false;
	}
	return true;
}

static void *_platform_symbol(platform_handle_t handle, const char *name)
{
	void *symbol;
	const char *reason;

	(void)dlerror();
	symbol = dlsym(handle, name);
	if (symbol == nullptr) {
		reason = dlerror();
		_set_error("cannot resolve \"%s\": %s", name,
			  reason != nullptr ? reason : "symbol not found");
	}
	return symbol;
}

static void _platform_close(platform_handle_t handle) { (void)dlclose(handle); }

#endif // _WIN32

osal_dynlib_t *osal_dynlib_open(const char *path)
{
	osal_dynlib_t *library;

	_clear_error();
	if (path == nullptr || *path == '\0') {
		_set_error("library path must not be NULL or empty");
		return nullptr;
	}

	library = malloc(sizeof *library);
	if (library == nullptr) {
		_set_error("out of memory");
		return nullptr;
	}

	if (!_platform_open(&library->handle, path)) {
		free(library);
		return nullptr;
	}
	return library;
}

void *osal_dynlib_symbol(osal_dynlib_t *library, const char *name)
{
	_clear_error();
	if (library == nullptr) {
		_set_error("library handle must not be NULL");
		return nullptr;
	}
	if (name == nullptr || *name == '\0') {
		_set_error("symbol name must not be NULL or empty");
		return nullptr;
	}
	return _platform_symbol(library->handle, name);
}

void osal_dynlib_close(osal_dynlib_t *library)
{
	if (library == nullptr)
		return;

	_platform_close(library->handle);
	free(library);
}
