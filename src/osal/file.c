/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <anyca/osal/file.h>
#include <anyca/osal/thread.h>

#define OSAL_FILE_ERROR_MAX 512

static OSAL_THREAD_LOCAL char g_error[OSAL_FILE_ERROR_MAX];

static void _clear_error(void)
{
	g_error[0] = '\0';
}

static void _set_error(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	vsnprintf(g_error, sizeof g_error, format, arguments);
	va_end(arguments);
}

const char *osal_file_error(void)
{
	return g_error[0] != '\0' ? g_error : "no error";
}

static bool _is_separator(char character)
{
#if defined(_WIN32)
	return character == '/' || character == '\\';
#else
	return character == '/';
#endif
}

#if defined(_WIN32)

static bool _make_one_dir(const char *path)
{
	DWORD attributes;

	if (CreateDirectoryA(path, nullptr))
		return true;

	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		attributes = GetFileAttributesA(path);
		if (attributes != INVALID_FILE_ATTRIBUTES
		    && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
			return true;
	}

	_set_error("cannot create directory \"%s\" (Windows error %lu)", path,
		   (unsigned long) GetLastError());
	return false;
}

/* Index of the first path component that may be created.  The UNC server and
 * share components (\\server\share) already exist and must not be passed to
 * CreateDirectoryA(); extended prefixes (\\?\ and \\.\) are skipped too. */
static size_t _make_dirs_start(const char *path)
{
	size_t offset = 0;
	size_t cursor;
	unsigned components = 0;

	if (!_is_separator(path[0]) || path[1] == '\0'
	    || !_is_separator(path[1]))
		return 1;

	if ((path[2] == '?' || path[2] == '.') && _is_separator(path[3]))
		offset = 4;
	if (strncmp(path + offset, "UNC\\", 4) == 0
	    || strncmp(path + offset, "UNC/", 4) == 0)
		offset += 4;

	/* An extended drive path (\\?\C:\...) starts after the drive colon. */
	if (path[offset] != '\0' && path[offset + 1] == ':')
		return offset + 3;

	cursor = offset;
	while (_is_separator(path[cursor]))
		cursor++;
	while (components < 2 && path[cursor] != '\0') {
		while (path[cursor] != '\0' && !_is_separator(path[cursor]))
			cursor++;
		if (path[cursor] == '\0')
			break;
		cursor++;
		components++;
	}
	return cursor;
}


#else

static bool _make_one_dir(const char *path)
{
	struct stat status;

	if (mkdir(path, 0755) == 0)
		return true;

	if (errno == EEXIST && stat(path, &status) == 0
	    && S_ISDIR(status.st_mode))
		return true;

	_set_error("cannot create directory \"%s\": %s", path,
		   strerror(errno));
	return false;
}

#endif

bool osal_file_make_dirs(const char *path)
{
	char *buffer;
	size_t length;
	bool ok = true;

	_clear_error();
	if (path == nullptr || path[0] == '\0') {
		_set_error("directory path must not be NULL or empty");
		return false;
	}

	length = strlen(path);
	buffer = malloc(length + 1);
	if (buffer == nullptr) {
		_set_error("out of memory");
		return false;
	}
	memcpy(buffer, path, length + 1);

#if defined(_WIN32)
	size_t start = _make_dirs_start(buffer);
#else
	size_t start = 1;
#endif

	for (size_t i = start; i < length && ok; i++) {
		if (!_is_separator(buffer[i]))
			continue;
		if (_is_separator(buffer[i - 1]))
			continue;
#if defined(_WIN32)
		/* Keep the "C:" drive prefix in the first component. */
		if (i == 2 && buffer[1] == ':')
			continue;
#endif
		buffer[i] = '\0';
		ok = _make_one_dir(buffer);
		buffer[i] = path[i];
	}
	if (ok)
		ok = _make_one_dir(buffer);

	free(buffer);
	return ok;
}

bool osal_file_create_private(const char *path)
{
	_clear_error();
	if (path == nullptr || path[0] == '\0') {
		_set_error("file path must not be NULL or empty");
		return false;
	}

#if defined(_WIN32)
	HANDLE file;

	file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
			   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			   CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE) {
		(void) CloseHandle(file);
		return true;
	}
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;
	_set_error("cannot create \"%s\" (Windows error %lu)", path,
		   (unsigned long) GetLastError());
	return false;
#else
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd >= 0) {
		(void) close(fd);
		return true;
	}
	if (errno == EEXIST)
		return true;
	_set_error("cannot create \"%s\": %s", path, strerror(errno));
	return false;
#endif
}

#if defined(_WIN32)
struct osal_file_lock {
	HANDLE file;
};
#else
struct osal_file_lock {
	int fd;
};
#endif

osal_file_lock_t *osal_file_lock_acquire(const char *path)
{
	osal_file_lock_t *lock;

	_clear_error();
	if (path == nullptr || path[0] == '\0') {
		_set_error("lock path must not be NULL or empty");
		return nullptr;
	}

	lock = malloc(sizeof *lock);
	if (lock == nullptr) {
		_set_error("out of memory");
		return nullptr;
	}

#if defined(_WIN32)
	{
		OVERLAPPED overlapped = { 0 };

		lock->file = CreateFileA(
			path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (lock->file == INVALID_HANDLE_VALUE) {
			_set_error("cannot open \"%s\" (Windows error %lu)", path,
				   (unsigned long) GetLastError());
			free(lock);
			return nullptr;
		}
		if (!LockFileEx(lock->file, LOCKFILE_EXCLUSIVE_LOCK, 0,
				MAXDWORD, MAXDWORD, &overlapped)) {
			_set_error("cannot lock \"%s\" (Windows error %lu)", path,
				   (unsigned long) GetLastError());
			(void) CloseHandle(lock->file);
			free(lock);
			return nullptr;
		}
	}
#else
	lock->fd = open(path, O_RDWR | O_CREAT, 0600);
	if (lock->fd < 0) {
		_set_error("cannot open \"%s\": %s", path, strerror(errno));
		free(lock);
		return nullptr;
	}
	while (flock(lock->fd, LOCK_EX) != 0) {
		if (errno == EINTR)
			continue;
		_set_error("cannot lock \"%s\": %s", path, strerror(errno));
		(void) close(lock->fd);
		free(lock);
		return nullptr;
	}
#endif
	return lock;
}

void osal_file_lock_release(osal_file_lock_t *lock)
{
	if (lock == nullptr)
		return;

#if defined(_WIN32)
	{
		OVERLAPPED overlapped = { 0 };

		(void) UnlockFileEx(lock->file, 0, MAXDWORD, MAXDWORD,
				    &overlapped);
		(void) CloseHandle(lock->file);
	}
#else
	(void) flock(lock->fd, LOCK_UN);
	(void) close(lock->fd);
#endif
	free(lock);
}

#if defined(_WIN32)

static bool _write_all(HANDLE file, const unsigned char *data, size_t length)
{
	while (length > 0) {
		DWORD written = 0;
		DWORD chunk = length > 0x7fffffffU
				      ? 0x7fffffffU
				      : (DWORD) length;

		if (!WriteFile(file, data, chunk, &written, nullptr)
		    || written == 0) {
			_set_error("WriteFile failed (Windows error %lu)",
				   (unsigned long) GetLastError());
			return false;
		}
		data += written;
		length -= written;
	}
	return true;
}

static bool _replace_file(const char *temporary, const char *path)
{
	if (MoveFileExA(temporary, path,
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		return true;

	_set_error("cannot replace \"%s\" (Windows error %lu)", path,
		   (unsigned long) GetLastError());
	return false;
}

#else

static bool _write_all(int fd, const unsigned char *data, size_t length)
{
	while (length > 0) {
		ssize_t written = write(fd, data, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			_set_error("write failed: %s", strerror(errno));
			return false;
		}
		if (written == 0) {
			_set_error("write returned zero bytes");
			return false;
		}
		data += (size_t) written;
		length -= (size_t) written;
	}
	return true;
}

static bool _sync_directory(const char *directory)
{
	int fd = open(directory, O_RDONLY);

	if (fd < 0) {
		_set_error("cannot open directory \"%s\" for fsync: %s",
			   directory, strerror(errno));
		return false;
	}
	if (fsync(fd) != 0) {
		_set_error("fsync failed for directory \"%s\": %s", directory,
			   strerror(errno));
		(void) close(fd);
		return false;
	}
	if (close(fd) != 0) {
		_set_error("close failed for directory \"%s\": %s", directory,
			   strerror(errno));
		return false;
	}
	return true;
}

#endif

bool osal_file_write_atomic(const char *path, const void *data, size_t length,
			    unsigned int mode)
{
	char *directory = nullptr;
	char *temporary = nullptr;
	const char *name;
	size_t directory_length;
	size_t temporary_length;
	bool ok = false;

	_clear_error();
#if defined(_WIN32)
	(void) mode; /* Win32 has no POSIX permission bits. */
#endif

	if (path == nullptr || path[0] == '\0') {
		_set_error("file path must not be NULL or empty");
		return false;
	}
	if (data == nullptr && length != 0) {
		_set_error("data must not be NULL when length is nonzero");
		return false;
	}
	name = path;
	for (const char *cursor = path; *cursor != '\0'; cursor++) {
		if (_is_separator(*cursor))
			name = cursor + 1;
	}
	if (name[0] == '\0') {
		_set_error("file path \"%s\" does not name a file", path);
		return false;
	}

	directory_length = (size_t) (name - path);
	while (directory_length > 0
	       && _is_separator(path[directory_length - 1]))
		directory_length--;

	directory = malloc(directory_length + 2);
	if (directory == nullptr) {
		_set_error("out of memory");
		return false;
	}
	if (directory_length == 0) {
		if (_is_separator(path[0]))
			strcpy(directory, "/");
		else
			strcpy(directory, ".");
	} else {
		memcpy(directory, path, directory_length);
		directory[directory_length] = '\0';
	}
#if defined(_WIN32)
	if (directory_length == 2 && directory[1] == ':')
		strcat(directory, "\\");
#endif

	if (!osal_file_make_dirs(directory)) {
		free(directory);
		return false;
	}

	temporary_length = strlen(directory) + strlen(name) + 32;
	temporary = malloc(temporary_length);
	if (temporary == nullptr) {
		_set_error("out of memory");
		free(directory);
		return false;
	}

#if defined(_WIN32)
	for (unsigned int attempt = 0; attempt < 100 && !ok; attempt++) {
		HANDLE file;
		bool written;

		snprintf(temporary, temporary_length, "%s\\.%s.tmp.%lu.%u",
			 directory, name, (unsigned long) GetCurrentProcessId(),
			 attempt);
		file = CreateFileA(temporary, GENERIC_WRITE, 0, nullptr,
				   CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
				   nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			if (GetLastError() == ERROR_FILE_EXISTS)
				continue;
			_set_error("cannot create \"%s\" (Windows error %lu)",
				   temporary, (unsigned long) GetLastError());
			break;
		}

		written = _write_all(file, data, length)
			&& FlushFileBuffers(file);
		if (!written && g_error[0] == '\0')
			_set_error("FlushFileBuffers failed (Windows error %lu)",
				   (unsigned long) GetLastError());
		if (!CloseHandle(file) && written) {
			_set_error("CloseHandle failed (Windows error %lu)",
				   (unsigned long) GetLastError());
			written = false;
		}
		/*
		 * MoveFileExA() cannot replace a file that is still open with
		 * an exclusive (dwShareMode = 0) handle, so close the write
		 * handle first.
		 */
		if (written)
			ok = _replace_file(temporary, path);
		if (!ok)
			(void) DeleteFileA(temporary);
	}
#else
	for (unsigned int attempt = 0; attempt < 100 && !ok; attempt++) {
		int fd;
		bool written;

		snprintf(temporary, temporary_length, "%s/.%s.tmp.XXXXXX",
			 directory, name);
		fd = mkstemp(temporary);
		if (fd < 0) {
			_set_error("cannot create \"%s\": %s", temporary,
				   strerror(errno));
			break;
		}
		if (mode == 0)
			mode = 0644;
		if (fchmod(fd, (mode_t) mode) != 0) {
			/*
			 * Do not publish a file whose permissions differ from
			 * the caller's request: a private key could otherwise
			 * become readable.
			 */
			_set_error("cannot set permissions on \"%s\": %s",
				   temporary, strerror(errno));
			(void) close(fd);
			(void) unlink(temporary);
			break;
		}

		written = _write_all(fd, data, length);
		if (written && fsync(fd) != 0) {
			_set_error("fsync failed for \"%s\": %s", temporary,
				   strerror(errno));
			written = false;
		}
		if (close(fd) != 0 && written) {
			_set_error("close failed for \"%s\": %s", temporary,
				   strerror(errno));
			written = false;
		}
		if (written && rename(temporary, path) == 0) {
			/*
			 * The rename is only durable once the directory entry is
			 * flushed; reporting success after a failed fsync would
			 * claim a durability the filesystem does not provide.
			 */
			ok = _sync_directory(directory);
			break;
		}
		if (written)
			_set_error("cannot replace \"%s\": %s", path,
				   strerror(errno));
		(void) unlink(temporary);
	}
#endif

	free(temporary);
	free(directory);
	return ok;
}
