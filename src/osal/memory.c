/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <anyca/osal/memory.h>

#if defined(_MSC_VER) && !defined(__cplusplus)
/*
 * MSVC does not define max_align_t in C mode.  double is the type its C++
 * <cstddef> uses for max_align_t and has the same alignment as every scalar
 * type on the supported Windows targets.
 */
typedef double osal_max_align_t;
#else
typedef max_align_t osal_max_align_t;
#endif

/*
 * Placed immediately before the page-aligned payload, this header records
 * how to release the original allocation.  osal_max_align_t makes the header
 * a multiple of the maximum alignment, keeping the payload aligned.
 */
struct osal_secure_header {
	void *raw;
	size_t size;
	size_t locked_size;
	osal_max_align_t alignment;
};

static void _secure_zero(void *pointer, size_t length)
{
#if defined(_WIN32)
	SecureZeroMemory(pointer, length);
#else
	volatile unsigned char *bytes = pointer;

	while (length > 0) {
		*bytes++ = 0;
		length--;
	}
#endif
}

static size_t _system_page_size(void)
{
#if defined(_WIN32)
	SYSTEM_INFO info;

	GetSystemInfo(&info);
	return (size_t) info.dwPageSize;
#else
	long page_size = sysconf(_SC_PAGESIZE);

	return page_size > 0 ? (size_t)page_size : 4096;
#endif
}

static uintptr_t _align_up(uintptr_t value, size_t alignment)
{
	size_t remainder = (size_t)(value % alignment);

	if (remainder == 0)
		return value;
	return value + (alignment - remainder);
}

static size_t _round_up(size_t value, size_t alignment)
{
	size_t remainder = value % alignment;

	if (remainder == 0)
		return value;
	return value + (alignment - remainder);
}

static bool _lock_pages(void *pointer, size_t length)
{
#if defined(_WIN32)
	if (VirtualLock(pointer, length) == 0) {
		errno = ENOMEM;
		return false;
	}
	return true;
#else
	if (mlock(pointer, length) != 0)
		return false;

#if defined(MADV_DONTDUMP)
	(void) madvise(pointer, length, MADV_DONTDUMP);
#elif defined(MADV_NOCORE)
	(void) madvise(pointer, length, MADV_NOCORE);
#endif
	return true;
#endif
}

static void _unlock_pages(void *pointer, size_t length)
{
#if defined(_WIN32)
	(void) VirtualUnlock(pointer, length);
#else
#if defined(MADV_DODUMP)
	(void) madvise(pointer, length, MADV_DODUMP);
#elif defined(MADV_CORE)
	(void) madvise(pointer, length, MADV_CORE);
#endif
	(void) munlock(pointer, length);
#endif
}

void *osal_malloc(size_t size)
{
	return malloc(size);
}

void *osal_calloc(size_t count, size_t size)
{
	return calloc(count, size);
}

void *osal_realloc(void *pointer, size_t size)
{
	return realloc(pointer, size);
}

void osal_free(void *pointer)
{
	free(pointer);
}

void *osal_secure_malloc(size_t size)
{
	struct osal_secure_header *header;
	unsigned char *raw;
	void *payload;
	size_t page_size;
	size_t total;
	size_t locked_size;

	if (size == 0) {
		errno = EINVAL;
		return nullptr;
	}

	page_size = _system_page_size();
	if (size > SIZE_MAX - sizeof *header - 2 * page_size) {
		errno = ENOMEM;
		return nullptr;
	}

	/*
	 * Reserve room to align the payload and cover the last page, so no
	 * other allocation shares the pages that will be locked.
	 */
	total = size + sizeof *header + 2 * page_size;
	raw = calloc(1, total);
	if (raw == nullptr)
		return nullptr;

	payload = (void *)_align_up((uintptr_t)raw + sizeof *header, page_size);
	header = (struct osal_secure_header *)((unsigned char *)payload
					  - sizeof *header);
	locked_size = _round_up(size, page_size);

	header->raw = raw;
	header->size = size;
	header->locked_size = locked_size;

	if (!_lock_pages(payload, locked_size)) {
		_secure_zero(raw, total);
		free(raw);
		return nullptr;
	}

	return payload;
}

void osal_secure_free(void *pointer)
{
	struct osal_secure_header *header;
	void *raw;
	size_t size;
	size_t locked_size;

	if (pointer == nullptr)
		return;

	header = (struct osal_secure_header *)((unsigned char *)pointer
					  - sizeof *header);
	raw = header->raw;
	size = header->size;
	locked_size = header->locked_size;

	_secure_zero(header, sizeof *header + size);
	_unlock_pages(pointer, locked_size);
	free(raw);
}
