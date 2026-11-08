/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(_WIN32) && !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0600 /* condition variables */
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <errno.h>
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#endif

#include <anyca/osal/timer.h>
#include <anyca/osal/thread.h>

#define OSAL_TIMER_ERROR_MAX 256

/* Bound each timed wait so clock conversions stay in range. */
#define OSAL_TIMER_MAX_WAIT_MS (60u * 60u * 1000u)

#if defined(_WIN32)
typedef CRITICAL_SECTION osal_timer_mutex_t;
typedef CONDITION_VARIABLE osal_timer_condition_t;
typedef HANDLE osal_timer_thread_t;
#else
typedef pthread_mutex_t osal_timer_mutex_t;
typedef pthread_cond_t osal_timer_condition_t;
typedef pthread_t osal_timer_thread_t;

#if defined(__APPLE__)
/* Relative waits are immune to wall-clock changes on Darwin. */
extern int pthread_cond_timedwait_relative_np(pthread_cond_t *condition,
					      pthread_mutex_t *mutex,
					      const struct timespec *relative);
#endif
#endif

struct osal_timer {
	osal_timer_mutex_t lock;
	osal_timer_condition_t condition;
	osal_timer_thread_t thread;
#if defined(_WIN32)
	DWORD thread_id;
#elif !defined(__APPLE__)
	bool monotonic_condition;
#endif
	osal_timer_callback_t callback;
	void *context;
	uint64_t delay_ms;
	uint64_t interval_ms;
	unsigned long generation;
	bool running;
	bool callback_active;
	bool quitting;
};

static OSAL_THREAD_LOCAL char g_error[OSAL_TIMER_ERROR_MAX];

static void _clear_error(void) { g_error[0] = '\0'; }

static void _set_error(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	vsnprintf(g_error, sizeof g_error, format, arguments);
	va_end(arguments);
}

const char *osal_timer_error(void)
{
	return g_error[0] != '\0' ? g_error : "no error";
}

/* Monotonic milliseconds; unaffected by wall-clock changes. */
static uint64_t _monotonic_milliseconds(void)
{
#if defined(_WIN32)
	return (uint64_t) GetTickCount64();
#else
	struct timespec now;

	(void) clock_gettime(CLOCK_MONOTONIC, &now);
	return (uint64_t) now.tv_sec * 1000u
	       + (uint64_t) now.tv_nsec / 1000000u;
#endif
}

static uint64_t _deadline_after(uint64_t delay_ms)
{
	uint64_t now = _monotonic_milliseconds();

	return delay_ms > UINT64_MAX - now ? UINT64_MAX : now + delay_ms;
}

#if !defined(_WIN32)
static struct timespec _timespec_from_milliseconds(uint64_t milliseconds)
{
	struct timespec result;

	result.tv_sec = (time_t)(milliseconds / 1000);
	result.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
	return result;
}

static struct timespec _realtime_after(uint64_t milliseconds)
{
	struct timespec result = { 0, 0 };
	uint64_t seconds = milliseconds / 1000;
	uint64_t nanoseconds = (milliseconds % 1000) * 1000000;

	(void) clock_gettime(CLOCK_REALTIME, &result);
	result.tv_sec += (time_t) seconds;
	result.tv_nsec += (long) nanoseconds;
	if (result.tv_nsec >= 1000000000L) {
		result.tv_nsec -= 1000000000L;
		result.tv_sec += 1;
	}
	return result;
}
#endif

static void _timer_lock(osal_timer_t *timer)
{
#if defined(_WIN32)
	EnterCriticalSection(&timer->lock);
#else
	(void) pthread_mutex_lock(&timer->lock);
#endif
}

static void _timer_unlock(osal_timer_t *timer)
{
#if defined(_WIN32)
	LeaveCriticalSection(&timer->lock);
#else
	(void) pthread_mutex_unlock(&timer->lock);
#endif
}

static void _timer_condition_wait(osal_timer_t *timer)
{
#if defined(_WIN32)
	(void) SleepConditionVariableCS(&timer->condition, &timer->lock,
					 INFINITE);
#else
	(void) pthread_cond_wait(&timer->condition, &timer->lock);
#endif
}

static void _timer_condition_wait_until(osal_timer_t *timer,
					 uint64_t deadline_ms)
{
	uint64_t now = _monotonic_milliseconds();
	uint64_t remaining = deadline_ms > now ? deadline_ms - now : 0;

	if (remaining > OSAL_TIMER_MAX_WAIT_MS)
		remaining = OSAL_TIMER_MAX_WAIT_MS;

#if defined(_WIN32)
	(void) SleepConditionVariableCS(&timer->condition, &timer->lock,
					 (DWORD) remaining);
#elif defined(__APPLE__)
	struct timespec delay = _timespec_from_milliseconds(remaining);

	(void) pthread_cond_timedwait_relative_np(&timer->condition,
						  &timer->lock, &delay);
#else
	int result;

	if (timer->monotonic_condition) {
		struct timespec deadline =
			_timespec_from_milliseconds(now + remaining);

		result = pthread_cond_timedwait(&timer->condition, &timer->lock,
						&deadline);
	} else {
		struct timespec deadline = _realtime_after(remaining);

		result = pthread_cond_timedwait(&timer->condition, &timer->lock,
						&deadline);
	}
	(void) result;
#endif
}

static void _timer_condition_wake(osal_timer_t *timer)
{
#if defined(_WIN32)
	WakeAllConditionVariable(&timer->condition);
#else
	(void) pthread_cond_broadcast(&timer->condition);
#endif
}

static bool _timer_sync_init(osal_timer_t *timer)
{
#if defined(_WIN32)
	InitializeCriticalSection(&timer->lock);
	InitializeConditionVariable(&timer->condition);
	return true;
#else
	pthread_condattr_t attributes;
	int error;

	error = pthread_mutex_init(&timer->lock, nullptr);
	if (error != 0) {
		_set_error("cannot initialize timer mutex: %s",
			   strerror(error));
		return false;
	}

	error = pthread_condattr_init(&attributes);
	if (error == 0) {
#if !defined(__APPLE__)
		if (pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC)
		    == 0)
			timer->monotonic_condition = true;
#endif
		error = pthread_cond_init(&timer->condition, &attributes);
		(void) pthread_condattr_destroy(&attributes);
	}

	if (error != 0) {
		_set_error("cannot initialize timer condition: %s",
			   strerror(error));
		(void) pthread_mutex_destroy(&timer->lock);
		return false;
	}
	return true;
#endif
}

static void _timer_sync_destroy(osal_timer_t *timer)
{
#if defined(_WIN32)
	DeleteCriticalSection(&timer->lock);
#else
	(void) pthread_cond_destroy(&timer->condition);
	(void) pthread_mutex_destroy(&timer->lock);
#endif
}

#if defined(_WIN32)
static unsigned __stdcall _timer_worker(void *argument);
#else
static void *_timer_worker(void *argument);
#endif

static bool _timer_thread_start(osal_timer_t *timer)
{
#if defined(_WIN32)
	unsigned thread_id = 0;

	timer->thread = (HANDLE) _beginthreadex(nullptr, 0, _timer_worker,
						timer, 0, &thread_id);
	if (timer->thread == nullptr) {
		_set_error("cannot create timer thread: %s", strerror(errno));
		return false;
	}
	timer->thread_id = (DWORD) thread_id;
#else
	int error = pthread_create(&timer->thread, nullptr, _timer_worker,
				   timer);

	if (error != 0) {
		_set_error("cannot create timer thread: %s", strerror(error));
		return false;
	}
#endif
	return true;
}

static void _timer_thread_join(osal_timer_t *timer)
{
#if defined(_WIN32)
	(void) WaitForSingleObject(timer->thread, INFINITE);
	(void) CloseHandle(timer->thread);
#else
	(void) pthread_join(timer->thread, nullptr);
#endif
}

static bool _timer_is_worker_thread(const osal_timer_t *timer)
{
#if defined(_WIN32)
	return GetCurrentThreadId() == timer->thread_id;
#else
	return pthread_equal(pthread_self(), timer->thread) != 0;
#endif
}

#if defined(_WIN32)
static unsigned __stdcall _timer_worker(void *argument)
#else
static void *_timer_worker(void *argument)
#endif
{
	osal_timer_t *timer = argument;

	_timer_lock(timer);
	for (;;) {
		while (!timer->quitting && !timer->running)
			_timer_condition_wait(timer);
		if (timer->quitting)
			break;

		unsigned long generation = timer->generation;
		uint64_t interval = timer->interval_ms;
		uint64_t deadline = _deadline_after(timer->delay_ms);

		for (;;) {
			while (!timer->quitting && timer->running
			       && timer->generation == generation) {
				if (_monotonic_milliseconds() >= deadline)
					break;
				_timer_condition_wait_until(timer, deadline);
			}

			if (timer->quitting)
				goto done;
			if (!timer->running
			    || timer->generation != generation)
				break;

			timer->callback_active = true;
			osal_timer_callback_t callback = timer->callback;
			void *context = timer->context;

			_timer_unlock(timer);
			callback(timer, context);
			_timer_lock(timer);

			timer->callback_active = false;
			_timer_condition_wake(timer);

			if (timer->quitting)
				goto done;
			if (!timer->running
			    || timer->generation != generation)
				break;

			if (interval == 0) {
				timer->running = false;
				break;
			}
			deadline = _deadline_after(interval);
		}
	}

done:
	_timer_unlock(timer);
#if defined(_WIN32)
	return 0;
#else
	return nullptr;
#endif
}

osal_timer_t *osal_timer_create(osal_timer_callback_t callback, void *context)
{
	osal_timer_t *timer;

	_clear_error();
	if (callback == nullptr) {
		_set_error("timer callback must not be NULL");
		return nullptr;
	}

	timer = calloc(1, sizeof *timer);
	if (timer == nullptr) {
		_set_error("out of memory");
		return nullptr;
	}

	timer->callback = callback;
	timer->context = context;
	if (!_timer_sync_init(timer)) {
		free(timer);
		return nullptr;
	}
	if (!_timer_thread_start(timer)) {
		_timer_sync_destroy(timer);
		free(timer);
		return nullptr;
	}
	return timer;
}

bool osal_timer_start(osal_timer_t *timer, uint64_t delay_ms,
		      uint64_t interval_ms)
{
	_clear_error();
	if (timer == nullptr) {
		_set_error("timer must not be NULL");
		return false;
	}

	_timer_lock(timer);
	if (timer->quitting) {
		_timer_unlock(timer);
		_set_error("timer is being destroyed");
		return false;
	}

	timer->delay_ms = delay_ms;
	timer->interval_ms = interval_ms;
	timer->running = true;
	timer->generation++;
	_timer_condition_wake(timer);
	_timer_unlock(timer);
	return true;
}

void osal_timer_stop(osal_timer_t *timer)
{
	if (timer == nullptr)
		return;

	_timer_lock(timer);
	timer->running = false;
	timer->generation++;
	_timer_condition_wake(timer);
	if (!_timer_is_worker_thread(timer)) {
		while (timer->callback_active)
			_timer_condition_wait(timer);
	}
	_timer_unlock(timer);
}

void osal_timer_destroy(osal_timer_t *timer)
{
	if (timer == nullptr)
		return;

	if (_timer_is_worker_thread(timer)) {
		_set_error("cannot destroy a timer from its own callback");
		return;
	}

	_timer_lock(timer);
	timer->quitting = true;
	timer->running = false;
	timer->generation++;
	_timer_condition_wake(timer);
	_timer_unlock(timer);

	_timer_thread_join(timer);
	_timer_sync_destroy(timer);
	free(timer);
}
