/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_OSAL_TIMER_H
#define ANYCA_OSAL_TIMER_H

/**
 * @file timer.h
 * @brief Cross-platform one-shot and periodic timers.
 *
 * A timer owns a worker thread that invokes the callback.  Deadlines use a
 * monotonic clock, so system time changes do not affect them.  At most one
 * callback runs at a time for a given timer.
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque timer handle. */
typedef struct osal_timer osal_timer_t;

/**
 * Timer callback, run on the timer's worker thread.
 *
 * It may call osal_timer_start() or osal_timer_stop() on @p timer, but must
 * not call osal_timer_destroy() on it.
 */
typedef void (*osal_timer_callback_t)(osal_timer_t *timer, void *context);

/**
 * Create a stopped timer.  The worker thread starts immediately and waits
 * until the timer is started; release with osal_timer_destroy().
 *
 * @param callback function invoked on each expiration; must not be NULL.
 * @param context  value passed to every callback invocation.
 */
osal_timer_t *osal_timer_create(osal_timer_callback_t callback,
					      void *context);

/**
 * Arm or re-arm a timer.
 *
 * The first callback runs after delay_ms.  interval_ms zero makes the timer
 * one-shot; a nonzero interval reschedules it that long after each callback
 * returns.  Starting a running timer replaces its schedule from now without
 * interrupting an active callback.  Stopped and expired timers may be
 * restarted.
 *
 * @return false when @p timer is NULL or is being destroyed.
 */
bool osal_timer_start(osal_timer_t *timer, uint64_t delay_ms,
				    uint64_t interval_ms);

/**
 * Cancel a pending expiration.
 *
 * Waits for a running callback to return, except when called from that
 * callback.  NULL or an idle timer is a no-op.
 */
void osal_timer_stop(osal_timer_t *timer);

/**
 * Stop the timer, join its worker thread and free it.
 *
 * Must not be called from the timer's callback, and other threads must not use
 * the timer once destruction starts.  NULL is a no-op.
 */
void osal_timer_destroy(osal_timer_t *timer);

/**
 * Text for the last timer error in the calling thread; "no error" when none
 * was recorded.
 */
const char *osal_timer_error(void);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_OSAL_TIMER_H
