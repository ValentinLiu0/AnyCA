/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <anyca/core.h>
#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>
#include <anyca/osal/timer.h>

#include "crl_service.h"

/* How often the scheduler checks reloaded settings and due publications. */
#define CRL_TICK_MS 60000ULL

/* Last publication time of one CA, keyed by name across configuration
 * reloads.  0 means a publication is due at the next tick. */
typedef struct crl_schedule {
	char *name;
	int64_t published_at;
	bool seen;
} crl_schedule_t;

static osal_timer_t *g_timer;
static crl_schedule_t *g_schedules;
static size_t g_schedule_count;

/* Current Unix time; 0 when it cannot be read. */
static int64_t _crl_now(void)
{
	time_t now = time(nullptr);

	return now == (time_t) -1 ? 0 : (int64_t) now;
}

bool crl_service_is_due(int64_t published_at, int64_t now,
			uint32_t period_min)
{
	int64_t period_seconds;

	if (period_min == 0)
		return false;
	period_seconds = (int64_t) period_min * 60;
	return published_at == 0 || now < published_at
		|| now - published_at >= period_seconds;
}

static crl_schedule_t *_crl_schedule_find(const char *name)
{
	if (name == nullptr)
		return nullptr;

	for (size_t i = 0; i < g_schedule_count; i++) {
		if (g_schedules[i].name != nullptr
		    && strcmp(g_schedules[i].name, name) == 0)
			return &g_schedules[i];
	}
	return nullptr;
}

/* Find or add the schedule of a CA; NULL when memory runs out. */
static crl_schedule_t *_crl_schedule_get(const char *name)
{
	crl_schedule_t *schedule = _crl_schedule_find(name);
	crl_schedule_t *grown;
	char *copy;
	size_t length;

	if (schedule != nullptr)
		return schedule;
	if (name == nullptr)
		return nullptr;

	length = strlen(name) + 1;
	copy = osal_malloc(length);
	if (copy == nullptr)
		return nullptr;
	memcpy(copy, name, length);

	grown = osal_realloc(g_schedules,
			     (g_schedule_count + 1) * sizeof *grown);
	if (grown == nullptr) {
		osal_free(copy);
		return nullptr;
	}
	g_schedules = grown;
	schedule = &g_schedules[g_schedule_count++];
	memset(schedule, 0, sizeof *schedule);
	schedule->name = copy;
	return schedule;
}

/* Drop schedules that were not seen in the last tick. */
static void _crl_schedules_prune(void)
{
	size_t kept = 0;

	for (size_t i = 0; i < g_schedule_count; i++) {
		if (!g_schedules[i].seen) {
			osal_free(g_schedules[i].name);
			continue;
		}
		g_schedules[kept++] = g_schedules[i];
	}
	g_schedule_count = kept;
}

/*
 * Periodic scheduler: core_session_begin() reloads changed CA settings, then
 * the tick publishes the CRL of every CA whose crl_publish_period_min has
 * elapsed.
 */
static void _crl_service_tick(osal_timer_t *timer, void *context)
{
	int64_t now = _crl_now();
	unsigned ca_count;

	(void) timer;
	(void) context;

	core_session_begin();

	for (size_t i = 0; i < g_schedule_count; i++)
		g_schedules[i].seen = false;

	ca_count = core_ca_count();
	for (unsigned i = 0; i < ca_count; i++) {
		ca_t *ca = core_ca_at(i);
		crl_schedule_t *schedule;
		bool due;

		if (ca == nullptr || ca->crl_publish_period_min == 0)
			continue;

		schedule = _crl_schedule_get(ca->name);
		if (schedule == nullptr) {
			LOGE("CA %s: cannot record the CRL schedule", ca->name);
			continue;
		}
		schedule->seen = true;

		due = crl_service_is_due(schedule->published_at, now,
					 ca->crl_publish_period_min);
		if (!due)
			continue;

		if (core_publish_crl(ca))
			schedule->published_at = now;
		else
			LOGE("CA %s: CRL publication failed", ca->name);
	}

	_crl_schedules_prune();
	core_session_end();
}

bool crl_service_start(void)
{
	const char *publish_path = core_crl_publish_path();
	bool publish = publish_path != nullptr && publish_path[0] != '\0';
	int64_t now;

	if (!publish) {
		if (core_ca_count() != 0)
			LOGW("No crl_publish_path is configured; "
			     "skipping CRL generation");
		return true;
	}

	/* Every start-up publishes once, even without an update period. */
	now = _crl_now();
	core_session_begin();
	unsigned ca_count = core_ca_count();
	for (unsigned i = 0; i < ca_count; i++) {
		ca_t *ca = core_ca_at(i);
		crl_schedule_t *schedule;

		if (ca == nullptr)
			continue;
		if (!core_publish_crl(ca)) {
			LOGW("CA %s: initial CRL generation failed", ca->name);
			continue;
		}
		schedule = _crl_schedule_get(ca->name);
		if (schedule != nullptr)
			schedule->published_at = now;
	}
	core_session_end();

	g_timer = osal_timer_create(_crl_service_tick, nullptr);
	if (g_timer == nullptr) {
		LOGE("Cannot create the CRL scheduler: %s", osal_timer_error());
		crl_service_stop();
		return false;
	}
	if (!osal_timer_start(g_timer, CRL_TICK_MS, CRL_TICK_MS)) {
		LOGE("Cannot start the CRL scheduler: %s", osal_timer_error());
		crl_service_stop();
		return false;
	}

	LOGI("CRL scheduler running every %llu second(s)",
	     (unsigned long long) (CRL_TICK_MS / 1000));
	return true;
}

void crl_service_stop(void)
{
	if (g_timer != nullptr) {
		osal_timer_stop(g_timer);
		osal_timer_destroy(g_timer);
		g_timer = nullptr;
	}

	for (size_t i = 0; i < g_schedule_count; i++)
		osal_free(g_schedules[i].name);
	osal_free(g_schedules);
	g_schedules = nullptr;
	g_schedule_count = 0;
}
