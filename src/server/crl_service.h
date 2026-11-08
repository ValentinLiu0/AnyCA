/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_SERVER_CRL_SERVICE_H
#define ANYCA_SERVER_CRL_SERVICE_H

/**
 * @file crl_service.h
 * @brief Periodic CRL generation for the configured CAs.
 *
 * Start-up publishes one CRL per CA when crl_publish_path is configured, then
 * runs one scheduler tick per minute.  Each tick reloads the CA configuration
 * from the store, picking up CLI changes without a restart, and publishes
 * every CA whose crl_publish_period_min has elapsed.  Publication builds and
 * signs a v2 CRL, writes crl_publish_path/<CA-name>/<CA-name>.crl and records
 * the number in the CA configuration.
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Whether a CA is due for periodic republication.
 *
 * A CA is due when it has never been published, when the clock moved
 * backwards, or when at least period_min minutes elapsed since published_at.
 * A zero period disables periodic publication and is never due.
 */
bool crl_service_is_due(int64_t published_at, int64_t now,
			uint32_t period_min);

/**
 * Publish CRLs once and start periodic generation.
 *
 * Every CA gets a CRL immediately when crl_publish_path is configured; a
 * per-minute tick then publishes CAs whose period has elapsed.  The core must
 * already be initialized.
 *
 * @return true on success; false when the timer cannot be created or started.
 */
bool crl_service_start(void);

/**
 * Stop and release the CRL scheduler, waiting for a running publication to
 * finish so the core may be released.  A no-op when not running.
 */
void crl_service_stop(void);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_SERVER_CRL_SERVICE_H
