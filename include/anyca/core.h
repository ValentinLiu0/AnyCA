/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_CORE_H
#define ANYCA_CORE_H

/**
 * @file core.h
 * @brief Process-wide core state: configured CAs, HSM tokens and the store.
 *
 * The core and store are not thread-safe.  Multi-threaded programs must run
 * every core or store operation between core_session_begin() and
 * core_session_end(); a single-threaded program, such as the CLI, may call
 * the accessors directly.
 */

#include <stdbool.h>
#include <stddef.h>

#include <anyca/ca.h>
#include <anyca/config.h>
#include <anyca/hsm.h>
#include <anyca/store.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Version of the core library and of the executables built with it, as
 * "MAJOR.MINOR.PATCH-commit" (the commit is "unknown" outside a git
 * checkout).
 *
 * The same value is compiled into anyca_cli and anyca_server.  The string is
 * static and may be used before core_init().
 */
const char *core_version(void);

/**
 * Initialize the global core from config.
 *
 * Opens the store and the PKCS #11 modules used by the stored CAs, then
 * builds one ca_t per CA, checking its certificate and HSM keys.  CAs that
 * fail validation are logged and skipped.  config must stay valid until
 * core_fini(); on success the session lock is ready.
 *
 * @return true when global setup succeeded, even if some CAs were skipped;
 *         false on invalid configuration or store failure (no state kept).
 */
bool core_init(const config_t *config);

/** Release the global core state.  No other thread may use the core, store or
 *  a session while this runs.  A no-op when not initialized. */
void core_fini(void);

/**
 * Begin a critical section over core and store state.
 *
 * Takes the core lock and reloads the CA configuration when another process
 * changed the store, so CLI changes take effect without a restart.  Unchanged
 * CAs keep their runtime objects and token handles; changed CAs are rebuilt,
 * and a failed rebuild keeps the previous runtime.  Deleted CAs are released.
 * A failed reload is logged and the current state stays in use.
 *
 * Sessions must not be nested; pair every call with core_session_end().
 */
void core_session_begin(void);

/** End the critical section started by core_session_begin(). */
void core_session_end(void);

/** Number of currently loaded CAs. */
unsigned core_ca_count(void);

/**
 * CA at index, or NULL when out of range.
 *
 * The pointer is valid until the next core_session_begin() may replace or
 * release the CA.
 */
ca_t *core_ca_at(unsigned index);

/** CA whose name matches, or NULL.  Same lifetime as core_ca_at(). */
ca_t *core_ca_by_name(const char *name);

/** CA whose OCSP responder endpoint matches, or NULL.  Same lifetime as
 *  core_ca_at(). */
ca_t *core_ca_by_ocsp_endpoint(const char *endpoint);

/** HSM token holding the CA private key, or NULL when ca did not come from a
 *  core accessor.  Valid until the next session may rebuild the CA. */
hsm_token_t *core_ca_token(const ca_t *ca);

/** HSM token holding the OCSP signing key; same rules as core_ca_token(). */
hsm_token_t *core_ca_ocsp_signer_token(const ca_t *ca);

/**
 * Store id of the CA, addressing its certificate and revocation tables.
 *
 * A key rotation yields a new id; the previous identity keeps its records.
 * Returns 0 when ca did not come from a core accessor.
 */
store_ca_id_t core_ca_store_id(const ca_t *ca);

/** CRL publish directory, or NULL when publication is disabled. */
const char *core_crl_publish_path(void);

/** CA certificate publish directory, or NULL when disabled. */
const char *core_cacerts_publish_path(void);

/**
 * Build, sign and publish one CA's CRL.
 *
 * Writes <crl_publish_path>/<CA-name>/<CA-name>.crl atomically and records
 * the CRL number in the store.  Multi-threaded callers must hold a session.
 *
 * @return true on success; false when publishing is disabled, the CA is not
 *         managed by the core, or building, signing, writing or recording
 *         fails.
 */
bool core_publish_crl(ca_t *ca);

/**
 * Publish one CA's DER certificate to
 * <cacerts_publish_path>/<CA-name>.crt.  Multi-threaded callers must hold a
 * session.
 *
 * @return true on success; false when publishing is disabled, the CA is not
 *         managed by the core, or the write fails.
 */
bool core_publish_ca_certificate(const ca_t *ca);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_CORE_H
