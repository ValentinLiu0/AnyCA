/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_STORE_H
#define ANYCA_STORE_H

/**
 * @file store.h
 * @brief Process-wide SQLite store for CA configurations, issued
 *        certificates and revocations.
 *
 * Each CA identity (name, key_hash) owns a certificate table and a revocation
 * table; key_hash is the SHA-256 of the issuer's DER SubjectPublicKeyInfo.  A
 * name re-registered with a different key hash gets a new id and tables; old
 * records stay with the old identity.
 *
 * The ca_config table holds one complete CA configuration per name,
 * including DER certificates and token PINs; the core loads it at start-up.
 * CA definitions do not appear in the YAML configuration.
 *
 * Records are addressed by CA id and canonical big-endian serial (the DER
 * INTEGER value without tag, length or sign padding; zero is 0x00).  Get
 * functions allocate the serial; free it with the matching function.  The
 * store is a singleton and not thread-safe; serialize access, for example
 * with core_session_begin()/core_session_end().
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Size of the issuer SPKI SHA-256 hash. */
#define STORE_CA_KEY_HASH_SIZE 32

/**
 * Default hash algorithm for generated OCSP signing certificates.
 *
 * Returned by store_ca_config_get() when the stored value is missing or
 * empty, including rows created before the field existed.
 */
#define STORE_DEFAULT_OCSP_SIGNER_DIGEST "sha384"

/** Registered CA identity, obtained from store_ca_register(). 0 is invalid. */
typedef int64_t store_ca_id_t;

/** Store operation result.  STORE_OK is zero, failures are negative. */
typedef enum store_result {
	STORE_OK = 0,
	/** A NULL/empty name, serial or output pointer was supplied. */
	STORE_ERR_ARGUMENT = -1,
	/** No CA or certificate matches the lookup key. */
	STORE_ERR_NOT_FOUND = -2,
	/** A row with the same key already exists. */
	STORE_ERR_DUPLICATE = -3,
	/** The operation violates a constraint, e.g. deleting a revoked
	 *  certificate or revoking an unknown certificate. */
	STORE_ERR_CONFLICT = -4,
	/** SQLite reported an error; see the log for details. */
	STORE_ERR_DATABASE = -5,
	/** Memory allocation failed. */
	STORE_ERR_MEMORY = -6,
} store_result_t;

/** One issued-certificate record. */
typedef struct store_certificate {
	/** Serial number, canonical big-endian bytes. */
	unsigned char *serial;
	size_t serial_length;
	/** Unix time of notAfter; 0 when unknown. */
	int64_t not_after;
} store_certificate_t;

/** One revoked-certificate record. */
typedef struct store_revocation {
	/** Serial number, canonical big-endian bytes. */
	unsigned char *serial;
	size_t serial_length;
	/** Unix time of revocation. */
	int64_t revoked_at;
	/** RFC 5280 reasonCode; 0 means unspecified. */
	int reason;
} store_revocation_t;

/** One registered CA identity. */
typedef struct store_ca_record {
	store_ca_id_t id;
	/** CA name; osal_malloc()ed. */
	char *name;
	/** SHA-256 of the CA DER SubjectPublicKeyInfo. */
	unsigned char key_hash[STORE_CA_KEY_HASH_SIZE];
	size_t key_hash_length;
} store_ca_record_t;

/**
 * One CA configuration entry.
 *
 * All strings and byte buffers are owned by the entry and released with
 * store_ca_config_free().  PINs are stored in the database because the
 * service must be able to log in to the tokens without another secret store.
 * The pin and ocsp_signer_pin fields are allocated with
 * osal_secure_malloc(); callers that replace them must do the same.
 */
typedef struct store_ca_config {
	char *name;
	char *hsm_provider;
	char *token_label;
	char *pin;
	char *key_label;
	/** DER-encoded CA certificate. */
	unsigned char *ca_cert;
	size_t ca_cert_length;
	/**
	 * HSM provider for the OCSP signer key.  NULL or empty means the CA
	 * provider; a stored value lets the OCSP key live in a different
	 * PKCS #11 module than the CA key.
	 */
	char *ocsp_signer_hsm_provider;
	char *ocsp_signer_token_label;
	char *ocsp_signer_pin;
	char *ocsp_signer_key_label;
	/** DER-encoded OCSP signing certificate. */
	unsigned char *ocsp_signer_cert;
	size_t ocsp_signer_cert_length;
	/**
	 * Hash algorithm name for generated OCSP signing certificates.
	 * store_ca_config_get() always supplies the default
	 * (STORE_DEFAULT_OCSP_SIGNER_DIGEST) when no value is stored.
	 */
	char *ocsp_signer_digest;
	uint32_t crl_publish_period_min;
	uint32_t ocsp_update_period_min;
	/** Number of the most recently published CRL; 0 before the first. */
	uint64_t crl_number;
	char *ocsp_responder_endpoint;
} store_ca_config_t;

/**
 * Add a CA configuration entry, keyed by name and ocsp_responder_endpoint.
 *
 * The core registers the CA identity separately at start-up.  Publish
 * directories are global configuration, and AIA and CRL distribution point
 * URIs belong to the YAML certificate_templates.
 *
 * @return STORE_OK, STORE_ERR_DUPLICATE when the name or endpoint exists, or
 *         another store_result_t error.
 */
store_result_t
store_ca_config_add(const store_ca_config_t *config);

/**
 * Replace the CA configuration entry named config->name.
 *
 * Every field except name and crl_number is replaced.  crl_number is written
 * only by store_ca_config_set_crl_number(), so an edit cannot roll back a
 * number published meanwhile.  The name is the lookup key and cannot be
 * changed here.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, STORE_ERR_DUPLICATE when the
 *         responder endpoint belongs to another CA, or another
 *         store_result_t error.
 */
store_result_t
store_ca_config_update(const store_ca_config_t *config);

/**
 * Look up a CA configuration entry by name.
 *
 * On success config must be released with store_ca_config_free(); it is
 * zeroed first.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, or another store_result_t error.
 */
store_result_t
store_ca_config_get(const char *name, store_ca_config_t *config);

/**
 * List CA configuration entries ordered by name.
 *
 * configs is osal_malloc()ed and NULL when *count is 0; release it with
 * store_ca_config_list_free().
 */
store_result_t
store_ca_config_list(store_ca_config_t **configs, size_t *count);

/**
 * Delete a CA configuration entry.  Its registered identity, certificate
 * records and revocations are kept as historical data.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, or another store_result_t error.
 */
store_result_t store_ca_config_delete(const char *name);

/** Release a CA configuration entry and the memory it owns. */
void store_ca_config_free(store_ca_config_t *config);

/** Release a list returned by store_ca_config_list(). */
void store_ca_config_list_free(store_ca_config_t *configs, size_t count);

/**
 * Open the SQLite store, creating the file and schema when needed.
 *
 * Uses read-write/create mode, foreign keys, WAL and full synchronous
 * commits.  An incompatible schema is rejected.
 *
 * @return true on success; false on invalid path, open or schema error, or
 *         when the store is already open.
 */
bool store_init(const char *path);

/**
 * Read the data version of the open connection.
 *
 * SQLite increments it when another connection commits, letting a long-running
 * server detect CLI changes and reload its configuration.
 *
 * @return STORE_OK, STORE_ERR_ARGUMENT, or another store_result_t error.
 */
store_result_t store_data_version(uint64_t *version);

/** Close the store and release the SQLite connection. */
void store_fini(void);

/**
 * Reserve the next CRL number for a registered CA.
 *
 * The first reservation seeds the sequence with the current Unix time; later
 * ones use max(next_number, now), so the sequence stays monotonic.  The read
 * and update run in one immediate SQLite transaction.  A failed publication
 * may leave a gap; numbers are never reused.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND for an unknown CA id, or another
 *         store_result_t error.
 */
store_result_t
store_crl_number_reserve(store_ca_id_t ca_id, uint64_t *number);

/**
 * Record the most recently published CRL number for the named CA.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, or another store_result_t error.
 */
store_result_t
store_ca_config_set_crl_number(const char *name, uint64_t number);

/**
 * Register a CA identity and return its id.
 *
 * key_hash is the SHA-256 of the issuer's DER SubjectPublicKeyInfo and must
 * be STORE_CA_KEY_HASH_SIZE bytes.  Registering the same (name, key_hash) is
 * idempotent; another key hash gets a new id and tables.  ca_id is set to 0
 * on failure.
 */
store_result_t
store_ca_register(const char *name, const unsigned char *key_hash,
		  size_t key_hash_length, store_ca_id_t *ca_id);

/**
 * List registered CA identities ordered by id.  records is osal_malloc()ed
 * and NULL when *count is 0; release it with store_ca_list_free().
 */
store_result_t store_ca_list(store_ca_record_t **records,
					   size_t *count);

/** Release a list returned by store_ca_list(). */
void store_ca_list_free(store_ca_record_t *records, size_t count);

/**
 * Record an issued certificate; the store copies the serial.
 *
 * @return STORE_OK, STORE_ERR_DUPLICATE when the serial exists, or another
 *         store_result_t error.
 */
store_result_t
store_certificate_add(store_ca_id_t ca_id,
		      const store_certificate_t *certificate);

/**
 * Look up an issued certificate.
 *
 * On success certificate->serial is osal_malloc()ed and must be released with
 * store_certificate_free(); certificate is zeroed first.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, or another store_result_t error.
 */
store_result_t
store_certificate_get(store_ca_id_t ca_id, const unsigned char *serial,
		      size_t serial_length,
		      store_certificate_t *certificate);

/**
 * Tell whether an issued certificate is recorded.  Cheaper than
 * store_certificate_get(): no serial buffer is allocated.
 *
 * @return STORE_OK when recorded, STORE_ERR_NOT_FOUND otherwise, or another
 *         store_result_t error.
 */
store_result_t
store_certificate_exists(store_ca_id_t ca_id, const unsigned char *serial,
			 size_t serial_length);

/**
 * List the certificates recorded for a CA, newest first.
 *
 * Ordered by not_after descending, then serial descending; unknown not_after
 * values come last.  limit > 0 returns at most limit records, limit <= 0
 * returns all.  Each element owns its serial; release the list with
 * store_certificate_list_free().
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND for an unknown CA id, or another
 *         store_result_t error.
 */
store_result_t
store_certificate_list(store_ca_id_t ca_id, int64_t limit,
		       store_certificate_t **certificates, size_t *count);

/**
 * Update not_after of the certificate identified by serial.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, or another store_result_t error.
 */
store_result_t
store_certificate_update(store_ca_id_t ca_id,
			 const store_certificate_t *certificate);

/**
 * Delete an issued certificate.  A still-revoked certificate cannot be
 * deleted; delete the revocation record first.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, STORE_ERR_CONFLICT when still
 *         revoked, or another store_result_t error.
 */
store_result_t
store_certificate_delete(store_ca_id_t ca_id, const unsigned char *serial,
			 size_t serial_length);

/** Release the serial of a record returned by store_certificate_get(). */
void store_certificate_free(store_certificate_t *certificate);

/** Release a list returned by store_certificate_list(). */
void store_certificate_list_free(store_certificate_t *certificates,
				 size_t count);

/**
 * Record a revoked certificate, which must already be recorded; the store
 * copies the serial.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND, STORE_ERR_DUPLICATE when already
 *         revoked, or another store_result_t error.
 */
store_result_t
store_revocation_add(store_ca_id_t ca_id,
		     const store_revocation_t *revocation);

/**
 * Look up a revoked certificate.
 *
 * On success revocation->serial is osal_malloc()ed and must be released with
 * store_revocation_free(); revocation is zeroed first.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND when not revoked, or another
 *         store_result_t error.
 */
store_result_t
store_revocation_get(store_ca_id_t ca_id, const unsigned char *serial,
		     size_t serial_length, store_revocation_t *revocation);

/**
 * List the revocation records of a CA, most recent first.
 *
 * Ordered by revoked_at descending, then serial descending.  limit > 0
 * returns at most limit records, limit <= 0 returns all.  Each element owns
 * its serial; release the list with store_revocation_list_free().
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND for an unknown CA id, or another
 *         store_result_t error.
 */
store_result_t
store_revocation_list(store_ca_id_t ca_id, int64_t limit,
		      store_revocation_t **revocations, size_t *count);

/**
 * Update revoked_at and reason of the revocation record identified by
 * serial.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND when not revoked, or another
 *         store_result_t error.
 */
store_result_t
store_revocation_update(store_ca_id_t ca_id,
			const store_revocation_t *revocation);

/**
 * Delete a revocation record, making the certificate good again; the
 * certificate record is left untouched.
 *
 * @return STORE_OK, STORE_ERR_NOT_FOUND when not revoked, or another
 *         store_result_t error.
 */
store_result_t
store_revocation_delete(store_ca_id_t ca_id, const unsigned char *serial,
			size_t serial_length);

/** Release the serial of a record returned by store_revocation_get(). */
void store_revocation_free(store_revocation_t *revocation);

/** Release a list returned by store_revocation_list(). */
void store_revocation_list_free(store_revocation_t *revocations,
				size_t count);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_STORE_H
