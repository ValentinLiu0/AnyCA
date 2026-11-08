/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <threads.h>
#include <time.h>

#include <sqlite3.h>

#include <anyca/osal/file.h>
#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>

#include <anyca/store.h>

/*
 * Schema version 1:
 *
 *   ca         (id, name, key_hash, UNIQUE (name, key_hash))
 *   crl_state  (ca_id PRIMARY KEY REFERENCES ca, next_number)
 *   ca_config  (name PRIMARY KEY, provider/token/key settings, DER certs,
 *               update periods, ocsp_responder_endpoint, crl_number)
 *
 * Each CA owns two on-demand tables, certificate_<id> (serial, not_after) and
 * revocation_<id> (serial, revoked_at, reason, referencing the certificate).
 * The numeric id keeps names and hashes out of SQL identifiers.  Serials are
 * canonical big-endian bytes because X.509 serials may exceed 64 bits.
 *
 * An empty ocsp_signer_hsm_provider means the OCSP signer key uses the CA
 * provider.  The SQL below is the authoritative column list.
 */
#define STORE_SCHEMA_VERSION 1
/* Expand the version constant into the SQL text below. */
#define STORE_STRINGIFY_(value) #value
#define STORE_STRINGIFY(value) STORE_STRINGIFY_(value)

static const char store_schema_sql[] =
	"BEGIN;"
	"CREATE TABLE IF NOT EXISTS ca ("
	"    id       INTEGER PRIMARY KEY,"
	"    name     TEXT NOT NULL,"
	"    key_hash BLOB NOT NULL,"
	"    UNIQUE (name, key_hash)"
	");"
	"CREATE TABLE IF NOT EXISTS crl_state ("
	"    ca_id       INTEGER PRIMARY KEY REFERENCES ca (id),"
	"    next_number INTEGER NOT NULL"
	");"
	"CREATE TABLE IF NOT EXISTS ca_config ("
	"    name                    TEXT PRIMARY KEY,"
	"    hsm_provider            TEXT NOT NULL,"
	"    token_label             TEXT NOT NULL,"
	"    pin                     TEXT NOT NULL,"
	"    key_label               TEXT NOT NULL,"
	"    ca_cert                 BLOB NOT NULL,"
	"    ocsp_signer_token_label TEXT NOT NULL,"
	"    ocsp_signer_pin         TEXT NOT NULL,"
	"    ocsp_signer_key_label   TEXT NOT NULL,"
	"    ocsp_signer_cert        BLOB NOT NULL,"
	"    crl_publish_period_min  INTEGER NOT NULL DEFAULT 0,"
	"    ocsp_update_period_min  INTEGER NOT NULL DEFAULT 0,"
	"    ocsp_responder_endpoint TEXT NOT NULL UNIQUE,"
	"    ocsp_signer_digest      TEXT NOT NULL DEFAULT 'sha384',"
	"    crl_number              INTEGER NOT NULL DEFAULT 0,"
	"    ocsp_signer_hsm_provider TEXT NOT NULL DEFAULT ''"
	");"
	"PRAGMA user_version = " STORE_STRINGIFY(STORE_SCHEMA_VERSION) ";"
	"COMMIT;";

static sqlite3 *g_store;

static bool _store_is_open(void)
{
	if (g_store == nullptr) {
		LOGE("Store is not open");
		return false;
	}
	return true;
}

static void _store_log_error(const char *what)
{
	LOGE("%s failed: %s", what, sqlite3_errmsg(g_store));
}

/* Run one or more SQL statements, logging the SQLite error on failure. */
static bool _store_exec(sqlite3 *db, const char *sql)
{
	char *message = nullptr;
	int result = sqlite3_exec(db, sql, nullptr, nullptr, &message);

	if (result != SQLITE_OK) {
		LOGE("Store SQL failed: %s",
		     message != nullptr ? message : sqlite3_errstr(result));
		sqlite3_free(message);
		return false;
	}
	return true;
}

/*
 * Run initialization SQL, retrying while another process holds the database
 * lock.  Two processes opening a fresh store at the same time can race on
 * PRAGMA journal_mode / schema creation; busy_timeout does not cover every
 * such statement.
 */
static bool _store_exec_retry(sqlite3 *db, const char *sql)
{
	const struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
	char *message;
	int result;

	for (unsigned attempt = 0; attempt < 50; attempt++) {
		message = nullptr;
		result = sqlite3_exec(db, sql, nullptr, nullptr, &message);
		if (result == SQLITE_OK) {
			sqlite3_free(message);
			return true;
		}
		sqlite3_free(message);
		if (result != SQLITE_BUSY && result != SQLITE_LOCKED) {
			LOGE("Store SQL failed: %s", sqlite3_errstr(result));
			return false;
		}
		(void) thrd_sleep(&delay, nullptr);
	}

	LOGE("Store initialization is still locked by another process");
	return false;
}

static store_result_t _store_validate_ca(const char *ca_name)
{
	if (ca_name == nullptr || ca_name[0] == '\0') {
		LOGE("CA name is not set");
		return STORE_ERR_ARGUMENT;
	}
	return STORE_OK;
}

static store_result_t _store_validate_ca_id(store_ca_id_t ca_id)
{
	if (ca_id <= 0) {
		LOGE("CA id is not valid");
		return STORE_ERR_ARGUMENT;
	}
	return STORE_OK;
}

/* RFC 5280 serialNumber: a positive integer of at most 20 octets. */
#define STORE_MAX_SERIAL_LENGTH 20

/* Largest Unix time that a four-digit GeneralizedTime can encode. */
#define STORE_MAX_ASN1_EPOCH ((int64_t) 253402300799)

static store_result_t _store_validate_serial(const unsigned char *serial,
					     size_t serial_length)
{
	bool nonzero = false;

	if (serial == nullptr || serial_length == 0
	    || serial_length > STORE_MAX_SERIAL_LENGTH
	    || serial_length > (size_t) INT_MAX) {
		LOGE("Certificate serial is not set or too large");
		return STORE_ERR_ARGUMENT;
	}
	if (serial_length == STORE_MAX_SERIAL_LENGTH
	    && (serial[0] & 0x80) != 0) {
		LOGE("Certificate serial is not a positive 20-byte value");
		return STORE_ERR_ARGUMENT;
	}
	for (size_t i = 0; i < serial_length; i++) {
		if (serial[i] != 0) {
			nonzero = true;
			break;
		}
	}
	if (!nonzero) {
		LOGE("Certificate serial must be positive");
		return STORE_ERR_ARGUMENT;
	}
	return STORE_OK;
}

/* RFC 5280 revocationDate must be a valid ASN.1 time. */
static store_result_t _store_validate_revoked_at(int64_t revoked_at)
{
	if (revoked_at <= 0 || revoked_at > STORE_MAX_ASN1_EPOCH) {
		LOGE("Revocation time is outside the ASN.1 time range");
		return STORE_ERR_ARGUMENT;
	}
	return STORE_OK;
}

/*
 * Prepare SQL with %lld placeholders for the numeric CA id; extra arguments
 * are harmless.
 */
static store_result_t _store_prepare_ca(sqlite3_stmt **stmt,
					const char *format,
					sqlite3_int64 ca_id,
					const char *what)
{
	char *sql = sqlite3_mprintf(format, (long long) ca_id,
				    (long long) ca_id, (long long) ca_id);
	int result;

	*stmt = nullptr;
	if (sql == nullptr) {
		LOGE("%s: out of memory", what);
		return STORE_ERR_MEMORY;
	}

	result = sqlite3_prepare_v2(g_store, sql, -1, stmt, nullptr);
	sqlite3_free(sql);
	if (result != SQLITE_OK) {
		_store_log_error(what);
		return STORE_ERR_DATABASE;
	}
	return STORE_OK;
}

/* Copy a non-empty BLOB column into a new osal_malloc()ed buffer. */
static store_result_t _store_copy_blob(sqlite3_stmt *stmt, int column,
				       unsigned char **data, size_t *length)
{
	const void *source = sqlite3_column_blob(stmt, column);
	int size = sqlite3_column_bytes(stmt, column);
	unsigned char *copy;

	if (source == nullptr || size <= 0)
		return STORE_ERR_DATABASE;

	copy = osal_malloc((size_t) size);
	if (copy == nullptr)
		return STORE_ERR_MEMORY;
	memcpy(copy, source, (size_t) size);
	*data = copy;
	*length = (size_t) size;
	return STORE_OK;
}

/*
 * Copy a BLOB column that may be empty.  A zero-length value yields a NULL
 * buffer and length zero; the caller can fill it in later.
 */
static store_result_t _store_copy_optional_blob(sqlite3_stmt *stmt, int column,
						unsigned char **data,
						size_t *length)
{
	const void *source = sqlite3_column_blob(stmt, column);
	int size = sqlite3_column_bytes(stmt, column);

	*data = nullptr;
	*length = 0;
	if (size == 0)
		return STORE_OK;
	if (source == nullptr || size < 0)
		return STORE_ERR_DATABASE;
	return _store_copy_blob(stmt, column, data, length);
}

/* Grow an array so that it holds at least needed elements. */
static bool _store_reserve(void **items, size_t *capacity, size_t needed,
			   size_t item_size)
{
	size_t new_capacity;
	void *grown;

	if (needed <= *capacity)
		return true;

	new_capacity = *capacity == 0 ? 16 : *capacity;
	while (new_capacity < needed) {
		if (new_capacity > SIZE_MAX / 2) {
			new_capacity = needed;
			break;
		}
		new_capacity *= 2;
	}
	if (new_capacity > SIZE_MAX / item_size)
		return false;

	grown = osal_realloc(*items, new_capacity * item_size);
	if (grown == nullptr)
		return false;
	*items = grown;
	*capacity = new_capacity;
	return true;
}

/* Tell whether a table exists. */
static bool _store_table_exists(sqlite3 *db, const char *table, bool *exists)
{
	sqlite3_stmt *stmt = nullptr;
	int rc;

	*exists = false;
	rc = sqlite3_prepare_v2(
		db,
		"SELECT 1 FROM sqlite_master"
		" WHERE type = 'table' AND name = ?1",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		LOGE("Cannot inspect store schema: %s", sqlite3_errmsg(db));
		return false;
	}

	sqlite3_bind_text(stmt, 1, table, -1, SQLITE_TRANSIENT);
	*exists = sqlite3_step(stmt) == SQLITE_ROW;
	sqlite3_finalize(stmt);
	return true;
}

/*
 * Create the schema for a new database, or verify the version of an existing
 * one.  Databases written by another schema version are rejected; the program
 * does not migrate them.
 */
static bool _store_prepare_schema(sqlite3 *db)
{
	sqlite3_stmt *stmt = nullptr;
	bool exists = false;
	int version = 0;
	int rc;

	rc = sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		LOGE("Cannot read store schema version: %s",
		     sqlite3_errmsg(db));
		return false;
	}
	if (sqlite3_step(stmt) == SQLITE_ROW)
		version = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);

	if (!_store_table_exists(db, "ca_config", &exists))
		return false;

	if (!exists) {
		bool has_ca = false;

		if (!_store_table_exists(db, "ca", &has_ca))
			return false;
		if (has_ca || version != 0) {
			LOGE("Unsupported store schema; create a new database");
			return false;
		}
		/* The schema and its user_version are committed together, so
		 * an interrupted creation never leaves version 0 with tables
		 * present. */
		return _store_exec_retry(db, store_schema_sql);
	}

	if (version != STORE_SCHEMA_VERSION) {
		LOGE("Unsupported store schema version %d (expected %d); "
		     "create a new database",
		     version, STORE_SCHEMA_VERSION);
		return false;
	}
	return true;
}

/* Look up the id registered for (name, key_hash). */
static store_result_t _store_ca_find(const char *ca_name,
				     const unsigned char *key_hash,
				     size_t key_hash_length,
				     sqlite3_int64 *ca_id)
{
	sqlite3_stmt *stmt = nullptr;
	store_result_t result = STORE_ERR_DATABASE;
	int rc;

	rc = sqlite3_prepare_v2(
		g_store,
		"SELECT id FROM ca WHERE name = ?1 AND key_hash = ?2",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA lookup");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_text(stmt, 1, ca_name, -1, SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmt, 2, key_hash, (int) key_hash_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		*ca_id = sqlite3_column_int64(stmt, 0);
		result = STORE_OK;
	} else if (rc == SQLITE_DONE) {
		result = STORE_ERR_NOT_FOUND;
	} else {
		_store_log_error("CA lookup");
	}

	sqlite3_finalize(stmt);
	return result;
}

/* Tell whether the name is already registered with any key hash. */
static store_result_t _store_ca_name_exists(const char *ca_name,
					    bool *exists)
{
	sqlite3_stmt *stmt = nullptr;
	store_result_t result = STORE_ERR_DATABASE;
	int rc;

	*exists = false;
	rc = sqlite3_prepare_v2(g_store, "SELECT 1 FROM ca WHERE name = ?1",
				-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA name lookup");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_text(stmt, 1, ca_name, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		*exists = true;
		result = STORE_OK;
	} else if (rc == SQLITE_DONE) {
		result = STORE_OK;
	} else {
		_store_log_error("CA name lookup");
	}

	sqlite3_finalize(stmt);
	return result;
}

/* Create the per-CA tables when they do not exist yet. */
static store_result_t _store_create_ca_tables(sqlite3_int64 ca_id)
{
	char *sql;
	char *message = nullptr;
	int rc;

	sql = sqlite3_mprintf(
		"CREATE TABLE IF NOT EXISTS certificate_%lld ("
		"    serial    BLOB PRIMARY KEY,"
		"    not_after INTEGER"
		") WITHOUT ROWID;"
		"CREATE TABLE IF NOT EXISTS revocation_%lld ("
		"    serial     BLOB PRIMARY KEY,"
		"    revoked_at INTEGER NOT NULL,"
		"    reason     INTEGER,"
		"    FOREIGN KEY (serial)"
		"        REFERENCES certificate_%lld (serial)"
		") WITHOUT ROWID;",
		(long long) ca_id, (long long) ca_id, (long long) ca_id);
	if (sql == nullptr)
		return STORE_ERR_MEMORY;

	rc = sqlite3_exec(g_store, sql, nullptr, nullptr, &message);
	sqlite3_free(sql);
	if (rc != SQLITE_OK) {
		LOGE("Cannot create CA tables: %s",
		     message != nullptr ? message : sqlite3_errmsg(g_store));
		sqlite3_free(message);
		return STORE_ERR_DATABASE;
	}
	return STORE_OK;
}

/* Find or create the identity (name, key_hash) and ensure its tables. */
static store_result_t _store_ca_get_or_create(const char *ca_name,
					      const unsigned char *key_hash,
					      size_t key_hash_length,
					      sqlite3_int64 *ca_id)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	bool name_exists = false;
	int rc;

	result = _store_ca_find(ca_name, key_hash, key_hash_length, ca_id);
	if (result == STORE_OK)
		return _store_create_ca_tables(*ca_id);
	if (result != STORE_ERR_NOT_FOUND)
		return result;

	result = _store_ca_name_exists(ca_name, &name_exists);
	if (result != STORE_OK)
		return result;
	if (name_exists)
		LOGW("CA \"%s\" has a different key hash; registering it as a "
		     "new CA",
		     ca_name);

	rc = sqlite3_prepare_v2(
		g_store,
		"INSERT OR IGNORE INTO ca (name, key_hash) VALUES (?1, ?2)",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA insert");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_text(stmt, 1, ca_name, -1, SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmt, 2, key_hash, (int) key_hash_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("CA insert");
		return STORE_ERR_DATABASE;
	}

	result = _store_ca_find(ca_name, key_hash, key_hash_length, ca_id);
	if (result != STORE_OK)
		return result;
	return _store_create_ca_tables(*ca_id);
}

/* Tell whether a CA id is registered. */
static store_result_t _store_ca_id_lookup(sqlite3_int64 ca_id)
{
	sqlite3_stmt *stmt = nullptr;
	store_result_t result = STORE_ERR_DATABASE;
	int rc;

	rc = sqlite3_prepare_v2(g_store, "SELECT 1 FROM ca WHERE id = ?1",
				-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA id lookup");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_int64(stmt, 1, ca_id);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		result = STORE_OK;
	} else if (rc == SQLITE_DONE) {
		result = STORE_ERR_NOT_FOUND;
	} else {
		_store_log_error("CA id lookup");
	}

	sqlite3_finalize(stmt);
	return result;
}

/* Tell whether a certificate row exists for ca_id and serial. */
static store_result_t _store_certificate_exists(sqlite3_int64 ca_id,
						const unsigned char *serial,
						size_t serial_length)
{
	sqlite3_stmt *stmt = nullptr;
	store_result_t result;
	int rc;

	result = _store_prepare_ca(
		&stmt,
		"SELECT 1 FROM certificate_%lld WHERE serial = ?1",
		ca_id, "Certificate lookup");
	if (result != STORE_OK)
		return result;

	sqlite3_bind_blob(stmt, 1, serial, (int) serial_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		result = STORE_OK;
	} else if (rc == SQLITE_DONE) {
		result = STORE_ERR_NOT_FOUND;
	} else {
		_store_log_error("Certificate lookup");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	return result;
}

store_result_t store_ca_register(const char *name,
				 const unsigned char *key_hash,
				 size_t key_hash_length,
				 store_ca_id_t *ca_id)
{
	store_result_t result;
	sqlite3_int64 id;

	if (ca_id == nullptr) {
		LOGE("CA id output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*ca_id = 0;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca(name);
	if (result != STORE_OK)
		return result;
	if (key_hash == nullptr || key_hash_length != STORE_CA_KEY_HASH_SIZE) {
		LOGE("CA key hash must be %d bytes", STORE_CA_KEY_HASH_SIZE);
		return STORE_ERR_ARGUMENT;
	}

	result = _store_ca_get_or_create(name, key_hash, key_hash_length, &id);
	if (result != STORE_OK)
		return result;

	*ca_id = (store_ca_id_t) id;
	return STORE_OK;
}

store_result_t store_ca_list(store_ca_record_t **records, size_t *count)
{
	store_ca_record_t *items = nullptr;
	size_t capacity = 0;
	size_t used = 0;
	sqlite3_stmt *stmt = nullptr;
	store_result_t result;
	int rc;

	if (records == nullptr || count == nullptr) {
		LOGE("CA list output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*records = nullptr;
	*count = 0;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;

	rc = sqlite3_prepare_v2(g_store,
				"SELECT id, name, key_hash FROM ca ORDER BY id",
				-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA list");
		return STORE_ERR_DATABASE;
	}

	result = STORE_OK;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		const unsigned char *name = sqlite3_column_text(stmt, 1);
		int name_length = sqlite3_column_bytes(stmt, 1);
		const void *key_hash = sqlite3_column_blob(stmt, 2);
		int key_hash_length = sqlite3_column_bytes(stmt, 2);
		store_ca_record_t *record;

		if (name == nullptr || key_hash == nullptr
		    || key_hash_length != STORE_CA_KEY_HASH_SIZE) {
			result = STORE_ERR_DATABASE;
			break;
		}
		if (!_store_reserve((void **) &items, &capacity, used + 1,
				    sizeof *items)) {
			result = STORE_ERR_MEMORY;
			break;
		}

		record = &items[used];
		memset(record, 0, sizeof *record);
		record->name = osal_malloc((size_t) name_length + 1);
		if (record->name == nullptr) {
			result = STORE_ERR_MEMORY;
			break;
		}
		memcpy(record->name, name, (size_t) name_length);
		record->name[name_length] = '\0';
		record->id = (store_ca_id_t) sqlite3_column_int64(stmt, 0);
		memcpy(record->key_hash, key_hash, STORE_CA_KEY_HASH_SIZE);
		record->key_hash_length = STORE_CA_KEY_HASH_SIZE;
		used++;
	}
	if (rc != SQLITE_DONE && result == STORE_OK) {
		_store_log_error("CA list");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result != STORE_OK) {
		store_ca_list_free(items, used);
		return result;
	}

	*records = items;
	*count = used;
	return STORE_OK;
}

void store_ca_list_free(store_ca_record_t *records, size_t count)
{
	if (records == nullptr)
		return;

	for (size_t i = 0; i < count; i++)
		osal_free(records[i].name);
	osal_free(records);
}

static bool _store_text_is_set(const char *value)
{
	return value != nullptr && value[0] != '\0';
}

/* Copy a TEXT column into a new osal_malloc()ed, NUL-terminated string. */
static store_result_t _store_copy_text(sqlite3_stmt *stmt, int column,
				       char **text)
{
	const unsigned char *source = sqlite3_column_text(stmt, column);
	int length = sqlite3_column_bytes(stmt, column);
	char *copy;

	if (source == nullptr || length < 0)
		return STORE_ERR_DATABASE;

	copy = osal_malloc((size_t) length + 1);
	if (copy == nullptr)
		return STORE_ERR_MEMORY;
	memcpy(copy, source, (size_t) length);
	copy[length] = '\0';
	*text = copy;
	return STORE_OK;
}

/* Copy a secret TEXT column into locked, wipe-on-free memory. */
static store_result_t _store_copy_secure_text(sqlite3_stmt *stmt, int column,
					      char **text)
{
	const unsigned char *source = sqlite3_column_text(stmt, column);
	int length = sqlite3_column_bytes(stmt, column);
	char *copy;

	if (source == nullptr || length < 0)
		return STORE_ERR_DATABASE;

	copy = osal_secure_malloc((size_t) length + 1);
	if (copy == nullptr)
		return STORE_ERR_MEMORY;
	memcpy(copy, source, (size_t) length);
	copy[length] = '\0';
	*text = copy;
	return STORE_OK;
}

/* Copy an optional TEXT column; SQL NULL becomes NULL. */
static store_result_t _store_copy_optional_text(sqlite3_stmt *stmt, int column,
						char **text)
{
	*text = nullptr;
	if (sqlite3_column_type(stmt, column) == SQLITE_NULL)
		return STORE_OK;
	return _store_copy_text(stmt, column, text);
}

/* Copy a TEXT column, substituting default_value for NULL or empty text. */
static store_result_t _store_copy_text_default(sqlite3_stmt *stmt, int column,
					       const char *default_value,
					       char **text)
{
	const unsigned char *source = sqlite3_column_text(stmt, column);
	int length = sqlite3_column_bytes(stmt, column);
	char *copy;

	if (source == nullptr || length <= 0) {
		source = (const unsigned char *) default_value;
		length = (int) strlen(default_value);
	}

	copy = osal_malloc((size_t) length + 1);
	if (copy == nullptr)
		return STORE_ERR_MEMORY;
	memcpy(copy, source, (size_t) length);
	copy[length] = '\0';
	*text = copy;
	return STORE_OK;
}

static store_result_t _store_copy_uint32(sqlite3_stmt *stmt, int column,
					 uint32_t *value)
{
	sqlite3_int64 number = sqlite3_column_int64(stmt, column);

	if (number < 0 || (sqlite3_uint64) number > UINT32_MAX)
		return STORE_ERR_DATABASE;
	*value = (uint32_t) number;
	return STORE_OK;
}

static store_result_t _store_copy_uint64(sqlite3_stmt *stmt, int column,
					 uint64_t *value)
{
	sqlite3_int64 number = sqlite3_column_int64(stmt, column);

	if (number < 0)
		return STORE_ERR_DATABASE;
	*value = (uint64_t) number;
	return STORE_OK;
}

/*
 * Column order shared by every ca_config SELECT:
 *
 *  0 name, 1 hsm_provider, 2 token_label, 3 pin, 4 key_label, 5 ca_cert,
 *  6 ocsp_signer_token_label, 7 ocsp_signer_pin, 8 ocsp_signer_key_label,
 *  9 ocsp_signer_cert, 10 crl_publish_period_min,
 * 11 ocsp_update_period_min, 12 ocsp_responder_endpoint,
 * 13 ocsp_signer_digest, 14 crl_number, 15 ocsp_signer_hsm_provider
 */
#define STORE_CA_CONFIG_COLUMNS \
	"name, hsm_provider, token_label, pin, key_label, ca_cert," \
	" ocsp_signer_token_label, ocsp_signer_pin, ocsp_signer_key_label," \
	" ocsp_signer_cert, crl_publish_period_min, ocsp_update_period_min," \
	" ocsp_responder_endpoint, ocsp_signer_digest, crl_number," \
	" ocsp_signer_hsm_provider"

/* Copy one ca_config row into config, which is initially zeroed. */
static store_result_t _store_copy_ca_config(sqlite3_stmt *stmt,
					    store_ca_config_t *config)
{
	store_result_t result;

	result = _store_copy_text(stmt, 0, &config->name);
	if (result == STORE_OK)
		result = _store_copy_text(stmt, 1, &config->hsm_provider);
	if (result == STORE_OK)
		result = _store_copy_text(stmt, 2, &config->token_label);
	if (result == STORE_OK)
		result = _store_copy_secure_text(stmt, 3, &config->pin);
	if (result == STORE_OK)
		result = _store_copy_text(stmt, 4, &config->key_label);
	if (result == STORE_OK)
		result = _store_copy_blob(stmt, 5, &config->ca_cert,
					  &config->ca_cert_length);
	if (result == STORE_OK)
		result = _store_copy_text(stmt, 6,
					  &config->ocsp_signer_token_label);
	if (result == STORE_OK)
		result = _store_copy_secure_text(stmt, 7,
						 &config->ocsp_signer_pin);
	if (result == STORE_OK)
		result = _store_copy_text(stmt, 8,
					  &config->ocsp_signer_key_label);
	if (result == STORE_OK)
		result = _store_copy_optional_blob(
			stmt, 9, &config->ocsp_signer_cert,
			&config->ocsp_signer_cert_length);
	if (result == STORE_OK)
		result = _store_copy_uint32(stmt, 10,
					    &config->crl_publish_period_min);
	if (result == STORE_OK)
		result = _store_copy_uint32(stmt, 11,
					    &config->ocsp_update_period_min);
	if (result == STORE_OK)
		result = _store_copy_text(stmt, 12,
					  &config->ocsp_responder_endpoint);
	if (result == STORE_OK)
		result = _store_copy_text_default(
			stmt, 13, STORE_DEFAULT_OCSP_SIGNER_DIGEST,
			&config->ocsp_signer_digest);
	if (result == STORE_OK)
		result = _store_copy_uint64(stmt, 14, &config->crl_number);
	if (result == STORE_OK)
		result = _store_copy_optional_text(
			stmt, 15, &config->ocsp_signer_hsm_provider);
	return result;
}

static store_result_t
_store_validate_ca_config(const store_ca_config_t *config)
{
	if (config == nullptr) {
		LOGE("CA configuration is not set");
		return STORE_ERR_ARGUMENT;
	}
	if (!_store_text_is_set(config->name)
	    || !_store_text_is_set(config->hsm_provider)
	    || !_store_text_is_set(config->token_label)
	    || !_store_text_is_set(config->pin)
	    || !_store_text_is_set(config->key_label)
	    || !_store_text_is_set(config->ocsp_signer_token_label)
	    || !_store_text_is_set(config->ocsp_signer_pin)
	    || !_store_text_is_set(config->ocsp_signer_key_label)
	    || !_store_text_is_set(config->ocsp_responder_endpoint)) {
		LOGE("CA configuration has an empty required field");
		return STORE_ERR_ARGUMENT;
	}
	if (config->ca_cert == nullptr || config->ca_cert_length == 0
	    || config->ca_cert_length > (size_t) INT_MAX
	    || config->ocsp_signer_cert == nullptr
	    || config->ocsp_signer_cert_length == 0
	    || config->ocsp_signer_cert_length > (size_t) INT_MAX) {
		LOGE("CA configuration certificate is missing or too large");
		return STORE_ERR_ARGUMENT;
	}
	if (config->crl_number > (uint64_t) INT64_MAX) {
		LOGE("CA configuration CRL number is out of range");
		return STORE_ERR_ARGUMENT;
	}
	return STORE_OK;
}

/* Bind a TEXT value, substituting default_value when it is NULL or empty. */
static int _store_bind_text_default(sqlite3_stmt *stmt, int index,
				    const char *value, const char *default_value)
{
	if (!_store_text_is_set(value))
		value = default_value;
	return sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
}

/*
 * Bind a complete ca_config row using the STORE_CA_CONFIG_COLUMNS order.
 * with_crl_number binds the trailing crl_number parameter as well; the
 * UPDATE path leaves it out so ordinary configuration edits never overwrite
 * the number published by the CRL service.
 */
static int _store_bind_ca_config(sqlite3_stmt *stmt,
				 const store_ca_config_t *config,
				 bool with_crl_number)
{
	int rc;

	rc = sqlite3_bind_text(stmt, 1, config->name, -1, SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 2, config->hsm_provider, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 3, config->token_label, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 4, config->pin, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 5, config->key_label, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_blob(stmt, 6, config->ca_cert,
				       (int) config->ca_cert_length,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 7,
				       config->ocsp_signer_token_label, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 8, config->ocsp_signer_pin, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 9,
				       config->ocsp_signer_key_label, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_blob(stmt, 10, config->ocsp_signer_cert,
				       (int) config->ocsp_signer_cert_length,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_int64(stmt, 11,
					config->crl_publish_period_min);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_int64(stmt, 12,
					config->ocsp_update_period_min);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_text(stmt, 13,
				       config->ocsp_responder_endpoint, -1,
				       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = _store_bind_text_default(
			stmt, 14, config->ocsp_signer_digest,
			STORE_DEFAULT_OCSP_SIGNER_DIGEST);
	if (rc == SQLITE_OK)
		rc = _store_bind_text_default(
			stmt, 15, config->ocsp_signer_hsm_provider, "");
	if (rc == SQLITE_OK && with_crl_number)
		rc = sqlite3_bind_int64(stmt, 16,
					(sqlite3_int64) config->crl_number);
	return rc;
}

store_result_t store_ca_config_add(const store_ca_config_t *config)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_config(config);
	if (result != STORE_OK)
		return result;

	rc = sqlite3_prepare_v2(
		g_store,
		"INSERT INTO ca_config ("
		" name, hsm_provider, token_label, pin, key_label, ca_cert,"
		" ocsp_signer_token_label, ocsp_signer_pin,"
		" ocsp_signer_key_label, ocsp_signer_cert,"
		" crl_publish_period_min, ocsp_update_period_min,"
		" ocsp_responder_endpoint,"
		" ocsp_signer_digest, ocsp_signer_hsm_provider, crl_number)"
		" VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,"
		" ?12, ?13, ?14, ?15, ?16)",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration insert");
		return STORE_ERR_DATABASE;
	}

	rc = _store_bind_ca_config(stmt, config, true);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration insert");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc == SQLITE_DONE)
		return STORE_OK;
	if (rc == SQLITE_CONSTRAINT)
		return STORE_ERR_DUPLICATE;
	_store_log_error("CA configuration insert");
	return STORE_ERR_DATABASE;
}

store_result_t store_ca_config_update(const store_ca_config_t *config)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_config(config);
	if (result != STORE_OK)
		return result;

	rc = sqlite3_prepare_v2(
		g_store,
		"UPDATE ca_config SET"
		" hsm_provider = ?2, token_label = ?3, pin = ?4,"
		" key_label = ?5, ca_cert = ?6,"
		" ocsp_signer_token_label = ?7, ocsp_signer_pin = ?8,"
		" ocsp_signer_key_label = ?9, ocsp_signer_cert = ?10,"
		" crl_publish_period_min = ?11, ocsp_update_period_min = ?12,"
		" ocsp_responder_endpoint = ?13,"
		" ocsp_signer_digest = ?14,"
		" ocsp_signer_hsm_provider = ?15"
		" WHERE name = ?1",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration update");
		return STORE_ERR_DATABASE;
	}

	rc = _store_bind_ca_config(stmt, config, false);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration update");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc == SQLITE_CONSTRAINT)
		return STORE_ERR_DUPLICATE;
	if (rc != SQLITE_DONE) {
		_store_log_error("CA configuration update");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

store_result_t store_ca_config_get(const char *name,
				   store_ca_config_t *config)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (config == nullptr) {
		LOGE("CA configuration output is not set");
		return STORE_ERR_ARGUMENT;
	}
	memset(config, 0, sizeof *config);

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	if (!_store_text_is_set(name)) {
		LOGE("CA name is not set");
		return STORE_ERR_ARGUMENT;
	}

	rc = sqlite3_prepare_v2(
		g_store,
		"SELECT " STORE_CA_CONFIG_COLUMNS
		" FROM ca_config WHERE name = ?1",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration lookup");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		result = _store_copy_ca_config(stmt, config);
	} else if (rc == SQLITE_DONE) {
		result = STORE_ERR_NOT_FOUND;
	} else {
		_store_log_error("CA configuration lookup");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result != STORE_OK)
		store_ca_config_free(config);
	return result;
}

store_result_t store_ca_config_list(store_ca_config_t **configs,
				    size_t *count)
{
	store_ca_config_t *items = nullptr;
	size_t capacity = 0;
	size_t used = 0;
	sqlite3_stmt *stmt = nullptr;
	store_result_t result;
	int rc;

	if (configs == nullptr || count == nullptr) {
		LOGE("CA configuration list output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*configs = nullptr;
	*count = 0;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;

	rc = sqlite3_prepare_v2(
		g_store,
		"SELECT " STORE_CA_CONFIG_COLUMNS
		" FROM ca_config ORDER BY name",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration list");
		return STORE_ERR_DATABASE;
	}

	result = STORE_OK;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		store_ca_config_t *record;

		if (!_store_reserve((void **) &items, &capacity, used + 1,
				    sizeof *items)) {
			result = STORE_ERR_MEMORY;
			break;
		}

		record = &items[used];
		memset(record, 0, sizeof *record);
		result = _store_copy_ca_config(stmt, record);
		if (result != STORE_OK) {
			store_ca_config_free(record);
			break;
		}
		used++;
	}
	if (rc != SQLITE_DONE && result == STORE_OK) {
		_store_log_error("CA configuration list");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result != STORE_OK) {
		store_ca_config_list_free(items, used);
		return result;
	}

	*configs = items;
	*count = used;
	return STORE_OK;
}

store_result_t store_ca_config_delete(const char *name)
{
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	if (!_store_text_is_set(name)) {
		LOGE("CA name is not set");
		return STORE_ERR_ARGUMENT;
	}

	rc = sqlite3_prepare_v2(g_store,
				"DELETE FROM ca_config WHERE name = ?1",
				-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA configuration delete");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("CA configuration delete");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

void store_ca_config_free(store_ca_config_t *config)
{
	if (config == nullptr)
		return;

	osal_free(config->name);
	osal_free(config->hsm_provider);
	osal_free(config->token_label);
	osal_secure_free(config->pin);
	osal_free(config->key_label);
	osal_free(config->ca_cert);
	osal_free(config->ocsp_signer_hsm_provider);
	osal_free(config->ocsp_signer_token_label);
	osal_secure_free(config->ocsp_signer_pin);
	osal_free(config->ocsp_signer_key_label);
	osal_free(config->ocsp_signer_cert);
	osal_free(config->ocsp_signer_digest);
	osal_free(config->ocsp_responder_endpoint);
	memset(config, 0, sizeof *config);
}

void store_ca_config_list_free(store_ca_config_t *configs, size_t count)
{
	if (configs == nullptr)
		return;

	for (size_t i = 0; i < count; i++)
		store_ca_config_free(&configs[i]);
	osal_free(configs);
}

store_result_t store_crl_number_reserve(store_ca_id_t ca_id, uint64_t *number)
{
	sqlite3_stmt *stmt = nullptr;
	store_result_t result = STORE_ERR_DATABASE;
	sqlite3_int64 next_number = 0;
	sqlite3_int64 now;
	uint64_t reserved;
	bool found = false;
	bool ca_exists = false;
	int rc;

	if (number == nullptr) {
		LOGE("CRL number output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*number = 0;
	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;

	/*
	 * BEGIN IMMEDIATE takes the write lock before the read, so two
	 * processes cannot reserve the same number.
	 */
	if (!_store_exec(g_store, "BEGIN IMMEDIATE;"))
		return STORE_ERR_DATABASE;

	rc = sqlite3_prepare_v2(g_store,
				"SELECT next_number FROM crl_state"
				" WHERE ca_id = ?1",
				-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CRL number reservation");
		goto rollback;
	}
	sqlite3_bind_int64(stmt, 1, ca_id);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		found = true;
		next_number = sqlite3_column_int64(stmt, 0);
	} else if (rc != SQLITE_DONE) {
		_store_log_error("CRL number reservation");
		goto rollback;
	}
	sqlite3_finalize(stmt);
	stmt = nullptr;

	if (!found) {
		/* No state yet; reject an id that has no registered CA. */
		rc = sqlite3_prepare_v2(g_store,
					"SELECT 1 FROM ca WHERE id = ?1", -1,
					&stmt, nullptr);
		if (rc != SQLITE_OK) {
			_store_log_error("CRL number reservation");
			goto rollback;
		}
		sqlite3_bind_int64(stmt, 1, ca_id);
		rc = sqlite3_step(stmt);
		if (rc == SQLITE_ROW) {
			ca_exists = true;
		} else if (rc != SQLITE_DONE) {
			_store_log_error("CRL number reservation");
			goto rollback;
		}
		sqlite3_finalize(stmt);
		stmt = nullptr;
		if (!ca_exists) {
			result = STORE_ERR_NOT_FOUND;
			goto rollback;
		}
	}

	if (next_number < 0) {
		LOGE("Stored CRL number is invalid");
		goto rollback;
	}
	now = (sqlite3_int64) time(NULL);
	if (now < 0)
		now = 0;
	/* Time seeds the first value and keeps numbers increasing. */
	reserved = (uint64_t) next_number > (uint64_t) now
			   ? (uint64_t) next_number
			   : (uint64_t) now;
	if (reserved >= (uint64_t) INT64_MAX) {
		LOGE("CRL number space is exhausted");
		goto rollback;
	}

	rc = sqlite3_prepare_v2(
		g_store,
		"INSERT OR REPLACE INTO crl_state (ca_id, next_number)"
		" VALUES (?1, ?2)",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CRL number reservation");
		goto rollback;
	}
	sqlite3_bind_int64(stmt, 1, ca_id);
	sqlite3_bind_int64(stmt, 2, (sqlite3_int64) (reserved + 1));
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("CRL number reservation");
		goto rollback;
	}
	sqlite3_finalize(stmt);
	stmt = nullptr;

	if (!_store_exec(g_store, "COMMIT;")) {
		(void) _store_exec(g_store, "ROLLBACK;");
		return STORE_ERR_DATABASE;
	}
	*number = reserved;
	return STORE_OK;

rollback:
	sqlite3_finalize(stmt);
	(void) _store_exec(g_store, "ROLLBACK;");
	return result;
}

store_result_t store_ca_config_set_crl_number(const char *name, uint64_t number)
{
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	if (!_store_text_is_set(name)) {
		LOGE("CA name is not set");
		return STORE_ERR_ARGUMENT;
	}
	if (number > (uint64_t) INT64_MAX) {
		LOGE("CRL number is out of range");
		return STORE_ERR_ARGUMENT;
	}

	rc = sqlite3_prepare_v2(
		g_store,
		"UPDATE ca_config SET crl_number = ?2 WHERE name = ?1", -1,
		&stmt, nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("CA CRL number update");
		return STORE_ERR_DATABASE;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(stmt, 2, (sqlite3_int64) number);
	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("CA CRL number update");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

store_result_t store_certificate_add(store_ca_id_t ca_id,
				     const store_certificate_t *certificate)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	if (certificate == nullptr) {
		LOGE("Certificate is not set");
		return STORE_ERR_ARGUMENT;
	}
	result = _store_validate_serial(certificate->serial,
					certificate->serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"INSERT INTO certificate_%lld (serial, not_after)"
		" VALUES (?1, ?2)",
		(sqlite3_int64) ca_id, "Certificate insert");
	if (result != STORE_OK)
		return result;

	rc = sqlite3_bind_blob(stmt, 1, certificate->serial,
			       (int) certificate->serial_length,
			       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK) {
		if (certificate->not_after != 0)
			rc = sqlite3_bind_int64(stmt, 2,
						certificate->not_after);
		else
			rc = sqlite3_bind_null(stmt, 2);
	}
	if (rc != SQLITE_OK) {
		_store_log_error("Certificate insert");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc == SQLITE_DONE)
		return STORE_OK;
	if (rc == SQLITE_CONSTRAINT)
		return STORE_ERR_DUPLICATE;
	_store_log_error("Certificate insert");
	return STORE_ERR_DATABASE;
}

store_result_t store_certificate_get(store_ca_id_t ca_id,
				     const unsigned char *serial,
				     size_t serial_length,
				     store_certificate_t *certificate)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (certificate == nullptr) {
		LOGE("Certificate output is not set");
		return STORE_ERR_ARGUMENT;
	}
	memset(certificate, 0, sizeof *certificate);

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_validate_serial(serial, serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"SELECT serial, not_after FROM certificate_%lld"
		" WHERE serial = ?1",
		(sqlite3_int64) ca_id, "Certificate lookup");
	if (result != STORE_OK)
		return result;

	sqlite3_bind_blob(stmt, 1, serial, (int) serial_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		const void *data = sqlite3_column_blob(stmt, 0);
		int length = sqlite3_column_bytes(stmt, 0);

		if (data == nullptr || length <= 0) {
			result = STORE_ERR_DATABASE;
		} else {
			certificate->serial = osal_malloc((size_t) length);
			if (certificate->serial == nullptr) {
				result = STORE_ERR_MEMORY;
			} else {
				memcpy(certificate->serial, data,
				       (size_t) length);
				certificate->serial_length = (size_t) length;
				certificate->not_after =
					sqlite3_column_type(stmt, 1)
							== SQLITE_NULL
						? 0
						: sqlite3_column_int64(stmt, 1);
				result = STORE_OK;
			}
		}
	} else if (rc == SQLITE_DONE) {
		result = STORE_ERR_NOT_FOUND;
	} else {
		_store_log_error("Certificate lookup");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result == STORE_ERR_MEMORY || result == STORE_ERR_DATABASE)
		store_certificate_free(certificate);
	return result;
}

store_result_t store_certificate_exists(store_ca_id_t ca_id,
					const unsigned char *serial,
					size_t serial_length)
{
	store_result_t result;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_validate_serial(serial, serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	return _store_certificate_exists((sqlite3_int64) ca_id, serial,
					 serial_length);
}

store_result_t store_certificate_list(store_ca_id_t ca_id, int64_t limit,
				      store_certificate_t **certificates,
				      size_t *count)
{
	store_certificate_t *items = nullptr;
	size_t capacity = 0;
	size_t used = 0;
	sqlite3_stmt *stmt = nullptr;
	store_result_t result;
	int rc;

	if (certificates == nullptr || count == nullptr) {
		LOGE("Certificate list output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*certificates = nullptr;
	*count = 0;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		limit > 0
			? "SELECT serial, not_after FROM certificate_%lld"
			  " ORDER BY not_after DESC, serial DESC LIMIT ?1"
			: "SELECT serial, not_after FROM certificate_%lld"
			  " ORDER BY not_after DESC, serial DESC",
		(sqlite3_int64) ca_id, "Certificate list");
	if (result != STORE_OK)
		return result;
	if (limit > 0
	    && sqlite3_bind_int64(stmt, 1, limit) != SQLITE_OK) {
		_store_log_error("Certificate list");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	result = STORE_OK;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		store_certificate_t *record;

		if (!_store_reserve((void **) &items, &capacity, used + 1,
				    sizeof *items)) {
			result = STORE_ERR_MEMORY;
			break;
		}

		record = &items[used];
		memset(record, 0, sizeof *record);
		result = _store_copy_blob(stmt, 0, &record->serial,
					  &record->serial_length);
		if (result != STORE_OK)
			break;
		record->not_after =
			sqlite3_column_type(stmt, 1) == SQLITE_NULL
				? 0
				: sqlite3_column_int64(stmt, 1);
		used++;
	}
	if (rc != SQLITE_DONE && result == STORE_OK) {
		_store_log_error("Certificate list");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result != STORE_OK) {
		store_certificate_list_free(items, used);
		return result;
	}

	*certificates = items;
	*count = used;
	return STORE_OK;
}

store_result_t store_certificate_update(store_ca_id_t ca_id,
					const store_certificate_t *certificate)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	if (certificate == nullptr) {
		LOGE("Certificate is not set");
		return STORE_ERR_ARGUMENT;
	}
	result = _store_validate_serial(certificate->serial,
					certificate->serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"UPDATE certificate_%lld SET not_after = ?2"
		" WHERE serial = ?1",
		(sqlite3_int64) ca_id, "Certificate update");
	if (result != STORE_OK)
		return result;

	sqlite3_bind_blob(stmt, 1, certificate->serial,
			  (int) certificate->serial_length, SQLITE_TRANSIENT);
	if (certificate->not_after != 0)
		sqlite3_bind_int64(stmt, 2, certificate->not_after);
	else
		sqlite3_bind_null(stmt, 2);

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("Certificate update");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

store_result_t store_certificate_delete(store_ca_id_t ca_id,
					const unsigned char *serial,
					size_t serial_length)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_validate_serial(serial, serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"DELETE FROM certificate_%lld WHERE serial = ?1",
		(sqlite3_int64) ca_id, "Certificate delete");
	if (result != STORE_OK)
		return result;

	sqlite3_bind_blob(stmt, 1, serial, (int) serial_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc == SQLITE_CONSTRAINT)
		return STORE_ERR_CONFLICT;
	if (rc != SQLITE_DONE) {
		_store_log_error("Certificate delete");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

void store_certificate_free(store_certificate_t *certificate)
{
	if (certificate == nullptr)
		return;

	osal_free(certificate->serial);
	certificate->serial = nullptr;
	certificate->serial_length = 0;
	certificate->not_after = 0;
}

void store_certificate_list_free(store_certificate_t *certificates,
				 size_t count)
{
	if (certificates == nullptr)
		return;

	for (size_t i = 0; i < count; i++)
		osal_free(certificates[i].serial);
	osal_free(certificates);
}

store_result_t store_revocation_add(store_ca_id_t ca_id,
				    const store_revocation_t *revocation)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	if (revocation == nullptr) {
		LOGE("Revocation is not set");
		return STORE_ERR_ARGUMENT;
	}
	result = _store_validate_serial(revocation->serial,
					revocation->serial_length);
	if (result != STORE_OK)
		return result;
	result = _store_validate_revoked_at(revocation->revoked_at);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_certificate_exists((sqlite3_int64) ca_id,
					   revocation->serial,
					   revocation->serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"INSERT INTO revocation_%lld"
		" (serial, revoked_at, reason) VALUES (?1, ?2, ?3)",
		(sqlite3_int64) ca_id, "Revocation insert");
	if (result != STORE_OK)
		return result;

	rc = sqlite3_bind_blob(stmt, 1, revocation->serial,
			       (int) revocation->serial_length,
			       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_int64(stmt, 2, revocation->revoked_at);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_int(stmt, 3, revocation->reason);
	if (rc != SQLITE_OK) {
		_store_log_error("Revocation insert");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc == SQLITE_DONE)
		return STORE_OK;
	if (rc == SQLITE_CONSTRAINT)
		return STORE_ERR_DUPLICATE;
	_store_log_error("Revocation insert");
	return STORE_ERR_DATABASE;
}

store_result_t store_revocation_get(store_ca_id_t ca_id,
				    const unsigned char *serial,
				    size_t serial_length,
				    store_revocation_t *revocation)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (revocation == nullptr) {
		LOGE("Revocation output is not set");
		return STORE_ERR_ARGUMENT;
	}
	memset(revocation, 0, sizeof *revocation);

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_validate_serial(serial, serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"SELECT serial, revoked_at, reason FROM revocation_%lld"
		" WHERE serial = ?1",
		(sqlite3_int64) ca_id, "Revocation lookup");
	if (result != STORE_OK)
		return result;

	sqlite3_bind_blob(stmt, 1, serial, (int) serial_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		const void *data = sqlite3_column_blob(stmt, 0);
		int length = sqlite3_column_bytes(stmt, 0);

		if (data == nullptr || length <= 0) {
			result = STORE_ERR_DATABASE;
		} else {
			revocation->serial = osal_malloc((size_t) length);
			if (revocation->serial == nullptr) {
				result = STORE_ERR_MEMORY;
			} else {
				memcpy(revocation->serial, data,
				       (size_t) length);
				revocation->serial_length = (size_t) length;
				revocation->revoked_at =
					sqlite3_column_int64(stmt, 1);
				revocation->reason =
					sqlite3_column_int(stmt, 2);
				result = STORE_OK;
			}
		}
	} else if (rc == SQLITE_DONE) {
		result = STORE_ERR_NOT_FOUND;
	} else {
		_store_log_error("Revocation lookup");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result == STORE_ERR_MEMORY || result == STORE_ERR_DATABASE)
		store_revocation_free(revocation);
	return result;
}

store_result_t store_revocation_list(store_ca_id_t ca_id, int64_t limit,
				     store_revocation_t **revocations,
				     size_t *count)
{
	store_revocation_t *items = nullptr;
	size_t capacity = 0;
	size_t used = 0;
	sqlite3_stmt *stmt = nullptr;
	store_result_t result;
	int rc;

	if (revocations == nullptr || count == nullptr) {
		LOGE("Revocation list output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*revocations = nullptr;
	*count = 0;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		limit > 0
			? "SELECT serial, revoked_at, reason FROM revocation_%lld"
			  " ORDER BY revoked_at DESC, serial DESC LIMIT ?1"
			: "SELECT serial, revoked_at, reason FROM revocation_%lld"
			  " ORDER BY revoked_at DESC, serial DESC",
		(sqlite3_int64) ca_id, "Revocation list");
	if (result != STORE_OK)
		return result;
	if (limit > 0
	    && sqlite3_bind_int64(stmt, 1, limit) != SQLITE_OK) {
		_store_log_error("Revocation list");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	result = STORE_OK;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		store_revocation_t *record;

		if (!_store_reserve((void **) &items, &capacity, used + 1,
				    sizeof *items)) {
			result = STORE_ERR_MEMORY;
			break;
		}

		record = &items[used];
		memset(record, 0, sizeof *record);
		result = _store_copy_blob(stmt, 0, &record->serial,
					  &record->serial_length);
		if (result != STORE_OK)
			break;
		record->revoked_at = sqlite3_column_int64(stmt, 1);
		record->reason = sqlite3_column_int(stmt, 2);
		used++;
	}
	if (rc != SQLITE_DONE && result == STORE_OK) {
		_store_log_error("Revocation list");
		result = STORE_ERR_DATABASE;
	}

	sqlite3_finalize(stmt);
	if (result != STORE_OK) {
		store_revocation_list_free(items, used);
		return result;
	}

	*revocations = items;
	*count = used;
	return STORE_OK;
}

store_result_t store_revocation_update(store_ca_id_t ca_id,
				       const store_revocation_t *revocation)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	if (revocation == nullptr) {
		LOGE("Revocation is not set");
		return STORE_ERR_ARGUMENT;
	}
	result = _store_validate_serial(revocation->serial,
					revocation->serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"UPDATE revocation_%lld SET revoked_at = ?2, reason = ?3"
		" WHERE serial = ?1",
		(sqlite3_int64) ca_id, "Revocation update");
	if (result != STORE_OK)
		return result;

	rc = sqlite3_bind_blob(stmt, 1, revocation->serial,
			       (int) revocation->serial_length,
			       SQLITE_TRANSIENT);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_int64(stmt, 2, revocation->revoked_at);
	if (rc == SQLITE_OK)
		rc = sqlite3_bind_int(stmt, 3, revocation->reason);
	if (rc != SQLITE_OK) {
		_store_log_error("Revocation update");
		sqlite3_finalize(stmt);
		return STORE_ERR_DATABASE;
	}

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("Revocation update");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

store_result_t store_revocation_delete(store_ca_id_t ca_id,
				       const unsigned char *serial,
				       size_t serial_length)
{
	store_result_t result;
	sqlite3_stmt *stmt = nullptr;
	int rc;

	if (!_store_is_open())
		return STORE_ERR_DATABASE;
	result = _store_validate_ca_id(ca_id);
	if (result != STORE_OK)
		return result;
	result = _store_validate_serial(serial, serial_length);
	if (result != STORE_OK)
		return result;

	result = _store_ca_id_lookup((sqlite3_int64) ca_id);
	if (result != STORE_OK)
		return result;

	result = _store_prepare_ca(
		&stmt,
		"DELETE FROM revocation_%lld WHERE serial = ?1",
		(sqlite3_int64) ca_id, "Revocation delete");
	if (result != STORE_OK)
		return result;

	sqlite3_bind_blob(stmt, 1, serial, (int) serial_length,
			  SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE) {
		_store_log_error("Revocation delete");
		return STORE_ERR_DATABASE;
	}
	return sqlite3_changes(g_store) == 0 ? STORE_ERR_NOT_FOUND : STORE_OK;
}

void store_revocation_free(store_revocation_t *revocation)
{
	if (revocation == nullptr)
		return;

	osal_free(revocation->serial);
	revocation->serial = nullptr;
	revocation->serial_length = 0;
	revocation->revoked_at = 0;
	revocation->reason = 0;
}

void store_revocation_list_free(store_revocation_t *revocations, size_t count)
{
	if (revocations == nullptr)
		return;

	for (size_t i = 0; i < count; i++)
		osal_free(revocations[i].serial);
	osal_free(revocations);
}

bool store_init(const char *path)
{
	sqlite3 *db = nullptr;
	int result;

	if (path == nullptr || path[0] == '\0') {
		LOGE("Store path is not set");
		return false;
	}
	if (g_store != nullptr) {
		LOGE("Store is already open");
		return false;
	}

	/*
	 * A new database stores token PINs in plaintext, so create it owner-only
	 * (mode 0600).  SQLite gives the WAL and shared-memory files the
	 * database file's mode.  An existing database keeps whatever mode the
	 * administrator chose.
	 */
	if (!osal_file_create_private(path)) {
		LOGE("Cannot create store \"%s\": %s", path, osal_file_error());
		return false;
	}

	result = sqlite3_open_v2(
		path, &db,
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
		nullptr);
	if (result != SQLITE_OK) {
		LOGE("Cannot open store \"%s\": %s", path,
		     db != nullptr ? sqlite3_errmsg(db) : sqlite3_errstr(result));
		sqlite3_close(db);
		return false;
	}

	sqlite3_busy_timeout(db, 5000);

	/*
	 * Foreign keys are per connection.  WAL lets readers proceed during
	 * a commit; synchronous=FULL keeps issuance and revocation durable.
	 */
	if (!_store_exec(db, "PRAGMA foreign_keys = ON;")
	    || !_store_exec_retry(db, "PRAGMA journal_mode = WAL;")
	    || !_store_exec(db, "PRAGMA synchronous = FULL;")
	    || !_store_prepare_schema(db)) {
		sqlite3_close_v2(db);
		return false;
	}

	g_store = db;
	LOGI("Opened store: %s", path);
	return true;
}

store_result_t store_data_version(uint64_t *version)
{
	sqlite3_stmt *stmt = nullptr;
	store_result_t result = STORE_ERR_DATABASE;
	int rc;

	if (version == nullptr) {
		LOGE("Store data version output is not set");
		return STORE_ERR_ARGUMENT;
	}
	*version = 0;
	if (!_store_is_open())
		return STORE_ERR_DATABASE;

	rc = sqlite3_prepare_v2(g_store, "PRAGMA data_version", -1, &stmt,
				nullptr);
	if (rc != SQLITE_OK) {
		_store_log_error("Store data version");
		return STORE_ERR_DATABASE;
	}

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		sqlite3_int64 value = sqlite3_column_int64(stmt, 0);

		if (value < 0) {
			LOGE("Store data version is invalid");
		} else {
			*version = (uint64_t) value;
			result = STORE_OK;
		}
	} else {
		_store_log_error("Store data version");
	}

	sqlite3_finalize(stmt);
	return result;
}

void store_fini(void)
{
	if (g_store == nullptr)
		return;

	sqlite3_close_v2(g_store);
	g_store = nullptr;
	LOGI("Store closed");
}
