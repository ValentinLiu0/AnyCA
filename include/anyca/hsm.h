/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_HSM_H
#define ANYCA_HSM_H

/**
 * @file hsm.h
 * @brief PKCS #11 module, token and operation facade.
 *
 * A process may open several PKCS #11 modules, each with its own token
 * handles and per-token session pools.  PKCS #11 types stay private.
 * Operations use pooled sessions and may run concurrently on different
 * sessions; token handles may be shared between threads but must not be
 * closed while in use, and a module must not be closed while any of its token
 * handles are open.  Errors are thread-local.
 */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default number of operation sessions per token. */
#define HSM_DEFAULT_MAX_SESSIONS 16

/** Operation result.  HSM_OK is zero, failures are negative. */
typedef enum hsm_status {
	HSM_OK = 0,
	HSM_ERR_ARGUMENT = -1,
	HSM_ERR_NOT_INITIALIZED = -2,
	HSM_ERR_ALREADY_INITIALIZED = -3,
	HSM_ERR_MODULE_LOAD = -4,
	HSM_ERR_MODULE_INIT = -5,
	HSM_ERR_TOKEN_NOT_FOUND = -6,
	HSM_ERR_TOKEN_NOT_LOGGED_IN = -7,
	HSM_ERR_PIN_INCORRECT = -8,
	HSM_ERR_SESSION = -9,
	HSM_ERR_SESSION_LIMIT = -10,
	HSM_ERR_OBJECT_NOT_FOUND = -11,
	HSM_ERR_MECHANISM = -12,
	HSM_ERR_BUFFER_TOO_SMALL = -13,
	HSM_ERR_SIGN = -14,
	HSM_ERR_DIGEST = -15,
	HSM_ERR_VERIFY = -16,
	HSM_ERR_DEVICE = -17,
	HSM_ERR_MEMORY = -18,
	HSM_ERR_BUSY = -19,
	HSM_ERR_INTERNAL = -20,
	HSM_ERR_DUPLICATE = -21,
} hsm_status_t;

/** Digest algorithms supported by hsm_digest(). */
typedef enum hsm_digest_alg {
	HSM_DIGEST_SHA1 = 0,
	HSM_DIGEST_SHA224,
	HSM_DIGEST_SHA256,
	HSM_DIGEST_SHA384,
	HSM_DIGEST_SHA512,
} hsm_digest_alg_t;

/** ML-DSA parameter sets. */
typedef enum hsm_ml_dsa_parameter_set {
	HSM_ML_DSA_44 = 0,
	HSM_ML_DSA_65,
	HSM_ML_DSA_87,
} hsm_ml_dsa_parameter_set_t;

/**
 * Signature algorithms supported by hsm_sign() and hsm_verify().
 *
 * The token hashes as part of the mechanism.  If a token lacks the combined
 * ECDSA+hash mechanism (e.g. SoftHSM), the data is hashed first and signed
 * with CKM_ECDSA.  ECDSA signatures use raw PKCS #11 r || s, not ASN.1 DER.
 *
 * ML-DSA uses the pure mechanism with an empty context; the key's
 * CKA_PARAMETER_SET must match the requested parameter set, and the token must
 * implement PKCS #11 3.2.
 */
typedef enum hsm_sign_alg {
	HSM_SIGN_RSA_PKCS1_SHA1 = 0,
	HSM_SIGN_RSA_PKCS1_SHA224,
	HSM_SIGN_RSA_PKCS1_SHA256,
	HSM_SIGN_RSA_PKCS1_SHA384,
	HSM_SIGN_RSA_PKCS1_SHA512,
	HSM_SIGN_RSA_PSS_SHA256,
	HSM_SIGN_RSA_PSS_SHA384,
	HSM_SIGN_RSA_PSS_SHA512,
	HSM_SIGN_ECDSA_SHA1,
	HSM_SIGN_ECDSA_SHA224,
	HSM_SIGN_ECDSA_SHA256,
	HSM_SIGN_ECDSA_SHA384,
	HSM_SIGN_ECDSA_SHA512,
	HSM_SIGN_ML_DSA_44,
	HSM_SIGN_ML_DSA_65,
	HSM_SIGN_ML_DSA_87,
} hsm_sign_alg_t;

/** Module initialization parameters. */
struct hsm_config {
	/** Path of the PKCS #11 provider (required). */
	const char *module_path;
	/**
	 * Maximum operation sessions created per token.  Zero selects
	 * HSM_DEFAULT_MAX_SESSIONS.  A login session is kept separately.
	 */
	size_t max_sessions_per_token;
};

/** Information reported by the loaded PKCS #11 module. */
struct hsm_module_info {
	char manufacturer[33];
	char description[33];
	unsigned long cryptoki_version_major;
	unsigned long cryptoki_version_minor;
	unsigned long library_version_major;
	unsigned long library_version_minor;
};

/** Information about a token handle. */
struct hsm_token_info {
	char label[33];
	char manufacturer[33];
	char model[17];
	char serial[17];
	unsigned long flags;
	bool logged_in;
	/** Operation sessions currently created for this token. */
	size_t session_count;
};

/** Detailed thread-local error information. */
struct hsm_error {
	hsm_status_t status;
	/** Native CK_RV, or 0 when the failure was detected by this layer. */
	unsigned long pkcs11_code;
	/** Name of the failing API or PKCS #11 operation. */
	const char *operation;
	char message[512];
};

/** Opaque module instance. */
typedef struct hsm_module hsm_module_t;

/** Opaque token instance. */
typedef struct hsm_token hsm_token_t;

/**
 * Open a PKCS #11 module.
 *
 * Loads the provider, resolves C_GetFunctionList() and initializes it with
 * CKF_OS_LOCKING_OK, falling back to default arguments when the provider
 * rejects that.  Modules are independent, and different providers may use
 * different libraries.
 */
hsm_status_t
hsm_module_open(const struct hsm_config *config, hsm_module_t **module);

/**
 * Close a module and unload the provider.
 *
 * All token handles opened from this module must be closed first; otherwise
 * HSM_ERR_BUSY is returned and the module stays open.  NULL is a no-op.
 */
hsm_status_t hsm_module_close(hsm_module_t *module);

/** Whether the module is currently open. */
bool hsm_module_is_open(const hsm_module_t *module);

/** Copy information about an open module. */
hsm_status_t
hsm_module_get_info(const hsm_module_t *module, struct hsm_module_info *info);

/**
 * Open a token by PKCS #11 label from a module.
 *
 * The first initialized token with a matching label is used.  Opening the same
 * token again returns another reference to the shared context, so login state
 * and the session pool are shared.  Same-label tokens in different modules are
 * separate contexts.
 */
hsm_status_t hsm_token_open(hsm_module_t *module,
					  const char *token_label,
					  hsm_token_t **token);

/**
 * Release a token handle.  The token context is destroyed when the last
 * handle is closed.  The handle must not be used afterwards or closed while
 * another thread is using it.
 */
void hsm_token_close(hsm_token_t *token);

/** Copy current token information. */
hsm_status_t hsm_get_token_info(hsm_token_t *token,
					      struct hsm_token_info *info);

/**
 * Log in as CKU_USER on a dedicated session.  Login state is shared by all
 * sessions of the token; an existing login returns HSM_OK.
 */
hsm_status_t hsm_token_login(hsm_token_t *token,
					   const char *pin);

/**
 * Log out the token after running operations finish.  Logging out when not
 * logged in returns HSM_OK.
 */
hsm_status_t hsm_token_logout(hsm_token_t *token);

/**
 * Change the user PIN; the token must be logged in as CKU_USER.  The PINs are
 * not retained.
 */
hsm_status_t hsm_token_set_pin(hsm_token_t *token,
					     const char *old_pin,
					     const char *new_pin);

/** Public-key type supported by hsm_get_public_key(). */
typedef enum hsm_key_type {
	HSM_KEY_TYPE_RSA = 0,
	HSM_KEY_TYPE_EC,
	HSM_KEY_TYPE_ML_DSA,
} hsm_key_type_t;

/**
 * Public key material exported from a token.
 *
 * RSA keys use modulus and exponent; EC keys use ec_params (the DER-encoded
 * namedCurve OID) and ec_point (the uncompressed EC point without the PKCS
 * #11 OCTET STRING wrapper).  ML-DSA keys use ml_dsa_key, the raw public key
 * (CKA_VALUE) whose length is determined by ml_dsa_parameter_set.  Buffers
 * are owned by the structure and are released by hsm_public_key_free().
 */
typedef struct hsm_public_key {
	hsm_key_type_t type;
	unsigned char *modulus;
	size_t modulus_length;
	unsigned char *exponent;
	size_t exponent_length;
	unsigned char *ec_params;
	size_t ec_params_length;
	unsigned char *ec_point;
	size_t ec_point_length;
	unsigned char *ml_dsa_key;
	size_t ml_dsa_key_length;
	hsm_ml_dsa_parameter_set_t ml_dsa_parameter_set;
} hsm_public_key_t;

/**
 * Read the public key identified by CKA_LABEL.
 *
 * The token must contain a public key with the same label as the private key.
 * RSA, EC and ML-DSA keys are supported.  Buffers are osal_malloc()ed; release
 * them with hsm_public_key_free().
 */
hsm_status_t hsm_get_public_key(hsm_token_t *token,
					      const char *key_label,
					      hsm_public_key_t *key);

/** Release a public key returned by hsm_get_public_key().  NULL is a no-op. */
void hsm_public_key_free(hsm_public_key_t *key);

/** Class of a key object listed by hsm_list_key_objects(). */
typedef enum hsm_key_class {
	HSM_KEY_CLASS_PRIVATE = 0,
	HSM_KEY_CLASS_PUBLIC,
} hsm_key_class_t;

/**
 * Basic information about one key object in a token.
 *
 * The label and EC parameters are osal_malloc()ed and are released by
 * hsm_key_object_list_free().  Private and public key objects are reported
 * separately, even when they belong to the same key pair.
 */
typedef struct hsm_key_object {
	/** CKA_LABEL, NUL-terminated. */
	char *label;
	hsm_key_class_t key_class;
	hsm_key_type_t key_type;
	/** RSA modulus size in bits; zero when it is unavailable. */
	unsigned int rsa_bits;
	/** CKA_EC_PARAMS, a DER-encoded namedCurve OID; NULL for RSA and
	 *  ML-DSA keys. */
	unsigned char *ec_params;
	size_t ec_params_length;
	/** ML-DSA parameter set; meaningful only for HSM_KEY_TYPE_ML_DSA. */
	hsm_ml_dsa_parameter_set_t ml_dsa_parameter_set;
} hsm_key_object_t;

/**
 * List the RSA, EC and ML-DSA key objects in a token.
 *
 * Private and public objects are separate entries.  Empty labels and
 * unsupported key types are omitted.  The token need not be logged in, but
 * private-key objects are visible only when it is.
 */
hsm_status_t
hsm_list_key_objects(hsm_token_t *token, hsm_key_object_t **objects,
		     size_t *count);

/** Release a list returned by hsm_list_key_objects(). */
void hsm_key_object_list_free(hsm_key_object_t *objects, size_t count);

/** Named EC curves accepted by hsm_generate_ec_key_pair(). */
typedef enum hsm_ec_curve {
	HSM_EC_CURVE_P256 = 0,
	HSM_EC_CURVE_P384,
	HSM_EC_CURVE_P521,
} hsm_ec_curve_t;

/**
 * Generate an RSA key pair in the token.
 *
 * Both objects receive key_label.  The public key is verifiable, the private
 * key sensitive, non-extractable and usable for signing.  The token must be
 * logged in, and an existing public or private key with the same label is
 * rejected.
 *
 * @param bits key size in bits, at least 2048.
 */
hsm_status_t hsm_generate_rsa_key_pair(hsm_token_t *token,
						     unsigned int bits,
						     const char *key_label);

/**
 * Generate an EC key pair in the token.
 *
 * Both objects receive key_label and have the same attributes as
 * hsm_generate_rsa_key_pair().  The token must be logged in, and an existing
 * key with the same label is rejected.
 *
 * @param curve named curve for CKA_EC_PARAMS.
 */
hsm_status_t hsm_generate_ec_key_pair(hsm_token_t *token,
						    hsm_ec_curve_t curve,
						    const char *key_label);

/**
 * Generate an ML-DSA key pair in the token.
 *
 * Uses CKM_ML_DSA_KEY_PAIR_GEN with CKA_PARAMETER_SET set on the public key.
 * Both objects receive key_label and have the same protection attributes as
 * hsm_generate_rsa_key_pair().  The token must implement PKCS #11 3.2 and be
 * logged in; an existing key with the same label is rejected.
 */
hsm_status_t
hsm_generate_ml_dsa_key_pair(hsm_token_t *token,
			     hsm_ml_dsa_parameter_set_t parameter_set,
			     const char *key_label);

/**
 * Destroy the private and public key objects carrying key_label.
 *
 * The token must be logged in.  Deletion is idempotent: HSM_OK is returned
 * when no matching object exists.  If several objects of one class share the
 * label, only the first match is destroyed.
 */
hsm_status_t hsm_delete_key_pair(hsm_token_t *token,
					       const char *key_label);

/** Size in bytes of a digest, or 0 for an unknown algorithm. */
size_t hsm_get_digest_size(hsm_digest_alg_t algorithm);

/**
 * Hash data with the token.
 *
 * digest_capacity must be at least hsm_get_digest_size(algorithm).
 * HSM_ERR_BUFFER_TOO_SMALL sets *digest_len to the required size.
 */
hsm_status_t hsm_digest(hsm_token_t *token,
				      hsm_digest_alg_t algorithm,
				      const void *data, size_t data_len,
				      unsigned char *digest,
				      size_t digest_capacity,
				      size_t *digest_len);

/**
 * Sign data with the private key identified by CKA_LABEL.
 *
 * With signature == NULL, *signature_len receives the required size.
 * HSM_ERR_BUFFER_TOO_SMALL sets *signature_len to the required size.
 * Private-key operations normally require a logged-in token.
 *
 * A key with CKA_ALWAYS_AUTHENTICATE set additionally requires the user PIN
 * for every operation: use hsm_sign_with_pin().
 */
hsm_status_t hsm_sign(hsm_token_t *token,
				    hsm_sign_alg_t algorithm,
				    const char *key_label, const void *data,
				    size_t data_len,
				    unsigned char *signature,
				    size_t signature_capacity,
				    size_t *signature_len);

/**
 * Sign like hsm_sign(), supporting CKA_ALWAYS_AUTHENTICATE keys.
 *
 * After C_SignInit(), a key with CKA_ALWAYS_AUTHENTICATE set is authenticated
 * with C_Login(CKU_CONTEXT_SPECIFIC) using pin, as required by PKCS #11.  Keys
 * without the attribute ignore pin.  A key with the attribute rejects a NULL
 * or empty pin.
 */
hsm_status_t
hsm_sign_with_pin(hsm_token_t *token, hsm_sign_alg_t algorithm,
		  const char *key_label, const char *pin, const void *data,
		  size_t data_len, unsigned char *signature,
		  size_t signature_capacity, size_t *signature_len);

/**
 * Verify a signature with the public key identified by CKA_LABEL.
 *
 * HSM_ERR_VERIFY means the signature is invalid; other statuses mean the
 * operation could not be performed.
 */
hsm_status_t hsm_verify(hsm_token_t *token,
				      hsm_sign_alg_t algorithm,
				      const char *key_label,
				      const void *data, size_t data_len,
				      const unsigned char *signature,
				      size_t signature_len);

/** Fill buffer with bytes from the token's random number generator. */
hsm_status_t hsm_random(hsm_token_t *token, void *buffer,
				      size_t length);

/**
 * Detailed information about the last failure in the calling thread.
 * The returned pointer is valid until the next HSM call in that thread.
 */
const struct hsm_error *hsm_get_last_error(void);

/** Stable name of a status code, e.g. "HSM_ERR_PIN_INCORRECT". */
const char *hsm_status_to_string(hsm_status_t status);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_HSM_H
