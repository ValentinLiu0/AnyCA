/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#ifndef ANYCA_CA_H
#define ANYCA_CA_H

/**
 * @file ca.h
 * @brief Certificate Authority runtime object.
 *
 * A ca_t owns the CA settings, the parsed CA and OCSP signing certificates,
 * and the issuer data used to match OCSP CertIDs:
 *
 *     issuerNameHash = Hash(DER(X509_NAME))    -- certificate subject
 *     issuerKeyHash  = Hash(subjectPublicKey)  -- key bits, no tag/length
 *
 * Fill the settings fields, then call ca_load_certificate().
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Opaque OpenSSL type used by this interface.  Declaring it here instead of
 * including the OpenSSL headers keeps OpenSSL out of every consumer of ca.h;
 * only the implementation needs the complete type.
 */
typedef struct x509_st X509;

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum digest size held by a ca_hash_t (OpenSSL EVP_MAX_MD_SIZE). */
#define CA_MAX_HASH_SIZE 64

/** Owned byte string. */
typedef struct ca_blob {
	unsigned char *data;
	size_t length;
} ca_blob_t;

/** Digest value; only the first length bytes of data are meaningful. */
typedef struct ca_hash {
	unsigned char data[CA_MAX_HASH_SIZE];
	size_t length;
} ca_hash_t;

typedef struct ca {
	/*
	 * Settings copied from the configuration.  All strings are owned by
	 * the CA and released by ca_free().  The pin and ocsp_signer_pin
	 * fields must be allocated with osal_secure_malloc(); ca_free()
	 * wipes and releases them with osal_secure_free().
	 */
	char *name;
	char *hsm_provider;
	char *token_label;
	char *pin;
	char *key_label;
	/** DER-encoded CA certificate, owned by the CA. */
	ca_blob_t ca_cert_der;
	/** OCSP signer provider; NULL or empty means hsm_provider. */
	char *ocsp_signer_hsm_provider;
	char *ocsp_signer_token_label;
	char *ocsp_signer_pin;
	char *ocsp_signer_key_label;
	/** DER-encoded OCSP signing certificate, owned by the CA. */
	ca_blob_t ocsp_signer_cert_der;
	uint32_t crl_publish_period_min;
	uint32_t ocsp_update_period_min;
	/** Number of the most recently published CRL; 0 before the first. */
	uint64_t crl_number;
	char *ocsp_responder_endpoint;

	/** Parsed certificate from ca_cert_der. */
	X509 *certificate;

	/** Parsed OCSP signing certificate from ocsp_signer_cert_der. */
	X509 *ocsp_signer_certificate;

	/** DER encoding of the certificate subject name. */
	ca_blob_t issuer_name;

	/**
	 * subjectPublicKey BIT STRING contents (key bits without tag and
	 * length), i.e. the bytes that are hashed for issuerKeyHash.
	 */
	ca_blob_t issuer_key;

	/** Precomputed issuer hashes for SHA-1 and SHA-256. */
	ca_hash_t issuer_name_hash_sha1;
	ca_hash_t issuer_key_hash_sha1;
	ca_hash_t issuer_name_hash_sha256;
	ca_hash_t issuer_key_hash_sha256;

	/**
	 * SHA-256 of the DER SubjectPublicKeyInfo; the CA identity hash used
	 * by the store.  Unlike issuer_key_hash_sha256, it includes the key
	 * algorithm.
	 */
	ca_hash_t spki_hash_sha256;
} ca_t;

/**
 * Allocate a zero-initialized CA.  Fill the settings, then call
 * ca_load_certificate(); release with ca_free().
 *
 * @return the new CA, or NULL when allocation fails.
 */
ca_t *ca_new(void);

/** Tell whether a name is safe as one file or directory component: non-empty,
 *  without '/', '\\', ':', control characters, and not "." or "..". */
bool ca_name_is_valid(const char *name);

/** Tell whether a value is usable as an OCSP responder endpoint (the
 *  <endpoint> in /ocsp/<endpoint>): non-empty, printable, and without '/',
 *  '?' or '#'. */
bool ca_ocsp_responder_endpoint_is_valid(const char *endpoint);

/**
 * Parse the DER certificates held in ca->ca_cert_der and
 * ca->ocsp_signer_cert_der.
 *
 * The CA certificate must be a CA certificate (X509_check_ca()) and must be
 * valid at the current time.  An optional OCSP signing certificate must be
 * accepted by ca_ocsp_signer_authorized().
 * On success the issuer name/key data and hashes used by OCSP CertIDs are
 * computed.  On failure the previous certificate state is left unchanged.
 *
 * @return true on success; false on a missing or invalid certificate, an
 *         unauthorized signer or a hash failure.
 */
bool ca_load_certificate(ca_t *ca);

/** Release a CA and everything it owns.  Passing NULL is a no-op. */
void ca_free(ca_t *ca);

/** Read a DER-encoded X.509 certificate from path; release it with
 *  ca_certificate_free(). */
X509 *ca_certificate_load(const char *path);

/**
 * Decode one DER-encoded X.509 certificate from memory.
 *
 * The buffer must contain exactly one certificate.  Release the result with
 * ca_certificate_free().
 */
X509 *ca_certificate_load_der(const unsigned char *der,
					    size_t length);

/** Release a certificate returned by ca_certificate_load() or
 *  ca_certificate_load_der(). */
void ca_certificate_free(X509 *certificate);

/**
 * Copy the certificate serialNumber as canonical big-endian bytes: the DER
 * INTEGER value without tag, length or sign padding; zero is one 0x00 byte.
 * Release the buffer with osal_free().
 */
bool ca_certificate_serial(const X509 *certificate,
					 unsigned char **serial,
					 size_t *serial_length);

/** Read the certificate notAfter as Unix time. */
bool ca_certificate_not_after(const X509 *certificate,
					    int64_t *not_after);

/**
 * Tell whether this CA issued certificate: the issuer name must match the CA
 * subject and the CA public key must verify the signature.
 */
bool ca_issued_certificate(const ca_t *ca, X509 *certificate);

/**
 * Tell whether an OCSP CertID identifies this CA's issuer.
 *
 * Both the issuer name hash and the issuer key hash must match the CA
 * certificate, because different CAs may share a name.  SHA-1 and SHA-256 use
 * precomputed values; other digests are computed on demand.
 *
 * @param hash_nid OpenSSL NID of the CertID digest.
 */
bool ca_issuer_matches(const ca_t *ca, int hash_nid,
				     const unsigned char *name_hash,
				     size_t name_hash_length,
				     const unsigned char *key_hash,
				     size_t key_hash_length);

/**
 * Tell whether the configured OCSP signing certificate may sign for this CA.
 *
 * Per RFC 6960 section 4.2.2.2 the signer must be the CA certificate itself
 * or a directly issued certificate with id-kp-OCSPSigning in its extended key
 * usage, and must be within its validity period.
 */
bool ca_ocsp_signer_authorized(const ca_t *ca);

#ifdef __cplusplus
}
#endif

#endif // ANYCA_CA_H
