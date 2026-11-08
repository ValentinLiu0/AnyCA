/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>

#include <anyca/ossl/der.h>
#include <anyca/ossl/digest.h>
#include <anyca/ossl/x509.h>

#include <anyca/ca.h>

static_assert(CA_MAX_HASH_SIZE >= EVP_MAX_MD_SIZE,
	      "CA_MAX_HASH_SIZE must cover every EVP digest");

static bool _ca_issuer_hash(const ca_t *ca, const EVP_MD *md,
			    ca_hash_t *name_hash, ca_hash_t *key_hash);

/* Copy the DER encoding of the certificate subject, i.e. the issuer name
 * that an OCSP CertID hashes. */
static bool _ca_copy_issuer_name(ca_t *ca)
{
	X509_NAME *name = X509_get_subject_name(ca->certificate);
	ossl_der_t der = { 0 };

	if (name == nullptr || !ossl_x509_name_encode(name, &der))
		return false;

	/* ossl_der_t and ca_blob_t both own osal_malloc()ed bytes. */
	ca->issuer_name.data = der.data;
	ca->issuer_name.length = der.length;
	return true;
}

/* Copy the subjectPublicKey BIT STRING contents.  OpenSSL exposes the key
 * bits without the tag and length, which is exactly what RFC 6960 hashes. */
static bool _ca_copy_issuer_key(ca_t *ca)
{
	const unsigned char *data;
	size_t length;

	if (!ossl_x509_public_key_bits(ca->certificate, &data, &length))
		return false;

	ca->issuer_key.data = osal_malloc(length);
	if (ca->issuer_key.data == nullptr)
		return false;
	memcpy(ca->issuer_key.data, data, length);
	ca->issuer_key.length = length;
	return true;
}

static bool _ca_digest(const ca_blob_t *blob, const EVP_MD *md,
		       ca_hash_t *hash)
{
	if (blob == nullptr || hash == nullptr)
		return false;

	return ossl_digest(md, blob->data, blob->length, hash->data,
			   sizeof hash->data, &hash->length);
}

/*
 * Hash the DER SubjectPublicKeyInfo (algorithm and key) for the store
 * identity.  This is not the OCSP issuerKeyHash, which hashes only the
 * subjectPublicKey BIT STRING contents.
 */
static bool _ca_hash_spki(const X509 *certificate, ca_hash_t *hash)
{
	X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(certificate);
	ossl_der_t der = { 0 };
	bool ok;

	if (pubkey == nullptr || hash == nullptr)
		return false;
	if (!ossl_x509_pubkey_encode(pubkey, &der))
		return false;

	ok = ossl_digest(EVP_sha256(), der.data, der.length, hash->data,
			 sizeof hash->data, &hash->length);
	ossl_der_release(&der);
	return ok;
}

/* Read one DER-encoded certificate from path. */
static X509 *_ca_read_certificate(const char *path, const char *what)
{
	X509 *certificate;

	if (path == nullptr)
		return nullptr;

	certificate = ossl_x509_load_der_file(path);
	if (certificate == nullptr)
		LOGE("Failed to load %s: %s", what, path);
	return certificate;
}

/* Decode one DER-encoded certificate held in memory. */
static X509 *_ca_parse_certificate(const ca_blob_t *blob, const char *what)
{
	X509 *certificate;

	if (blob == nullptr || blob->data == nullptr || blob->length == 0)
		return nullptr;

	certificate = ossl_x509_load_der(blob->data, blob->length);
	if (certificate == nullptr)
		LOGE("Failed to parse %s", what);
	return certificate;
}

ca_t *ca_new(void)
{
	return osal_calloc(1, sizeof(ca_t));
}

/* Reject NUL-adjacent control characters in names used in paths and URLs. */
static bool _ca_has_control_character(const char *text)
{
	for (const unsigned char *cursor = (const unsigned char *) text;
	     *cursor != '\0'; cursor++) {
		if (*cursor < 0x20 || *cursor == 0x7f)
			return true;
	}
	return false;
}

bool ca_name_is_valid(const char *name)
{
	return name != nullptr && name[0] != '\0'
		&& strchr(name, '/') == nullptr
		&& strchr(name, '\\') == nullptr
		&& strchr(name, ':') == nullptr
		&& strcmp(name, ".") != 0 && strcmp(name, "..") != 0
		&& !_ca_has_control_character(name);
}

bool ca_ocsp_responder_endpoint_is_valid(const char *endpoint)
{
	if (endpoint == nullptr || endpoint[0] == '\0')
		return false;
	if (strchr(endpoint, '/') != nullptr
	    || strchr(endpoint, '?') != nullptr
	    || strchr(endpoint, '#') != nullptr)
		return false;
	return !_ca_has_control_character(endpoint);
}

/*
 * RFC 5280 section 4.2.1.9: a CA certificate must carry basicConstraints and
 * the extension must be critical.  X509_check_ca() only reads the cA value.
 */
static bool _ca_basic_constraints_ok(X509 *certificate)
{
	int index = X509_get_ext_by_NID(certificate, NID_basic_constraints, -1);
	X509_EXTENSION *extension;

	if (index < 0)
		return false;
	extension = X509_get_ext(certificate, index);
	return extension != nullptr
		&& X509_EXTENSION_get_critical(extension) != 0;
}

/*
 * The CA key signs every CRL, so a KeyUsage extension must permit cRLSign.
 * A certificate without KeyUsage is unrestricted.
 */
static bool _ca_crl_sign_allowed(X509 *certificate)
{
	ASN1_BIT_STRING *usage;
	bool allowed;

	if (X509_get_ext_by_NID(certificate, NID_key_usage, -1) < 0)
		return true;

	usage = X509_get_ext_d2i(certificate, NID_key_usage, nullptr, nullptr);
	if (usage == nullptr)
		return false;

	/* keyUsage bit 6 is cRLSign. */
	allowed = ASN1_BIT_STRING_get_bit(usage, 6) != 0;
	ASN1_BIT_STRING_free(usage);
	return allowed;
}

/*
 * Verify an imported CA certificate.  A self-issued certificate is checked
 * against its own key; an intermediate's issuer certificate is not part of
 * the stored CA configuration, so its signature cannot be verified here.
 */
static bool _ca_verify_imported_signature(X509 *certificate)
{
	if (X509_NAME_cmp(X509_get_subject_name(certificate),
			  X509_get_issuer_name(certificate))
	    != 0) {
		LOGW("CA certificate is not self-issued; its issuer signature "
		     "cannot be verified without the issuer certificate");
		return true;
	}

	return ossl_x509_verify_self_signature(certificate);
}

bool ca_load_certificate(ca_t *ca)
{
	X509 *certificate;
	X509 *signer_certificate = nullptr;
	ca_t staged = { 0 };
	ca_hash_t name_sha1 = { 0 };
	ca_hash_t key_sha1 = { 0 };
	ca_hash_t name_sha256 = { 0 };
	ca_hash_t key_sha256 = { 0 };
	ca_hash_t spki_sha256 = { 0 };

	if (ca == nullptr || ca->ca_cert_der.length == 0) {
		LOGE("CA certificate is not set");
		return false;
	}

	certificate = _ca_parse_certificate(&ca->ca_cert_der,
					    "CA certificate");
	if (certificate == nullptr)
		return false;

	if (ca->ocsp_signer_cert_der.length != 0) {
		signer_certificate = _ca_parse_certificate(
			&ca->ocsp_signer_cert_der,
			"OCSP signing certificate");
		if (signer_certificate == nullptr) {
			X509_free(certificate);
			return false;
		}
	}

	if (X509_check_ca(certificate) <= 0) {
		LOGE("Certificate for CA %s is not a CA certificate",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}

	if (!_ca_basic_constraints_ok(certificate)) {
		LOGE("CA certificate for %s has no critical basicConstraints",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}

	if (!_ca_crl_sign_allowed(certificate)) {
		LOGE("CA certificate for %s does not permit CRL signing "
		     "(cRLSign)",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}

	if (!_ca_verify_imported_signature(certificate)) {
		LOGE("CA certificate for %s failed signature verification",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}

	if (!ossl_x509_valid_now(certificate)) {
		LOGE("Certificate for CA %s is not currently valid",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}

	/*
	 * Stage the new material and commit only after every step succeeds,
	 * so a failure keeps the previous certificate state.
	 */
	staged.certificate = certificate;
	staged.ocsp_signer_certificate = signer_certificate;
	if (signer_certificate != nullptr
	    && !ca_ocsp_signer_authorized(&staged)) {
		LOGE("OCSP signing certificate is not authorized for CA %s",
		     ca->name != nullptr ? ca->name : "<unnamed>");
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}
	if (!_ca_copy_issuer_name(&staged) || !_ca_copy_issuer_key(&staged)
	    || !_ca_hash_spki(certificate, &spki_sha256)
	    || !_ca_issuer_hash(&staged, EVP_sha1(), &name_sha1, &key_sha1)
	    || !_ca_issuer_hash(&staged, EVP_sha256(), &name_sha256,
			       &key_sha256)) {
		LOGE("Failed to initialise CA: %s",
			   ca->name != nullptr ? ca->name : "<unnamed>");
		osal_free(staged.issuer_name.data);
		osal_free(staged.issuer_key.data);
		X509_free(certificate);
		X509_free(signer_certificate);
		return false;
	}

	/* Commit. */
	X509_free(ca->certificate);
	X509_free(ca->ocsp_signer_certificate);
	osal_free(ca->issuer_name.data);
	osal_free(ca->issuer_key.data);

	ca->certificate = certificate;
	ca->ocsp_signer_certificate = signer_certificate;
	ca->issuer_name = staged.issuer_name;
	ca->issuer_key = staged.issuer_key;
	ca->issuer_name_hash_sha1 = name_sha1;
	ca->issuer_key_hash_sha1 = key_sha1;
	ca->issuer_name_hash_sha256 = name_sha256;
	ca->issuer_key_hash_sha256 = key_sha256;
	ca->spki_hash_sha256 = spki_sha256;

	LOGD("Loaded CA certificate: %s",
	     ca->name != nullptr ? ca->name : "<unnamed>");
	return true;
}

void ca_free(ca_t *ca)
{
	if (ca == nullptr)
		return;

	osal_free(ca->name);
	osal_free(ca->hsm_provider);
	osal_free(ca->token_label);
	osal_secure_free(ca->pin);
	osal_free(ca->key_label);
	osal_free(ca->ca_cert_der.data);
	osal_free(ca->ocsp_signer_hsm_provider);
	osal_free(ca->ocsp_signer_token_label);
	osal_secure_free(ca->ocsp_signer_pin);
	osal_free(ca->ocsp_signer_key_label);
	osal_free(ca->ocsp_signer_cert_der.data);
	osal_free(ca->ocsp_responder_endpoint);

	X509_free(ca->certificate);
	X509_free(ca->ocsp_signer_certificate);
	osal_free(ca->issuer_name.data);
	osal_free(ca->issuer_key.data);
	osal_free(ca);
}

X509 *ca_certificate_load(const char *path)
{
	if (path == nullptr) {
		LOGE("Certificate path is not set");
		return nullptr;
	}
	return _ca_read_certificate(path, "certificate");
}

X509 *ca_certificate_load_der(const unsigned char *der, size_t length)
{
	if (der == nullptr || length == 0) {
		LOGE("Certificate data is not set");
		return nullptr;
	}
	return ossl_x509_load_der(der, length);
}

void ca_certificate_free(X509 *certificate)
{
	X509_free(certificate);
}

bool ca_certificate_serial(const X509 *certificate, unsigned char **serial,
			   size_t *serial_length)
{
	return ossl_x509_serial(certificate, serial, serial_length);
}

bool ca_certificate_not_after(const X509 *certificate, int64_t *not_after)
{
	return ossl_x509_not_after(certificate, not_after);
}

bool ca_issued_certificate(const ca_t *ca, X509 *certificate)
{
	if (ca == nullptr || ca->certificate == nullptr
	    || certificate == nullptr)
		return false;

	return ossl_x509_issued_by(certificate, ca->certificate);
}

/*
 * Tell whether two certificates are byte-for-byte identical.  X509_cmp()
 * compares SHA-1 hashes of the DER encodings, so it can report two different
 * certificates as equal; the OCSP signer identity check needs an exact match.
 */
static bool _ca_same_certificate(const X509 *left, const X509 *right)
{
	unsigned char *left_der = nullptr;
	unsigned char *right_der = nullptr;
	int left_length;
	int right_length;
	bool same = false;

	if (left == nullptr || right == nullptr)
		return false;

	left_length = i2d_X509(left, &left_der);
	right_length = i2d_X509(right, &right_der);
	if (left_length > 0 && left_length == right_length)
		same = memcmp(left_der, right_der, (size_t) left_length) == 0;

	OPENSSL_free(left_der);
	OPENSSL_free(right_der);
	return same;
}

/*
 * RFC 6960 section 4.2.2.2: when the delegated signing certificate carries a
 * KeyUsage extension, it must assert digitalSignature.  A certificate without
 * the extension is unrestricted.
 */
static bool _ca_ocsp_signer_key_usage_ok(const X509 *certificate)
{
	ASN1_BIT_STRING *usage;
	bool ok;

	if (X509_get_ext_by_NID(certificate, NID_key_usage, -1) < 0)
		return true;

	usage = X509_get_ext_d2i(certificate, NID_key_usage, nullptr, nullptr);
	if (usage == nullptr)
		return false;

	ok = ASN1_BIT_STRING_get_bit(usage, 0) != 0;
	ASN1_BIT_STRING_free(usage);
	return ok;
}

bool ca_ocsp_signer_authorized(const ca_t *ca)
{
	if (ca == nullptr || ca->certificate == nullptr
	    || ca->ocsp_signer_certificate == nullptr)
		return false;

	if (!ossl_x509_valid_now(ca->ocsp_signer_certificate))
		return false;

	/* The CA may sign its own responses without a delegated EKU. */
	if (_ca_same_certificate(ca->certificate,
				 ca->ocsp_signer_certificate))
		return true;

	return ca_issued_certificate(ca, ca->ocsp_signer_certificate)
		&& ossl_x509_has_eku(ca->ocsp_signer_certificate,
				      NID_OCSP_sign)
		&& _ca_ocsp_signer_key_usage_ok(
			ca->ocsp_signer_certificate);
}

static bool _ca_issuer_hash(const ca_t *ca, const EVP_MD *md,
			    ca_hash_t *name_hash, ca_hash_t *key_hash)
{
	if (ca == nullptr || md == nullptr || name_hash == nullptr
	    || key_hash == nullptr)
		return false;

	memset(name_hash, 0, sizeof *name_hash);
	memset(key_hash, 0, sizeof *key_hash);

	return _ca_digest(&ca->issuer_name, md, name_hash)
		&& _ca_digest(&ca->issuer_key, md, key_hash);
}

bool ca_issuer_matches(const ca_t *ca, int hash_nid,
		       const unsigned char *name_hash, size_t name_hash_length,
		       const unsigned char *key_hash, size_t key_hash_length)
{
	const ca_hash_t *expected_name;
	const ca_hash_t *expected_key;
	ca_hash_t computed_name;
	ca_hash_t computed_key;
	const EVP_MD *md;
	bool name_matched;
	bool key_matched;

	if (ca == nullptr || name_hash == nullptr || key_hash == nullptr)
		return false;

	md = EVP_get_digestbynid(hash_nid);
	if (md == nullptr)
		return false;

	if (hash_nid == NID_sha1) {
		expected_name = &ca->issuer_name_hash_sha1;
		expected_key = &ca->issuer_key_hash_sha1;
	} else if (hash_nid == NID_sha256) {
		expected_name = &ca->issuer_name_hash_sha256;
		expected_key = &ca->issuer_key_hash_sha256;
	} else {
		if (!_ca_issuer_hash(ca, md, &computed_name, &computed_key))
			return false;
		expected_name = &computed_name;
		expected_key = &computed_key;
	}

	name_matched = name_hash_length == expected_name->length
		&& memcmp(name_hash, expected_name->data, name_hash_length) == 0;
	key_matched = key_hash_length == expected_key->length
		&& memcmp(key_hash, expected_key->data, key_hash_length) == 0;

	return name_matched && key_matched;
}
