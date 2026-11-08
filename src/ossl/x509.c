/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <anyca/osal/memory.h>

#include <anyca/ossl/asn1.h>
#include <anyca/ossl/der.h>
#include <anyca/ossl/digest.h>
#include <anyca/ossl/x509.h>

X509 *ossl_x509_load_der_file(const char *path)
{
	BIO *bio;
	X509 *certificate;

	if (path == nullptr)
		return nullptr;

	bio = BIO_new_file(path, "rb");
	if (bio == nullptr)
		return nullptr;

	certificate = d2i_X509_bio(bio, nullptr);
	BIO_free(bio);
	return certificate;
}

X509 *ossl_x509_load_der(const unsigned char *der, size_t length)
{
	void *value = nullptr;

	if (!ossl_der_decode_item(ASN1_ITEM_rptr(X509), der, length, &value))
		return nullptr;
	return value;
}

X509_CRL *ossl_x509_crl_load_der(const unsigned char *der, size_t length)
{
	void *value = nullptr;

	if (!ossl_der_decode_item(ASN1_ITEM_rptr(X509_CRL), der, length,
				  &value))
		return nullptr;
	return value;
}

X509_REQ *ossl_x509_req_load_file(const char *path)
{
	BIO *bio;
	X509_REQ *request;

	if (path == nullptr)
		return nullptr;

	bio = BIO_new_file(path, "rb");
	if (bio == nullptr)
		return nullptr;
	request = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (request != nullptr)
		return request;

	ERR_clear_error();
	bio = BIO_new_file(path, "rb");
	if (bio == nullptr)
		return nullptr;
	request = d2i_X509_REQ_bio(bio, nullptr);
	BIO_free(bio);
	return request;
}

/* Return an owned reference to a certificate's public key. */
static EVP_PKEY *_ossl_x509_certificate_pkey(X509 *certificate)
{
	EVP_PKEY *key = X509_get0_pubkey(certificate);

	if (key == nullptr || EVP_PKEY_up_ref(key) != 1)
		return nullptr;
	return key;
}

/* Return an owned reference to a certificate request's public key. */
static EVP_PKEY *_ossl_x509_request_pkey(X509_REQ *request)
{
	EVP_PKEY *key = X509_REQ_get0_pubkey(request);

	if (key == nullptr || EVP_PKEY_up_ref(key) != 1)
		return nullptr;
	return key;
}

/* Extract a public key from a DER certificate, request or SubjectPublicKeyInfo. */
static EVP_PKEY *_ossl_x509_public_key_der(const unsigned char *data,
					   size_t length)
{
	X509_PUBKEY *subject_public_key = nullptr;
	EVP_PKEY *key = nullptr;
	X509_REQ *request = nullptr;
	X509 *certificate;
	void *value = nullptr;

	certificate = ossl_x509_load_der(data, length);
	if (certificate != nullptr) {
		key = _ossl_x509_certificate_pkey(certificate);
		X509_free(certificate);
		if (key != nullptr)
			return key;
	}
	ERR_clear_error();

	if (ossl_der_decode_item(ASN1_ITEM_rptr(X509_REQ), data, length,
				 &value)) {
		request = value;
		key = _ossl_x509_request_pkey(request);
		X509_REQ_free(request);
		if (key != nullptr)
			return key;
	}
	ERR_clear_error();

	if (ossl_x509_pubkey_decode(data, length, &subject_public_key)) {
		key = X509_PUBKEY_get(subject_public_key);
		X509_PUBKEY_free(subject_public_key);
	}
	ERR_clear_error();
	return key;
}

/* Extract a public key from a PEM certificate, request or public key. */
static EVP_PKEY *_ossl_x509_public_key_pem(const unsigned char *data,
					   size_t length)
{
	X509_REQ *request;
	EVP_PKEY *key = nullptr;
	X509 *certificate;
	BIO *bio;

	if (length > INT_MAX)
		return nullptr;

	bio = BIO_new_mem_buf(data, (int) length);
	if (bio != nullptr) {
		certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
		if (certificate != nullptr) {
			key = _ossl_x509_certificate_pkey(certificate);
			X509_free(certificate);
		}
		BIO_free(bio);
		if (key != nullptr)
			return key;
	}
	ERR_clear_error();

	bio = BIO_new_mem_buf(data, (int) length);
	if (bio != nullptr) {
		request = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
		if (request != nullptr) {
			key = _ossl_x509_request_pkey(request);
			X509_REQ_free(request);
		}
		BIO_free(bio);
		if (key != nullptr)
			return key;
	}
	ERR_clear_error();

	bio = BIO_new_mem_buf(data, (int) length);
	if (bio != nullptr) {
		key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);
	}
	ERR_clear_error();
	return key;
}

EVP_PKEY *ossl_x509_load_public_key(const unsigned char *data, size_t length)
{
	EVP_PKEY *key;

	if (data == nullptr || length == 0)
		return nullptr;

	key = _ossl_x509_public_key_der(data, length);
	if (key == nullptr) {
		ERR_clear_error();
		key = _ossl_x509_public_key_pem(data, length);
	}
	return key;
}

bool ossl_x509_name_encode(const X509_NAME *name, ossl_der_t *der)
{
	return ossl_der_encode_item(ASN1_ITEM_rptr(X509_NAME), name, der);
}

bool ossl_x509_name_decode(const unsigned char *der, size_t length,
			   X509_NAME **name)
{
	void *value = nullptr;

	if (name == nullptr)
		return false;
	*name = nullptr;
	if (!ossl_der_decode_item(ASN1_ITEM_rptr(X509_NAME), der, length,
				  &value))
		return false;
	*name = value;
	return true;
}

bool ossl_x509_pubkey_encode(const X509_PUBKEY *public_key, ossl_der_t *der)
{
	return ossl_der_encode_item(ASN1_ITEM_rptr(X509_PUBKEY), public_key, der);
}

bool ossl_x509_pubkey_decode(const unsigned char *der, size_t length,
			     X509_PUBKEY **public_key)
{
	void *value = nullptr;

	if (public_key == nullptr)
		return false;
	*public_key = nullptr;
	if (!ossl_der_decode_item(ASN1_ITEM_rptr(X509_PUBKEY), der, length,
				  &value))
		return false;
	*public_key = value;
	return true;
}

bool ossl_x509_spki_encode(const EVP_PKEY *public_key, ossl_der_t *der)
{
	unsigned char *encoded;
	unsigned char *cursor;
	int length;

	if (der == nullptr)
		return false;
	der->data = nullptr;
	der->length = 0;

	if (public_key == nullptr)
		return false;

	length = i2d_PUBKEY(public_key, nullptr);
	if (length <= 0)
		return false;

	encoded = osal_malloc((size_t) length);
	if (encoded == nullptr)
		return false;

	cursor = encoded;
	if (i2d_PUBKEY(public_key, &cursor) != length) {
		osal_free(encoded);
		return false;
	}

	der->data = encoded;
	der->length = (size_t) length;
	return true;
}

X509_ALGOR *ossl_x509_signature_algorithm_new(int signature_nid)
{
	X509_ALGOR *algorithm;
	ASN1_OBJECT *object;
	int parameter_type = V_ASN1_UNDEF;
	int digest_nid;
	int key_nid;

	if (signature_nid == NID_undef)
		return nullptr;
	object = OBJ_nid2obj(signature_nid);
	if (object == nullptr)
		return nullptr;

	if (OBJ_find_sigid_algs(signature_nid, &digest_nid, &key_nid) == 1
	    && key_nid == EVP_PKEY_RSA)
		parameter_type = V_ASN1_NULL;

	algorithm = X509_ALGOR_new();
	if (algorithm == nullptr)
		return nullptr;
	if (X509_ALGOR_set0(algorithm, object, parameter_type, nullptr) != 1) {
		X509_ALGOR_free(algorithm);
		return nullptr;
	}
	return algorithm;
}

bool ossl_x509_public_key_bits(const X509 *certificate,
			       const unsigned char **bits, size_t *length)
{
	const ASN1_BIT_STRING *key;
	const unsigned char *data;
	int key_length;

	if (bits == nullptr || length == nullptr)
		return false;
	*bits = nullptr;
	*length = 0;
	if (certificate == nullptr)
		return false;

	key = X509_get0_pubkey_bitstr(certificate);
	if (key == nullptr)
		return false;

	data = ASN1_STRING_get0_data(key);
	key_length = ASN1_STRING_length(key);
	if (data == nullptr || key_length <= 0)
		return false;

	*bits = data;
	*length = (size_t) key_length;
	return true;
}

bool ossl_x509_serial(const X509 *certificate, unsigned char **serial,
		      size_t *serial_length)
{
	if (certificate == nullptr)
		return false;

	return ossl_asn1_integer_to_bytes(
		X509_get0_serialNumber(certificate), serial, serial_length,
		nullptr);
}

bool ossl_x509_not_after(const X509 *certificate, int64_t *not_after)
{
	if (certificate == nullptr)
		return false;

	return ossl_asn1_time_to_epoch(X509_get0_notAfter(certificate),
				       not_after);
}

bool ossl_x509_valid_now(const X509 *certificate)
{
	const ASN1_TIME *not_before;
	const ASN1_TIME *not_after;
	time_t now = time(nullptr);

	if (certificate == nullptr)
		return false;

	not_before = X509_get0_notBefore(certificate);
	not_after = X509_get0_notAfter(certificate);
	if (not_before == nullptr || not_after == nullptr)
		return false;

	return X509_cmp_time(not_before, &now) < 0
		&& X509_cmp_time(not_after, &now) > 0;
}

bool ossl_x509_has_eku(const X509 *certificate, int nid)
{
	EXTENDED_KEY_USAGE *usage;
	bool found = false;

	if (certificate == nullptr)
		return false;

	usage = X509_get_ext_d2i(certificate, NID_ext_key_usage, nullptr,
				 nullptr);
	if (usage == nullptr)
		return false;

	for (int i = 0; i < sk_ASN1_OBJECT_num(usage); i++) {
		if (OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, i)) == nid) {
			found = true;
			break;
		}
	}

	EXTENDED_KEY_USAGE_free(usage);
	return found;
}

/* Return the subjectPublicKey BIT STRING contents of a public key. */
static bool _ossl_x509_pubkey_bits(const X509_PUBKEY *public_key,
				   const unsigned char **bits, size_t *length)
{
	ASN1_OBJECT *algorithm;
	const unsigned char *key;
	X509_ALGOR *algor;
	int key_length;

	if (bits == nullptr || length == nullptr)
		return false;
	*bits = nullptr;
	*length = 0;
	if (public_key == nullptr)
		return false;

	if (X509_PUBKEY_get0_param(&algorithm, &key, &key_length, &algor,
				   public_key)
	    != 1)
		return false;
	if (key == nullptr || key_length <= 0)
		return false;

	*bits = key;
	*length = (size_t) key_length;
	return true;
}

/* Build the RFC 5280 key identifier octet string from public key bits. */
static ASN1_OCTET_STRING *_ossl_x509_key_identifier(
	const unsigned char *bits, size_t length)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	size_t digest_length = 0;
	ASN1_OCTET_STRING *identifier;

	if (!ossl_digest(EVP_sha1(), bits, length, digest, sizeof digest,
			 &digest_length))
		return nullptr;

	identifier = ASN1_OCTET_STRING_new();
	if (identifier == nullptr
	    || ASN1_OCTET_STRING_set(identifier, digest,
				     (int) digest_length)
		       != 1) {
		ASN1_OCTET_STRING_free(identifier);
		return nullptr;
	}
	return identifier;
}

X509_EXTENSION *ossl_x509_subject_key_identifier(
	const X509_PUBKEY *public_key)
{
	const unsigned char *bits;
	size_t length;
	ASN1_OCTET_STRING *identifier;
	X509_EXTENSION *extension;

	if (!_ossl_x509_pubkey_bits(public_key, &bits, &length))
		return nullptr;

	identifier = _ossl_x509_key_identifier(bits, length);
	if (identifier == nullptr)
		return nullptr;

	extension = X509V3_EXT_i2d(NID_subject_key_identifier, 0, identifier);
	ASN1_OCTET_STRING_free(identifier);
	return extension;
}

X509_EXTENSION *ossl_x509_authority_key_identifier(
	const X509 *issuer_certificate)
{
	AUTHORITY_KEYID *authority = nullptr;
	ASN1_OCTET_STRING *key_id = nullptr;
	X509_EXTENSION *extension = nullptr;
	const unsigned char *bits;
	size_t length;

	if (issuer_certificate == nullptr)
		return nullptr;

	key_id = X509_get_ext_d2i(issuer_certificate,
				  NID_subject_key_identifier, nullptr, nullptr);
	if (key_id == nullptr) {
		if (!ossl_x509_public_key_bits(issuer_certificate, &bits,
					       &length))
			return nullptr;
		key_id = _ossl_x509_key_identifier(bits, length);
		if (key_id == nullptr)
			return nullptr;
	}

	authority = AUTHORITY_KEYID_new();
	if (authority == nullptr)
		goto done;
	authority->keyid = key_id;
	key_id = nullptr;

	extension = X509V3_EXT_i2d(NID_authority_key_identifier, 0,
				   authority);

done:
	AUTHORITY_KEYID_free(authority);
	ASN1_OCTET_STRING_free(key_id);
	return extension;
}

X509_EXTENSION *ossl_x509_extension_new_der(const char *oid, bool critical,
					    const unsigned char *der,
					    size_t length)
{
	ASN1_OBJECT *object;
	ASN1_OCTET_STRING *value;
	X509_EXTENSION *extension;

	if (oid == nullptr || (der == nullptr && length != 0)
	    || length > INT_MAX)
		return nullptr;

	object = OBJ_txt2obj(oid, 0);
	if (object == nullptr)
		return nullptr;

	value = ASN1_OCTET_STRING_new();
	if (value == nullptr
	    || ASN1_OCTET_STRING_set(value, der, (int) length) != 1) {
		ASN1_OCTET_STRING_free(value);
		ASN1_OBJECT_free(object);
		return nullptr;
	}

	extension = X509_EXTENSION_create_by_OBJ(nullptr, object,
						 critical ? 1 : 0, value);
	ASN1_OCTET_STRING_free(value);
	ASN1_OBJECT_free(object);
	return extension;
}

X509_EXTENSION *ossl_x509_extension_new_by_nid(int nid, bool critical,
					       const void *value)
{
	if (value == nullptr)
		return nullptr;
	return X509V3_EXT_i2d(nid, critical ? 1 : 0, (void *) value);
}

bool ossl_x509_extension_push(STACK_OF(X509_EXTENSION) **extensions,
			      X509_EXTENSION *extension)
{
	if (extensions == nullptr || extension == nullptr) {
		X509_EXTENSION_free(extension);
		return false;
	}

	if (*extensions == nullptr) {
		*extensions = sk_X509_EXTENSION_new_null();
		if (*extensions == nullptr) {
			X509_EXTENSION_free(extension);
			return false;
		}
	}
	if (sk_X509_EXTENSION_push(*extensions, extension) <= 0) {
		X509_EXTENSION_free(extension);
		return false;
	}
	return true;
}

STACK_OF(X509_EXTENSION) *ossl_x509_extension_copy_stack(
	const STACK_OF(X509_EXTENSION) *extensions)
{
	STACK_OF(X509_EXTENSION) *copy;
	int count;

	if (extensions == nullptr)
		return nullptr;

	count = sk_X509_EXTENSION_num(extensions);
	if (count <= 0)
		return nullptr;

	copy = sk_X509_EXTENSION_new_null();
	if (copy == nullptr)
		return nullptr;

	for (int i = 0; i < count; i++) {
		X509_EXTENSION *extension = X509_EXTENSION_dup(
			sk_X509_EXTENSION_value(extensions, i));

		if (extension == nullptr
		    || sk_X509_EXTENSION_push(copy, extension) <= 0) {
			X509_EXTENSION_free(extension);
			sk_X509_EXTENSION_pop_free(copy, X509_EXTENSION_free);
			return nullptr;
		}
	}
	return copy;
}

char *ossl_x509_extension_oid(X509_EXTENSION *extension)
{
	ASN1_OBJECT *object;
	char *oid;
	int length;

	if (extension == nullptr)
		return nullptr;

	object = X509_EXTENSION_get_object(extension);
	if (object == nullptr)
		return nullptr;

	length = OBJ_obj2txt(nullptr, 0, object, 1);
	if (length <= 0)
		return nullptr;

	oid = osal_malloc((size_t) length + 1);
	if (oid == nullptr)
		return nullptr;
	if (OBJ_obj2txt(oid, length + 1, object, 1) != length) {
		osal_free(oid);
		return nullptr;
	}
	return oid;
}

bool ossl_x509_extension_data(X509_EXTENSION *extension, bool *critical,
			      const unsigned char **value,
			      size_t *value_length)
{
	ASN1_OCTET_STRING *data;
	const unsigned char *contents;
	int length;

	if (extension == nullptr || critical == nullptr || value == nullptr
	    || value_length == nullptr)
		return false;

	data = X509_EXTENSION_get_data(extension);
	if (data == nullptr)
		return false;

	contents = ASN1_STRING_get0_data(data);
	length = ASN1_STRING_length(data);
	if (length < 0 || (contents == nullptr && length != 0))
		return false;

	*critical = X509_EXTENSION_get_critical(extension) != 0;
	*value = contents;
	*value_length = (size_t) length;
	return true;
}

bool ossl_x509_issued_by(X509 *certificate, const X509 *issuer)
{
	EVP_PKEY *public_key;

	if (certificate == nullptr || issuer == nullptr)
		return false;

	if (X509_NAME_cmp(X509_get_issuer_name(certificate),
			  X509_get_subject_name(issuer)) != 0)
		return false;

	public_key = X509_get0_pubkey(issuer);
	if (public_key == nullptr)
		return false;

	return X509_verify(certificate, public_key) == 1;
}

bool ossl_x509_verify_self_signature(X509 *certificate)
{
	EVP_PKEY *public_key;

	if (certificate == nullptr)
		return false;

	public_key = X509_get0_pubkey(certificate);
	if (public_key == nullptr)
		return false;

	return X509_verify(certificate, public_key) == 1;
}

bool ossl_x509_crl_issued_by(X509_CRL *crl, const X509 *issuer)
{
	EVP_PKEY *public_key;

	if (crl == nullptr || issuer == nullptr)
		return false;

	if (X509_NAME_cmp(X509_CRL_get_issuer(crl),
			  X509_get_subject_name(issuer)) != 0)
		return false;

	public_key = X509_get0_pubkey(issuer);
	if (public_key == nullptr)
		return false;

	return X509_CRL_verify(crl, public_key) == 1;
}

bool ossl_x509_req_verify_self(X509_REQ *request)
{
	EVP_PKEY *public_key;

	if (request == nullptr)
		return false;

	public_key = X509_REQ_get0_pubkey(request);
	if (public_key == nullptr)
		return false;

	return X509_REQ_verify(request, public_key) == 1;
}

bool ossl_x509_verify_data(const X509 *certificate, const void *data,
			   size_t data_length,
			   const unsigned char *signature,
			   size_t signature_length)
{
	EVP_PKEY *public_key;
	EVP_MD_CTX *context;
	ossl_der_t encoded = { 0 };
	const unsigned char *verify_signature = signature;
	size_t verify_length = signature_length;
	bool ok = false;

	if (certificate == nullptr
	    || (data == nullptr && data_length != 0)
	    || signature == nullptr || signature_length == 0
	    || signature_length > INT_MAX)
		return false;

	public_key = X509_get0_pubkey(certificate);
	if (public_key == nullptr)
		return false;

	/*
	 * ML-DSA has no separate digest step: the provider signs and verifies
	 * the message directly.  EVP_DigestVerifyInit() with a digest does not
	 * apply, and EVP_PKEY_verify_init() alone does not select the message
	 * interface, so use the one-shot message API.
	 */
	if (EVP_PKEY_is_a(public_key, "ML-DSA-44")
	    || EVP_PKEY_is_a(public_key, "ML-DSA-65")
	    || EVP_PKEY_is_a(public_key, "ML-DSA-87")) {
		const char *type_name = EVP_PKEY_get0_type_name(public_key);
		EVP_SIGNATURE *algorithm =
			type_name != nullptr
				? EVP_SIGNATURE_fetch(nullptr, type_name, nullptr)
				: nullptr;
		EVP_PKEY_CTX *verify_context =
			EVP_PKEY_CTX_new_from_pkey(nullptr, public_key, nullptr);
		bool verified = verify_context != nullptr && algorithm != nullptr
				&& EVP_PKEY_verify_message_init(
					   verify_context, algorithm, nullptr)
					   == 1
				&& EVP_PKEY_verify(
					   verify_context, signature,
					   signature_length, data, data_length)
					   == 1;

		EVP_PKEY_CTX_free(verify_context);
		EVP_SIGNATURE_free(algorithm);
		return verified;
	}

	/*
	 * PKCS #11 returns ECDSA signatures as raw r || s, while OpenSSL
	 * expects a DER ECDSA-Sig-Value.  RSA signatures need no conversion.
	 */
	if (EVP_PKEY_get_base_id(public_key) == EVP_PKEY_EC) {
		if (!ossl_der_encode_ecdsa_signature(signature, signature_length,
						     &encoded))
			return false;
		verify_signature = encoded.data;
		verify_length = encoded.length;
	}

	context = EVP_MD_CTX_new();
	if (context == nullptr) {
		ossl_der_release(&encoded);
		return false;
	}

	if (EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr,
				 public_key) == 1
	    && EVP_DigestVerify(context, verify_signature, verify_length, data,
				data_length) == 1)
		ok = true;

	EVP_MD_CTX_free(context);
	ossl_der_release(&encoded);
	return ok;
}
