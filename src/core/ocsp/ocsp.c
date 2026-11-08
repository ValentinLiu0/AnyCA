/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>

#include <anyca/ossl/asn1.h>
#include <anyca/ossl/der.h>
#include <anyca/ossl/x509.h>

#include <anyca/ocsp.h>

/* Parsed OCSPRequest. */
struct ocsp_request {
	OCSP_REQUEST *request;
	size_t count;
};

/* id-pkix-ocsp-pref-sig-algs (RFC 6960 section 4.4.7); OpenSSL has no NID. */
#define OCSP_PREF_SIG_ALGS_OID "1.3.6.1.5.5.7.48.1.8"

/* Upper bound on algorithms copied from one preferred-algorithms extension. */
#define OCSP_MAX_PREFERRED_ALGORITHMS 32

static ocsp_signature_algorithm_t _ocsp_nid_to_algorithm(int nid);

/*
 * Write data as lowercase hex plus a terminating NUL; write an empty string
 * when the buffer is too small.
 */
static void _ocsp_hex_encode(const unsigned char *data, size_t length,
			     char *output, size_t output_size)
{
	static const char digits[] = "0123456789abcdef";

	if (output_size == 0)
		return;
	if (data == nullptr || length > (output_size - 1) / 2) {
		output[0] = '\0';
		return;
	}

	for (size_t i = 0; i < length; i++) {
		output[2 * i] = digits[data[i] >> 4];
		output[2 * i + 1] = digits[data[i] & 0x0f];
	}
	output[2 * length] = '\0';
}

/* Write an ASN.1 OCTET STRING as lowercase hexadecimal. */
static void _ocsp_hex_asn1(const ASN1_OCTET_STRING *value, char *output,
			   size_t output_size)
{
	int length;

	if (output_size == 0)
		return;
	output[0] = '\0';
	if (value == nullptr)
		return;

	length = ASN1_STRING_length(value);
	if (length <= 0)
		return;
	_ocsp_hex_encode(ASN1_STRING_get0_data(value), (size_t) length,
			 output, output_size);
}

/* Log each query's CertID hash algorithm, issuer hashes and serial. */
static void _ocsp_log_queries(OCSP_REQUEST *request)
{
	int count = OCSP_request_onereq_count(request);

	LOGD("OCSP request contains %d query(ies)", count);
	for (int i = 0; i < count; i++) {
		OCSP_ONEREQ *one = OCSP_request_onereq_get0(request, i);
		OCSP_CERTID *cert_id =
			one != nullptr ? OCSP_onereq_get0_id(one) : nullptr;
		ASN1_OCTET_STRING *issuer_name_hash = nullptr;
		ASN1_OCTET_STRING *issuer_key_hash = nullptr;
		ASN1_OBJECT *hash_algorithm = nullptr;
		ASN1_INTEGER *serial_number = nullptr;
		char algorithm[64];
		char name_hash[2 * EVP_MAX_MD_SIZE + 1];
		char key_hash[2 * EVP_MAX_MD_SIZE + 1];
		char *serial;

		if (cert_id == nullptr
		    || OCSP_id_get0_info(&issuer_name_hash, &hash_algorithm,
					 &issuer_key_hash, &serial_number,
					 cert_id) != 1) {
			LOGW("Failed to read the CertID of OCSP query %d", i);
			continue;
		}

		algorithm[0] = '\0';
		if (hash_algorithm != nullptr)
			OBJ_obj2txt(algorithm, sizeof algorithm, hash_algorithm,
				    0);
		_ocsp_hex_asn1(issuer_name_hash, name_hash, sizeof name_hash);
		_ocsp_hex_asn1(issuer_key_hash, key_hash, sizeof key_hash);
		serial = ossl_asn1_integer_to_hex(serial_number);

		LOGD("OCSP query %d: hash algorithm: %s, issuer name "
			   "hash: %s, issuer key hash: %s, serial number: %s",
			   i, algorithm[0] != '\0' ? algorithm : "<unknown>",
			   name_hash[0] != '\0' ? name_hash : "<empty>",
			   key_hash[0] != '\0' ? key_hash : "<empty>",
			   serial != nullptr ? serial : "<null>");
		osal_free(serial);
	}
}

char *ocsp_request_to_string(const unsigned char *req, size_t size)
{
	const unsigned char *cursor = req;
	OCSP_REQUEST *request;
	BIO *bio;
	char *data = nullptr;
	char *text = nullptr;
	long length;

	if (req == nullptr || size == 0 || size > (size_t) LONG_MAX) {
		LOGE("Invalid OCSP request buffer");
		return nullptr;
	}

	request = d2i_OCSP_REQUEST(nullptr, &cursor, (long) size);
	if (request == nullptr) {
		LOGE("Failed to decode OCSP request");
		return nullptr;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == nullptr) {
		LOGE("Failed to allocate a memory BIO");
		OCSP_REQUEST_free(request);
		return nullptr;
	}

	if (OCSP_REQUEST_print(bio, request, 0) != 1) {
		LOGE("Failed to format OCSP request");
		goto done;
	}

	length = BIO_get_mem_data(bio, &data);
	if (length <= 0 || data == nullptr) {
		LOGE("Empty OCSP request description");
		goto done;
	}

	text = osal_malloc((size_t) length + 1);
	if (text == nullptr) {
		LOGE("Failed to allocate the OCSP request description");
		goto done;
	}
	memcpy(text, data, (size_t) length);
	text[(size_t) length] = '\0';

done:
	BIO_free(bio);
	OCSP_REQUEST_free(request);
	return text;
}

void ocsp_request_free(ocsp_request_t *request)
{
	if (request == nullptr)
		return;

	OCSP_REQUEST_free(request->request);
	osal_free(request);
}

/* Tell whether an extension carries id-pkix-ocsp-pref-sig-algs. */
static bool _ocsp_extension_is_pref_sig_algs(X509_EXTENSION *extension)
{
	char oid[64];

	if (extension == nullptr
	    || OBJ_obj2txt(oid, sizeof oid, X509_EXTENSION_get_object(extension),
			   1) <= 0)
		return false;
	return strcmp(oid, OCSP_PREF_SIG_ALGS_OID) == 0;
}

/* Validate the optional SMIMECapability after an AlgorithmIdentifier. */
static bool _ocsp_validate_optional_algorithm_field(const unsigned char *data,
						     long length)
{
	ossl_asn1_tlv_t field;
	const unsigned char *cursor = data;

	if (length == 0)
		return true;
	if (data == nullptr || length < 0)
		return false;

	return ossl_asn1_expect_tlv(&cursor, length, V_ASN1_SEQUENCE,
				    V_ASN1_UNIVERSAL, &field)
		&& field.content_length == length - (long) (cursor - data);
}

/*
 * Extract the signature algorithm OID from one PreferredSignatureAlgorithm:
 * SEQUENCE { sigIdentifier AlgorithmIdentifier, pubKeyAlgIdentifier OPTIONAL }.
 */
static bool _ocsp_pref_sig_algorithm_nid(const ASN1_STRING *encoded, int *nid)
{
	const unsigned char *outer;
	const unsigned char *cursor;
	const unsigned char *algorithm_cursor;
	ossl_asn1_tlv_t sequence;
	X509_ALGOR *algorithm;
	long outer_length;
	bool ok;

	if (encoded == nullptr || nid == nullptr)
		return false;

	outer = ASN1_STRING_get0_data(encoded);
	outer_length = ASN1_STRING_length(encoded);
	if (outer == nullptr || outer_length <= 0)
		return false;

	cursor = outer;
	if (!ossl_asn1_expect_tlv(&cursor, outer_length, V_ASN1_SEQUENCE,
				  V_ASN1_UNIVERSAL, &sequence))
		return false;
	if ((long) (cursor - outer) + sequence.content_length != outer_length)
		return false;

	algorithm_cursor = sequence.content;
	algorithm = d2i_X509_ALGOR(nullptr, &algorithm_cursor,
				   sequence.content_length);
	if (algorithm == nullptr)
		return false;

	*nid = algorithm->algorithm != nullptr
		? OBJ_obj2nid(algorithm->algorithm)
		: NID_undef;
	ok = _ocsp_validate_optional_algorithm_field(
		algorithm_cursor,
		sequence.content_length
			- (long) (algorithm_cursor - sequence.content));
	X509_ALGOR_free(algorithm);
	return ok;
}

/*
 * Parse a preferred signature algorithms extension into the supported
 * algorithms, in client preference order.  Returns false when the ASN.1
 * structure is malformed; algorithms is optional for validation only.
 */
static bool _ocsp_parse_pref_sig_algs(X509_EXTENSION *extension,
				      ocsp_signature_algorithm_t *algorithms,
				      size_t capacity, size_t *count)
{
	ASN1_SEQUENCE_ANY *sequence = nullptr;
	ASN1_OCTET_STRING *data;
	const unsigned char *cursor;
	const unsigned char *end;
	size_t found = 0;
	bool ok = false;

	if (count != nullptr)
		*count = 0;
	if (extension == nullptr)
		return false;

	data = X509_EXTENSION_get_data(extension);
	if (data == nullptr || ASN1_STRING_length(data) <= 0)
		return false;

	cursor = ASN1_STRING_get0_data(data);
	if (cursor == nullptr)
		return false;
	end = cursor + ASN1_STRING_length(data);
	sequence = d2i_ASN1_SEQUENCE_ANY(nullptr, &cursor,
					 ASN1_STRING_length(data));
	if (sequence == nullptr || cursor != end)
		goto done;

	for (int i = 0; i < sk_ASN1_TYPE_num(sequence); i++) {
		ASN1_TYPE *item = sk_ASN1_TYPE_value(sequence, i);
		ocsp_signature_algorithm_t parsed;
		int nid;

		if (item == nullptr || ASN1_TYPE_get(item) != V_ASN1_SEQUENCE)
			goto done;
		if (!_ocsp_pref_sig_algorithm_nid(item->value.sequence, &nid))
			goto done;

		parsed = _ocsp_nid_to_algorithm(nid);
		if (parsed != OCSP_SIGNATURE_DEFAULT && algorithms != nullptr
		    && found < capacity)
			algorithms[found++] = parsed;
	}

	if (count != nullptr)
		*count = found;
	ok = true;

done:
	if (sequence != nullptr)
		sk_ASN1_TYPE_pop_free(sequence, ASN1_TYPE_free);
	return ok;
}

/* Validate a nonce extension, including the RFC 8954 length limit. */
static bool _ocsp_validate_nonce_extension(X509_EXTENSION *extension)
{
	ASN1_OCTET_STRING *data;
	ASN1_OCTET_STRING *nonce;
	const unsigned char *cursor;
	const unsigned char *end;
	bool ok = false;
	int length;

	if (extension == nullptr)
		return false;

	data = X509_EXTENSION_get_data(extension);
	if (data == nullptr)
		return false;
	length = ASN1_STRING_length(data);
	cursor = ASN1_STRING_get0_data(data);
	if (length <= 0 || cursor == nullptr)
		return false;

	end = cursor + length;
	nonce = d2i_ASN1_OCTET_STRING(nullptr, &cursor, length);
	if (nonce == nullptr)
		return false;
	if (cursor == end && ASN1_STRING_length(nonce) >= 1
	    && ASN1_STRING_length(nonce) <= 32)
		ok = true;
	ASN1_OCTET_STRING_free(nonce);
	return ok;
}

/*
 * Reject unrecognized critical request extensions and invalid nonces.  The
 * nonce and preferred signature algorithms extensions are understood; all
 * other critical extensions are not.
 */
static bool _ocsp_validate_request_extensions(OCSP_REQUEST *request)
{
	int count = OCSP_REQUEST_get_ext_count(request);

	for (int i = 0; i < count; i++) {
		X509_EXTENSION *extension = OCSP_REQUEST_get_ext(request, i);

		if (extension == nullptr)
			return false;
		if (OBJ_obj2nid(X509_EXTENSION_get_object(extension))
		    == NID_id_pkix_OCSP_Nonce) {
			if (!_ocsp_validate_nonce_extension(extension)) {
				LOGW("OCSP request has an invalid nonce");
				return false;
			}
			continue;
		}
		if (!X509_EXTENSION_get_critical(extension))
			continue;
		if (_ocsp_extension_is_pref_sig_algs(extension)) {
			if (!_ocsp_parse_pref_sig_algs(extension, nullptr, 0,
						       nullptr)) {
				LOGW("OCSP request has an invalid preferred "
				     "signature algorithms extension");
				return false;
			}
			continue;
		}
		LOGW("OCSP request has an unrecognized critical extension");
		return false;
	}

	for (int i = 0; i < OCSP_request_onereq_count(request); i++) {
		OCSP_ONEREQ *one = OCSP_request_onereq_get0(request, i);
		int extension_count;

		if (one == nullptr)
			return false;
		extension_count = OCSP_ONEREQ_get_ext_count(one);
		for (int j = 0; j < extension_count; j++) {
			X509_EXTENSION *extension = OCSP_ONEREQ_get_ext(one, j);

			if (extension != nullptr
			    && X509_EXTENSION_get_critical(extension)) {
				LOGW("OCSP request has an unrecognized critical "
				     "single request extension");
				return false;
			}
		}
	}

	return true;
}

/* Reject a request whose TBSRequest version is present and not v1(0). */
static bool _ocsp_request_is_v1(const unsigned char *req, size_t size)
{
	const unsigned char *cursor = req;
	ossl_asn1_tlv_t outer;
	ossl_asn1_tlv_t tbs;
	ossl_asn1_tlv_t field;
	ossl_asn1_tlv_t version;

	if (size > (size_t) LONG_MAX)
		return false;
	if (!ossl_asn1_expect_tlv(&cursor, (long) size, V_ASN1_SEQUENCE,
				  V_ASN1_UNIVERSAL, &outer))
		return false;

	cursor = outer.content;
	if (!ossl_asn1_expect_tlv(&cursor, outer.content_length,
				  V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, &tbs))
		return false;

	cursor = tbs.content;
	if (!ossl_asn1_read_tlv(&cursor, tbs.content_length, &field))
		return false;

	/* Version is absent (DEFAULT v1) when the first field is not [0]. */
	if (field.xclass != V_ASN1_CONTEXT_SPECIFIC || field.tag != 0)
		return true;

	cursor = field.content;
	if (!ossl_asn1_expect_tlv(&cursor, field.content_length,
				  V_ASN1_INTEGER, V_ASN1_UNIVERSAL, &version))
		return false;

	/* DER INTEGER 0 is the single byte 0x00. */
	return version.content_length == 1 && version.content[0] == 0;
}

/* Validate every CertID and serial number before the responder uses them. */
static ocsp_result_t _ocsp_validate_queries(ocsp_request_t *request)
{
	for (size_t i = 0; i < request->count; i++) {
		ocsp_cert_id_t cert_id;
		unsigned char *serial = nullptr;
		size_t serial_length = 0;
		ocsp_result_t status;

		status = ocsp_request_cert_id(request, i, &cert_id);
		if (status != OCSP_OK) {
			LOGW("OCSP query %zu has an invalid CertID", i);
			return status == OCSP_ERR_MEMORY
				? OCSP_ERR_MEMORY
				: OCSP_ERR_REQUEST_DECODE;
		}

		status = ocsp_request_serial(request, i, &serial,
					     &serial_length);
		if (status != OCSP_OK) {
			osal_free(serial);
			LOGW("OCSP query %zu has an invalid serial number", i);
			return status == OCSP_ERR_MEMORY
				? OCSP_ERR_MEMORY
				: OCSP_ERR_REQUEST_DECODE;
		}
		osal_free(serial);
	}
	return OCSP_OK;
}

ocsp_result_t ocsp_request_parse(const unsigned char *req, size_t size,
				 ocsp_request_t **request)
{
	const unsigned char *cursor = req;
	ocsp_request_t *parsed;
	ocsp_result_t status;
	int count;

	if (request == nullptr)
		return OCSP_ERR_ARGUMENT;
	*request = nullptr;

	if (req == nullptr || size == 0 || size > (size_t) LONG_MAX) {
		LOGE("Invalid OCSP request buffer");
		return OCSP_ERR_ARGUMENT;
	}

	parsed = osal_calloc(1, sizeof *parsed);
	if (parsed == nullptr) {
		LOGE("Failed to allocate the OCSP request");
		return OCSP_ERR_MEMORY;
	}

	parsed->request = d2i_OCSP_REQUEST(nullptr, &cursor, (long) size);
	if (parsed->request == nullptr || cursor != req + size) {
		LOGE("Failed to decode OCSP request");
		ocsp_request_free(parsed);
		return OCSP_ERR_REQUEST_DECODE;
	}

	count = OCSP_request_onereq_count(parsed->request);
	if (count <= 0) {
		LOGE("OCSP request contains no queries");
		ocsp_request_free(parsed);
		return OCSP_ERR_REQUEST_DECODE;
	}
	parsed->count = (size_t) count;

	if (!_ocsp_request_is_v1(req, size)) {
		LOGE("Unsupported OCSP request version");
		ocsp_request_free(parsed);
		return OCSP_ERR_REQUEST_DECODE;
	}

	if (!_ocsp_validate_request_extensions(parsed->request)) {
		LOGE("Invalid OCSP request extensions");
		ocsp_request_free(parsed);
		return OCSP_ERR_REQUEST_DECODE;
	}

	status = _ocsp_validate_queries(parsed);
	if (status != OCSP_OK) {
		ocsp_request_free(parsed);
		return status;
	}

	_ocsp_log_queries(parsed->request);
	*request = parsed;
	return OCSP_OK;
}

ocsp_signature_algorithm_t
ocsp_request_preferred_signature(
	const ocsp_request_t *request,
	const ocsp_signature_algorithm_t *supported, size_t supported_count)
{
	ocsp_signature_algorithm_t algorithms[OCSP_MAX_PREFERRED_ALGORITHMS];
	size_t algorithm_count = 0;
	OCSP_REQUEST *raw;
	int extension_count;

	if (request == nullptr || request->request == nullptr
	    || supported == nullptr || supported_count == 0)
		return OCSP_SIGNATURE_DEFAULT;

	raw = request->request;
	extension_count = OCSP_REQUEST_get_ext_count(raw);
	for (int i = 0; i < extension_count; i++) {
		X509_EXTENSION *extension = OCSP_REQUEST_get_ext(raw, i);

		if (!_ocsp_extension_is_pref_sig_algs(extension))
			continue;
		if (!_ocsp_parse_pref_sig_algs(
			    extension, algorithms,
			    sizeof algorithms / sizeof algorithms[0],
			    &algorithm_count))
			return OCSP_SIGNATURE_DEFAULT;

		for (size_t j = 0; j < algorithm_count; j++) {
			for (size_t k = 0; k < supported_count; k++) {
				if (algorithms[j] == supported[k])
					return algorithms[j];
			}
		}
		return OCSP_SIGNATURE_DEFAULT;
	}

	return OCSP_SIGNATURE_DEFAULT;
}

size_t ocsp_request_query_count(const ocsp_request_t *request)
{
	return request != nullptr ? request->count : 0;
}

/* Copy one CertID issuer hash into a fixed output buffer. */
static bool _ocsp_copy_hash(const ASN1_OCTET_STRING *value,
			    unsigned char *output, size_t *output_length)
{
	int length;

	if (value == nullptr)
		return false;
	length = ASN1_STRING_length(value);
	if (length <= 0 || (size_t) length > OCSP_MAX_HASH_SIZE)
		return false;

	memcpy(output, ASN1_STRING_get0_data(value), (size_t) length);
	*output_length = (size_t) length;
	return true;
}

ocsp_result_t ocsp_request_cert_id(const ocsp_request_t *request, size_t index,
				   ocsp_cert_id_t *cert_id)
{
	OCSP_ONEREQ *one;
	OCSP_CERTID *id;
	ASN1_OCTET_STRING *name_hash = nullptr;
	ASN1_OCTET_STRING *key_hash = nullptr;
	ASN1_OBJECT *hash_algorithm = nullptr;
	ASN1_INTEGER *serial_number = nullptr;

	if (cert_id == nullptr) {
		LOGE("OCSP CertID output is not set");
		return OCSP_ERR_ARGUMENT;
	}
	memset(cert_id, 0, sizeof *cert_id);

	if (request == nullptr || request->request == nullptr
	    || index >= request->count)
		return OCSP_ERR_ARGUMENT;

	one = OCSP_request_onereq_get0(request->request, (int) index);
	id = one != nullptr ? OCSP_onereq_get0_id(one) : nullptr;
	if (id == nullptr
	    || OCSP_id_get0_info(&name_hash, &hash_algorithm, &key_hash,
				 &serial_number, id) != 1)
		return OCSP_ERR_REQUEST_DECODE;

	cert_id->hash_nid = hash_algorithm != nullptr
		? OBJ_obj2nid(hash_algorithm)
		: NID_undef;
	if (!_ocsp_copy_hash(name_hash, cert_id->issuer_name_hash,
			     &cert_id->issuer_name_hash_length))
		return OCSP_ERR_REQUEST_DECODE;

	/*
	 * certutil with an explicit responder URL sends issuerNameHash only.
	 * Leave issuer_key_hash_length at 0 and let the caller decide.
	 */
	if (key_hash != nullptr && ASN1_STRING_length(key_hash) > 0
	    && !_ocsp_copy_hash(key_hash, cert_id->issuer_key_hash,
				&cert_id->issuer_key_hash_length))
		return OCSP_ERR_REQUEST_DECODE;

	return OCSP_OK;
}

ocsp_result_t ocsp_request_serial(const ocsp_request_t *request, size_t index,
				  unsigned char **serial, size_t *serial_length)
{
	OCSP_ONEREQ *one;
	OCSP_CERTID *cert_id;
	ASN1_OCTET_STRING *name_hash = nullptr;
	ASN1_OCTET_STRING *key_hash = nullptr;
	ASN1_OBJECT *hash_algorithm = nullptr;
	ASN1_INTEGER *serial_number = nullptr;
	bool negative = false;

	if (serial == nullptr || serial_length == nullptr) {
		LOGE("Invalid OCSP serial arguments");
		return OCSP_ERR_ARGUMENT;
	}
	*serial = nullptr;
	*serial_length = 0;

	if (request == nullptr || request->request == nullptr
	    || index >= request->count)
		return OCSP_ERR_ARGUMENT;

	one = OCSP_request_onereq_get0(request->request, (int) index);
	cert_id = one != nullptr ? OCSP_onereq_get0_id(one) : nullptr;
	if (cert_id == nullptr
	    || OCSP_id_get0_info(&name_hash, &hash_algorithm, &key_hash,
				 &serial_number, cert_id) != 1
	    || serial_number == nullptr)
		return OCSP_ERR_REQUEST_DECODE;

	if (!ossl_asn1_integer_to_bytes(serial_number, serial, serial_length,
					&negative)) {
		if (negative) {
			LOGW("OCSP query %zu has a negative serial number",
			     index);
			return OCSP_ERR_REQUEST_DECODE;
		}
		return OCSP_ERR_MEMORY;
	}

	return OCSP_OK;
}

ocsp_result_t ocsp_get_signer_type(const X509 *certificate,
				   ocsp_signer_type_t *type)
{
	EVP_PKEY *key;
	int base_id;

	if (certificate == nullptr || type == nullptr)
		return OCSP_ERR_ARGUMENT;

	key = X509_get0_pubkey(certificate);
	if (key == nullptr)
		return OCSP_ERR_ARGUMENT;

	/*
	 * Provider-backed ML-DSA keys have no legacy base id
	 * (EVP_PKEY_base_id() returns 0), so identify them by name first.
	 */
	if (EVP_PKEY_is_a(key, "ML-DSA-44"))
		*type = OCSP_SIGNER_ML_DSA_44;
	else if (EVP_PKEY_is_a(key, "ML-DSA-65"))
		*type = OCSP_SIGNER_ML_DSA_65;
	else if (EVP_PKEY_is_a(key, "ML-DSA-87"))
		*type = OCSP_SIGNER_ML_DSA_87;
	else {
		base_id = EVP_PKEY_base_id(key);
		switch (base_id) {
		case EVP_PKEY_RSA:
			*type = OCSP_SIGNER_RSA;
			break;
		case EVP_PKEY_EC:
			*type = OCSP_SIGNER_ECDSA;
			break;
		default:
			LOGE("Unsupported OCSP signing key type: %d", base_id);
			return OCSP_ERR_ARGUMENT;
		}
	}
	return OCSP_OK;
}

/* Supported response signature algorithms and their signature OIDs. */
struct ocsp_signature_info {
	ocsp_signature_algorithm_t algorithm;
	ocsp_signer_type_t signer_type;
	int nid;
};

static const struct ocsp_signature_info ocsp_signatures[] = {
	{ OCSP_SIGNATURE_RSA_SHA1, OCSP_SIGNER_RSA,
	  NID_sha1WithRSAEncryption },
	{ OCSP_SIGNATURE_RSA_SHA256, OCSP_SIGNER_RSA,
	  NID_sha256WithRSAEncryption },
	{ OCSP_SIGNATURE_RSA_SHA384, OCSP_SIGNER_RSA,
	  NID_sha384WithRSAEncryption },
	{ OCSP_SIGNATURE_RSA_SHA512, OCSP_SIGNER_RSA,
	  NID_sha512WithRSAEncryption },
	{ OCSP_SIGNATURE_ECDSA_SHA1, OCSP_SIGNER_ECDSA,
	  NID_ecdsa_with_SHA1 },
	{ OCSP_SIGNATURE_ECDSA_SHA256, OCSP_SIGNER_ECDSA,
	  NID_ecdsa_with_SHA256 },
	{ OCSP_SIGNATURE_ECDSA_SHA384, OCSP_SIGNER_ECDSA,
	  NID_ecdsa_with_SHA384 },
	{ OCSP_SIGNATURE_ECDSA_SHA512, OCSP_SIGNER_ECDSA,
	  NID_ecdsa_with_SHA512 },
	{ OCSP_SIGNATURE_ML_DSA_44, OCSP_SIGNER_ML_DSA_44, NID_ML_DSA_44 },
	{ OCSP_SIGNATURE_ML_DSA_65, OCSP_SIGNER_ML_DSA_65, NID_ML_DSA_65 },
	{ OCSP_SIGNATURE_ML_DSA_87, OCSP_SIGNER_ML_DSA_87, NID_ML_DSA_87 },
};

static const struct ocsp_signature_info *
_ocsp_signature_info(ocsp_signature_algorithm_t algorithm)
{
	for (size_t i = 0; i < sizeof ocsp_signatures / sizeof ocsp_signatures[0];
	     i++) {
		if (ocsp_signatures[i].algorithm == algorithm)
			return &ocsp_signatures[i];
	}
	return nullptr;
}

static ocsp_signature_algorithm_t _ocsp_nid_to_algorithm(int nid)
{
	for (size_t i = 0; i < sizeof ocsp_signatures / sizeof ocsp_signatures[0];
	     i++) {
		if (ocsp_signatures[i].nid == nid)
			return ocsp_signatures[i].algorithm;
	}
	return OCSP_SIGNATURE_DEFAULT;
}

ocsp_signature_algorithm_t
ocsp_default_signature_algorithm(ocsp_signer_type_t signer_type)
{
	switch (signer_type) {
	case OCSP_SIGNER_RSA:
		return OCSP_SIGNATURE_RSA_SHA256;
	case OCSP_SIGNER_ECDSA:
		return OCSP_SIGNATURE_ECDSA_SHA256;
	case OCSP_SIGNER_ML_DSA_44:
		return OCSP_SIGNATURE_ML_DSA_44;
	case OCSP_SIGNER_ML_DSA_65:
		return OCSP_SIGNATURE_ML_DSA_65;
	case OCSP_SIGNER_ML_DSA_87:
		return OCSP_SIGNATURE_ML_DSA_87;
	default:
		return OCSP_SIGNATURE_DEFAULT;
	}
}

/* Append the DER encoding of an OpenSSL object through its ASN.1 item. */
static bool _ocsp_append_der_item(ossl_der_buf_t *out, const ASN1_ITEM *item,
				  const void *object)
{
	ossl_der_t der = { 0 };
	bool ok;

	ok = ossl_der_encode_item(item, object, &der)
		&& ossl_der_buf_append(out, der.data, der.length);
	ossl_der_release(&der);
	return ok;
}

static bool _ocsp_append_cert_id(ossl_der_buf_t *out,
				 const OCSP_CERTID *cert_id)
{
	return _ocsp_append_der_item(out, ASN1_ITEM_rptr(OCSP_CERTID),
				     cert_id);
}

static bool _ocsp_append_name(ossl_der_buf_t *out, const X509_NAME *name)
{
	return _ocsp_append_der_item(out, ASN1_ITEM_rptr(X509_NAME), name);
}

static bool _ocsp_append_time(ossl_der_buf_t *out,
			      const ASN1_GENERALIZEDTIME *time)
{
	return _ocsp_append_der_item(out, ASN1_ITEM_rptr(ASN1_GENERALIZEDTIME),
				     time);
}

static bool _ocsp_append_wrapped_time(ossl_der_buf_t *out,
				      unsigned char tag,
				      const ASN1_GENERALIZEDTIME *time)
{
	ossl_der_buf_t value = { 0 };
	bool ok = _ocsp_append_time(&value, time)
		&& ossl_der_buf_wrap(out, tag, &value);

	ossl_der_buf_release(&value);
	return ok;
}

static bool _ocsp_append_extension(ossl_der_buf_t *out,
				   const X509_EXTENSION *extension)
{
	return _ocsp_append_der_item(out, ASN1_ITEM_rptr(X509_EXTENSION),
				     extension);
}

static bool _ocsp_append_certificate(ossl_der_buf_t *out,
				     const X509 *certificate)
{
	return _ocsp_append_der_item(out, ASN1_ITEM_rptr(X509), certificate);
}

/*
 * Append a signature as a BIT STRING; the unused-bits octet is always zero.
 */
static bool _ocsp_append_bit_string(ossl_der_buf_t *out,
				    const unsigned char *data, size_t length)
{
	ossl_der_buf_t body = { 0 };
	static const unsigned char unused_bits = 0x00;
	bool ok;

	if (data == nullptr || length == 0)
		return false;

	ok = ossl_der_buf_append(&body, &unused_bits, sizeof unused_bits)
		&& ossl_der_buf_append(&body, data, length)
		&& ossl_der_buf_wrap(out, 0x03, &body);

	ossl_der_buf_release(&body);
	return ok;
}

/* Convert the raw r||s ECDSA signature returned by the HSM to DER. */
static bool _ocsp_ecdsa_signature_der(ossl_der_buf_t *out,
				      const unsigned char *raw,
				      size_t raw_length)
{
	ossl_der_t der = { 0 };
	bool ok;

	ok = ossl_der_encode_ecdsa_signature(raw, raw_length, &der)
		&& ossl_der_buf_append(out, der.data, der.length);
	ossl_der_release(&der);
	return ok;
}

/* Encode the raw HSM signature and select its AlgorithmIdentifier. */
static bool _ocsp_prepare_signature(ossl_der_buf_t *out,
				    const ocsp_signature_t *signature,
				    ocsp_signer_type_t type,
				    ocsp_signature_algorithm_t algorithm,
				    int *algorithm_nid)
{
	const struct ocsp_signature_info *info;

	if (signature->data == nullptr || signature->length == 0
	    || signature->length > INT_MAX)
		return false;

	info = _ocsp_signature_info(algorithm);
	if (info == nullptr || info->signer_type != type)
		return false;

	*algorithm_nid = info->nid;
	if (type == OCSP_SIGNER_ECDSA)
		return _ocsp_ecdsa_signature_der(out, signature->data,
						 signature->length);
	return ossl_der_buf_append(out, signature->data, signature->length);
}

/* Append signatureAlgorithm with the parameters required by its scheme. */
static bool _ocsp_append_algorithm(ossl_der_buf_t *out, int nid)
{
	X509_ALGOR *algorithm = ossl_x509_signature_algorithm_new(nid);
	bool ok;

	if (algorithm == nullptr)
		return false;

	ok = _ocsp_append_der_item(out, ASN1_ITEM_rptr(X509_ALGOR), algorithm);
	X509_ALGOR_free(algorithm);
	return ok;
}

/* Append revocationReason [0] EXPLICIT CRLReason (an ENUMERATED). */
static bool _ocsp_append_reason(ossl_der_buf_t *out, int reason)
{
	ossl_der_buf_t value = { 0 };
	ossl_der_buf_t enumerated = { 0 };
	unsigned char encoded_reason = (unsigned char) reason;
	bool ok;

	ok = ossl_der_buf_append(&value, &encoded_reason, sizeof encoded_reason)
		&& ossl_der_buf_wrap(&enumerated, 0x0a, &value)
		&& ossl_der_buf_wrap(out, 0xa0, &enumerated);

	ossl_der_buf_release(&value);
	ossl_der_buf_release(&enumerated);
	return ok;
}

/*
 * Append CertStatus: good/unknown are NULL-valued context tags, revoked [1]
 * IMPLICIT carries revocationTime and an optional reason.
 */
static bool _ocsp_append_cert_status(ossl_der_buf_t *out,
				     const ocsp_cert_status_info_t *info)
{
	static const unsigned char good_status[] = { 0x80, 0x00 };
	static const unsigned char unknown_status[] = { 0x82, 0x00 };
	ossl_der_buf_t revoked_info = { 0 };
	ASN1_GENERALIZEDTIME *revoked_at = nullptr;
	bool ok = false;

	switch (info->status) {
	case OCSP_CERT_STATUS_GOOD:
		return ossl_der_buf_append(out, good_status, sizeof good_status);
	case OCSP_CERT_STATUS_UNKNOWN:
		return ossl_der_buf_append(out, unknown_status,
					sizeof unknown_status);
	case OCSP_CERT_STATUS_REVOKED:
		break;
	default:
		return false;
	}

	/* CRLReason has no value 7. */
	if (info->revoked_at <= 0
	    || (int64_t) (time_t) info->revoked_at != info->revoked_at
	    || info->reason < 0 || info->reason > 10 || info->reason == 7)
		return false;

	revoked_at = ossl_asn1_generalized_time_from_epoch(info->revoked_at);
	if (revoked_at == nullptr)
		return false;

	if (!_ocsp_append_time(&revoked_info, revoked_at))
		goto done;
	if (info->reason != 0
	    && !_ocsp_append_reason(&revoked_info, info->reason))
		goto done;
	ok = ossl_der_buf_wrap(out, 0xa1, &revoked_info);

done:
	ossl_der_buf_release(&revoked_info);
	ASN1_GENERALIZEDTIME_free(revoked_at);
	return ok;
}

/* Append one SingleResponse to responses (the SEQUENCE OF contents). */
static bool _ocsp_append_single_response(
	ossl_der_buf_t *responses, const OCSP_CERTID *cert_id,
	const ocsp_cert_status_info_t *status,
	const ASN1_GENERALIZEDTIME *this_update,
	const ASN1_GENERALIZEDTIME *next_update)
{
	ossl_der_buf_t single = { 0 };
	bool ok = false;

	if (!_ocsp_append_cert_id(&single, cert_id))
		goto done;
	if (!_ocsp_append_cert_status(&single, status))
		goto done;
	if (!_ocsp_append_time(&single, this_update))
		goto done;
	if (next_update != nullptr
	    && !_ocsp_append_wrapped_time(&single, 0xa0, next_update))
		goto done;

	ok = ossl_der_buf_wrap(responses, 0x30, &single);

done:
	ossl_der_buf_release(&single);
	return ok;
}

/*
 * Copy the request nonce into responseExtensions; append nothing when there
 * is no nonce.
 */
static bool _ocsp_append_nonce(ossl_der_buf_t *out, OCSP_REQUEST *request)
{
	ossl_der_buf_t list = { 0 };
	ossl_der_buf_t sequence = { 0 };
	X509_EXTENSION *nonce;
	X509_EXTENSION *response_nonce = nullptr;
	int index;
	bool ok = false;

	index = OCSP_REQUEST_get_ext_by_NID(request, NID_id_pkix_OCSP_Nonce,
					    -1);
	if (index < 0)
		return true;

	nonce = OCSP_REQUEST_get_ext(request, index);
	if (nonce == nullptr)
		return true;

	/*
	 * RFC 8954 requires the nonce in responses to be non-critical, even
	 * though a request may have marked it critical.  Re-encode a copy
	 * with the critical bit cleared instead of echoing the request BER.
	 */
	response_nonce = X509_EXTENSION_dup(nonce);
	if (response_nonce == nullptr
	    || !X509_EXTENSION_set_critical(response_nonce, 0))
		goto done;

	if (!_ocsp_append_extension(&list, response_nonce)
	    || !ossl_der_buf_wrap(&sequence, 0x30, &list)
	    || !ossl_der_buf_wrap(out, 0xa1, &sequence))
		goto done;

	ok = true;

done:
	X509_EXTENSION_free(response_nonce);
	ossl_der_buf_release(&list);
	ossl_der_buf_release(&sequence);
	return ok;
}

/* Build the ResponseData that is later signed as the BasicOCSPResponse tbs. */
static bool _ocsp_build_response_data(
	ossl_der_buf_t *response_data, const ocsp_request_t *request,
	const ocsp_response_params_t *params,
	const ASN1_GENERALIZEDTIME *this_update,
	const ASN1_GENERALIZEDTIME *next_update)
{
	ossl_der_buf_t body = { 0 };
	ossl_der_buf_t responder_id = { 0 };
	ossl_der_buf_t responses = { 0 };
	ossl_der_buf_t response_sequence = { 0 };
	X509_NAME *subject;
	int count = (int) request->count;
	bool ok = false;

	if (count <= 0 || params->cert_status_count != request->count)
		return false;

	/* responderID byName [1] EXPLICIT Name */
	subject = X509_get_subject_name(params->signer_certificate);
	if (subject == nullptr || !_ocsp_append_name(&responder_id, subject)
	    || !ossl_der_buf_wrap(&body, 0xa1, &responder_id))
		goto done;

	/* producedAt */
	if (!_ocsp_append_time(&body, this_update))
		goto done;

	for (int i = 0; i < count; i++) {
		OCSP_ONEREQ *one =
			OCSP_request_onereq_get0(request->request, i);
		OCSP_CERTID *cert_id =
			one != nullptr ? OCSP_onereq_get0_id(one) : nullptr;

		if (cert_id == nullptr
		    || !_ocsp_append_single_response(
			    &responses, cert_id, &params->cert_statuses[i],
			    this_update, next_update))
			goto done;
	}

	/* responses SEQUENCE OF SingleResponse */
	if (!ossl_der_buf_wrap(&response_sequence, 0x30, &responses)
	    || !ossl_der_buf_append(&body, response_sequence.data,
				 response_sequence.length))
		goto done;

	/* responseExtensions [1] EXPLICIT Extensions, nonce only */
	if (!_ocsp_append_nonce(&body, request->request)
	    || !ossl_der_buf_wrap(response_data, 0x30, &body))
		goto done;

	ok = true;

done:
	ossl_der_buf_release(&body);
	ossl_der_buf_release(&responder_id);
	ossl_der_buf_release(&responses);
	ossl_der_buf_release(&response_sequence);
	return ok;
}

/* Build BasicOCSPResponse around the signed ResponseData. */
static bool _ocsp_build_basic(ossl_der_buf_t *basic,
			      const ossl_der_buf_t *response_data,
			      const ossl_der_buf_t *signature,
			      int signature_nid,
			      const X509 *signer_certificate)
{
	ossl_der_buf_t body = { 0 };
	ossl_der_buf_t algorithm = { 0 };
	ossl_der_buf_t certificate_list = { 0 };
	ossl_der_buf_t certificate_sequence = { 0 };
	ossl_der_buf_t certificates = { 0 };
	bool ok = false;

	if (!_ocsp_append_algorithm(&algorithm, signature_nid))
		goto done;

	/* tbsResponseData, signatureAlgorithm, signature */
	if (!ossl_der_buf_append(&body, response_data->data,
			      response_data->length)
	    || !ossl_der_buf_append(&body, algorithm.data, algorithm.length)
	    || !_ocsp_append_bit_string(&body, signature->data,
					signature->length))
		goto done;

	/* certs [0] EXPLICIT SEQUENCE OF Certificate */
	if (!_ocsp_append_certificate(&certificate_list, signer_certificate)
	    || !ossl_der_buf_wrap(&certificate_sequence, 0x30,
			       &certificate_list)
	    || !ossl_der_buf_wrap(&certificates, 0xa0, &certificate_sequence)
	    || !ossl_der_buf_append(&body, certificates.data,
				 certificates.length)
	    || !ossl_der_buf_wrap(basic, 0x30, &body))
		goto done;

	ok = true;

done:
	ossl_der_buf_release(&body);
	ossl_der_buf_release(&algorithm);
	ossl_der_buf_release(&certificate_list);
	ossl_der_buf_release(&certificate_sequence);
	ossl_der_buf_release(&certificates);
	return ok;
}

/* Wrap BasicOCSPResponse into a successful OCSPResponse. */
static bool _ocsp_build_response(ossl_der_buf_t *response,
				 const ossl_der_buf_t *basic)
{
	/* id-pkix-ocsp-basic: 1.3.6.1.5.5.7.48.1.1 */
	static const unsigned char basic_oid[] = {
		0x06, 0x09, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x30, 0x01, 0x01,
	};
	static const unsigned char successful[] = { 0x0a, 0x01, 0x00 };
	ossl_der_buf_t octet_string = { 0 };
	ossl_der_buf_t response_bytes_body = { 0 };
	ossl_der_buf_t response_bytes = { 0 };
	ossl_der_buf_t response_bytes_explicit = { 0 };
	ossl_der_buf_t body = { 0 };
	bool ok = false;

	/* response OCTET STRING { BasicOCSPResponse } */
	if (!ossl_der_buf_wrap(&octet_string, 0x04, basic)
	    || !ossl_der_buf_append(&response_bytes_body, basic_oid,
				 sizeof basic_oid)
	    || !ossl_der_buf_append(&response_bytes_body, octet_string.data,
				 octet_string.length)
	    || !ossl_der_buf_wrap(&response_bytes, 0x30, &response_bytes_body)
	    || !ossl_der_buf_wrap(&response_bytes_explicit, 0xa0,
			       &response_bytes))
		goto done;

	/* OCSPResponse ::= SEQUENCE { responseStatus, responseBytes } */
	if (!ossl_der_buf_append(&body, successful, sizeof successful)
	    || !ossl_der_buf_append(&body, response_bytes_explicit.data,
				 response_bytes_explicit.length)
	    || !ossl_der_buf_wrap(response, 0x30, &body))
		goto done;

	ok = true;

done:
	ossl_der_buf_release(&octet_string);
	ossl_der_buf_release(&response_bytes_body);
	ossl_der_buf_release(&response_bytes);
	ossl_der_buf_release(&response_bytes_explicit);
	ossl_der_buf_release(&body);
	return ok;
}

/* Decode the generated structure as a sanity check before returning it. */
static bool _ocsp_validate_basic(const ossl_der_buf_t *basic)
{
	void *decoded = nullptr;

	if (basic == nullptr
	    || !ossl_der_decode_item(ASN1_ITEM_rptr(OCSP_BASICRESP),
				     basic->data, basic->length, &decoded))
		return false;

	OCSP_BASICRESP_free(decoded);
	return true;
}

static bool _ocsp_validate_response(const ossl_der_buf_t *response)
{
	void *decoded = nullptr;

	if (response == nullptr
	    || !ossl_der_decode_item(ASN1_ITEM_rptr(OCSP_RESPONSE),
				     response->data, response->length,
				     &decoded))
		return false;

	OCSP_RESPONSE_free(decoded);
	return true;
}

ocsp_result_t ocsp_generate_response(const ocsp_request_t *request,
				     const ocsp_response_params_t *params,
				     unsigned char **resp,
				     size_t *resp_size)
{
	ASN1_GENERALIZEDTIME *this_update = nullptr;
	ASN1_GENERALIZEDTIME *next_update = nullptr;
	ossl_der_buf_t response_data = { 0 };
	ossl_der_buf_t signature_der = { 0 };
	ossl_der_buf_t basic = { 0 };
	ossl_der_buf_t response = { 0 };
	ocsp_signature_t signature = { 0 };
	ocsp_signature_algorithm_t signature_algorithm;
	ocsp_signer_type_t signer_type;
	ocsp_result_t status = OCSP_ERR_ARGUMENT;
	int signature_nid = NID_undef;
	time_t now;

	if (resp == nullptr || resp_size == nullptr) {
		LOGE("resp and resp_size must not be NULL");
		return OCSP_ERR_ARGUMENT;
	}
	*resp = nullptr;
	*resp_size = 0;

	if (request == nullptr || request->request == nullptr
	    || params == nullptr || params->signer_certificate == nullptr
	    || params->cert_statuses == nullptr || params->sign == nullptr
	    || params->cert_status_count != request->count) {
		LOGE("Invalid OCSP response arguments");
		return OCSP_ERR_ARGUMENT;
	}

	status = ocsp_get_signer_type(params->signer_certificate, &signer_type);
	if (status != OCSP_OK) {
		LOGE("Unsupported OCSP signer certificate");
		goto done;
	}

	signature_algorithm = params->signature_algorithm;
	if (signature_algorithm == OCSP_SIGNATURE_DEFAULT)
		signature_algorithm =
			ocsp_default_signature_algorithm(signer_type);
	{
		const struct ocsp_signature_info *info =
			_ocsp_signature_info(signature_algorithm);

		if (info == nullptr || info->signer_type != signer_type) {
			LOGE("Unsupported OCSP signature algorithm");
			status = OCSP_ERR_ARGUMENT;
			goto done;
		}
	}

	now = time(nullptr);
	if (now == (time_t) -1) {
		status = OCSP_ERR_MEMORY;
		goto done;
	}
	this_update = ossl_asn1_generalized_time_from_epoch((int64_t) now);
	if (this_update == nullptr) {
		status = OCSP_ERR_MEMORY;
		goto done;
	}
	if (params->next_update_minutes != 0) {
		next_update = ossl_asn1_generalized_time_from_epoch(
			(int64_t) now
			+ (int64_t) params->next_update_minutes * 60);
		if (next_update == nullptr) {
			status = OCSP_ERR_MEMORY;
			goto done;
		}
	}

	if (!_ocsp_build_response_data(&response_data, request, params,
				       this_update, next_update)) {
		LOGE("Failed to build the OCSP ResponseData");
		status = OCSP_ERR_RESPONSE_ENCODE;
		goto done;
	}

	status = params->sign(params->sign_context, response_data.data,
			      response_data.length, &signature);
	if (status != OCSP_OK) {
		LOGE("Failed to sign the OCSP response");
		goto done;
	}

	if (!_ocsp_prepare_signature(&signature_der, &signature, signer_type,
				     signature_algorithm, &signature_nid)) {
		LOGE("Invalid signature returned by the signing callback");
		status = OCSP_ERR_SIGN;
		goto done;
	}

	if (!_ocsp_build_basic(&basic, &response_data, &signature_der,
			       signature_nid, params->signer_certificate)
	    || !_ocsp_validate_basic(&basic)) {
		LOGE("Failed to encode the BasicOCSPResponse");
		status = OCSP_ERR_RESPONSE_ENCODE;
		goto done;
	}

	if (!_ocsp_build_response(&response, &basic)
	    || !_ocsp_validate_response(&response)) {
		LOGE("Failed to encode the OCSPResponse");
		status = OCSP_ERR_RESPONSE_ENCODE;
		goto done;
	}

	*resp = response.data;
	*resp_size = response.length;
	response.data = nullptr;
	response.length = 0;
	response.capacity = 0;
	status = OCSP_OK;

done:
	/* The signing callback may have produced a buffer on failure. */
	osal_free(signature.data);
	ossl_der_buf_release(&signature_der);
	ossl_der_buf_release(&response_data);
	ossl_der_buf_release(&basic);
	ossl_der_buf_release(&response);
	ASN1_GENERALIZEDTIME_free(this_update);
	ASN1_GENERALIZEDTIME_free(next_update);
	return status;
}

ocsp_result_t ocsp_generate_error_response(
	ocsp_response_status_t response_status, unsigned char **resp,
	size_t *resp_size)
{
	unsigned char *data;

	if (resp == nullptr || resp_size == nullptr) {
		LOGE("resp and resp_size must not be NULL");
		return OCSP_ERR_ARGUMENT;
	}
	*resp = nullptr;
	*resp_size = 0;

	switch (response_status) {
	case OCSP_RESP_STATUS_MALFORMED_REQUEST:
	case OCSP_RESP_STATUS_INTERNAL_ERROR:
	case OCSP_RESP_STATUS_TRY_LATER:
	case OCSP_RESP_STATUS_SIG_REQUIRED:
	case OCSP_RESP_STATUS_UNAUTHORIZED:
		break;
	default:
		LOGE("Invalid OCSP response status: %d", response_status);
		return OCSP_ERR_ARGUMENT;
	}

	/* An error OCSPResponse carries only responseStatus. */
	data = osal_malloc(5);
	if (data == nullptr) {
		LOGE("Failed to allocate the OCSP status response");
		return OCSP_ERR_MEMORY;
	}
	data[0] = 0x30; /* SEQUENCE */
	data[1] = 0x03;
	data[2] = 0x0a; /* ENUMERATED */
	data[3] = 0x01;
	data[4] = (unsigned char) response_status;

	*resp = data;
	*resp_size = 5;
	return OCSP_OK;
}
