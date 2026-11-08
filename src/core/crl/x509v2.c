/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>

#include <anyca/crl.h>
#include <anyca/ossl/asn1.h>
#include <anyca/ossl/der.h>
#include <anyca/ossl/x509.h>

#define CRL_MAX_SERIAL_LENGTH 20

/*
 * TBSCertList from RFC 5280 section 5.1.  The version is a plain INTEGER in
 * a CRL (unlike the [0] EXPLICIT version of a certificate) and is present
 * because every generated CRL is v2.
 */
typedef struct crl_tbs {
	ASN1_INTEGER *version;
	X509_ALGOR *signature;
	X509_NAME *issuer;
	ASN1_TIME *this_update;
	ASN1_TIME *next_update;
	STACK_OF(X509_REVOKED) *revoked;
	STACK_OF(X509_EXTENSION) *extensions;
} crl_tbs_t;

ASN1_SEQUENCE(crl_tbs_t) = {
	ASN1_SIMPLE(crl_tbs_t, version, ASN1_INTEGER),
	ASN1_SIMPLE(crl_tbs_t, signature, X509_ALGOR),
	ASN1_SIMPLE(crl_tbs_t, issuer, X509_NAME),
	ASN1_SIMPLE(crl_tbs_t, this_update, ASN1_TIME),
	ASN1_OPT(crl_tbs_t, next_update, ASN1_TIME),
	ASN1_SEQUENCE_OF_OPT(crl_tbs_t, revoked, X509_REVOKED),
	ASN1_EXP_SEQUENCE_OF_OPT(crl_tbs_t, extensions, X509_EXTENSION, 0),
} ASN1_SEQUENCE_END(crl_tbs_t)

typedef struct crl_certificate {
	crl_tbs_t *tbs;
	X509_ALGOR *signature_algorithm;
	ASN1_BIT_STRING *signature;
} crl_certificate_t;

ASN1_SEQUENCE(crl_certificate_t) = {
	ASN1_SIMPLE(crl_certificate_t, tbs, crl_tbs_t),
	ASN1_SIMPLE(crl_certificate_t, signature_algorithm, X509_ALGOR),
	ASN1_SIMPLE(crl_certificate_t, signature, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(crl_certificate_t)

/* Builder-side revoked entry; OpenSSL objects are created when encoding. */
typedef struct crl_entry {
	unsigned char *serial;
	size_t serial_length;
	int64_t revoked_at;
	int reason;
} crl_entry_t;

struct crl_builder {
	X509 *issuer_certificate;
	X509_NAME *issuer;
	int64_t this_update;
	int64_t next_update;
	crl_entry_t *entries;
	size_t entry_count;
	size_t entry_capacity;
	STACK_OF(X509_EXTENSION) *extensions;
};

static int _crl_rsa_signature_nid(crl_digest_algorithm_t digest)
{
	switch (digest) {
	case CRL_DIGEST_SHA1:
		return NID_sha1WithRSAEncryption;
	case CRL_DIGEST_SHA256:
		return NID_sha256WithRSAEncryption;
	case CRL_DIGEST_SHA384:
		return NID_sha384WithRSAEncryption;
	case CRL_DIGEST_SHA512:
		return NID_sha512WithRSAEncryption;
	}
	return NID_undef;
}

static int _crl_ecdsa_signature_nid(crl_digest_algorithm_t digest)
{
	switch (digest) {
	case CRL_DIGEST_SHA1:
		return NID_ecdsa_with_SHA1;
	case CRL_DIGEST_SHA256:
		return NID_ecdsa_with_SHA256;
	case CRL_DIGEST_SHA384:
		return NID_ecdsa_with_SHA384;
	case CRL_DIGEST_SHA512:
		return NID_ecdsa_with_SHA512;
	}
	return NID_undef;
}

static X509_ALGOR *_crl_signature_algorithm(crl_signature_scheme_t scheme,
					    crl_digest_algorithm_t digest)
{
	int nid = NID_undef;

	if (scheme == CRL_SIGNATURE_RSA)
		nid = _crl_rsa_signature_nid(digest);
	else if (scheme == CRL_SIGNATURE_ECDSA)
		nid = _crl_ecdsa_signature_nid(digest);
	else if (scheme == CRL_SIGNATURE_ML_DSA_44)
		nid = NID_ML_DSA_44;
	else if (scheme == CRL_SIGNATURE_ML_DSA_65)
		nid = NID_ML_DSA_65;
	else if (scheme == CRL_SIGNATURE_ML_DSA_87)
		nid = NID_ML_DSA_87;

	return ossl_x509_signature_algorithm_new(nid);
}

static ASN1_INTEGER *_crl_serial_integer(const unsigned char *serial,
					 size_t serial_length)
{
	if (serial == nullptr || serial_length == 0
	    || serial_length > CRL_MAX_SERIAL_LENGTH
	    || serial_length > INT_MAX)
		return nullptr;
	if (serial_length == CRL_MAX_SERIAL_LENGTH
	    && (serial[0] & 0x80) != 0)
		return nullptr;

	return ossl_asn1_integer_from_bytes(serial, serial_length);
}

static bool _crl_revoked_add_reason(X509_REVOKED *revoked, int reason)
{
	ASN1_ENUMERATED *value;
	int result;

	value = ASN1_ENUMERATED_new();
	if (value == nullptr || ASN1_ENUMERATED_set(value, reason) != 1) {
		ASN1_ENUMERATED_free(value);
		return false;
	}
	result = X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, value, 0,
					   0);
	ASN1_ENUMERATED_free(value);
	return result == 1;
}

static X509_REVOKED *_crl_revoked_entry(const crl_entry_t *entry)
{
	X509_REVOKED *revoked = nullptr;
	ASN1_INTEGER *serial = nullptr;
	ASN1_TIME *revocation_date = nullptr;

	revoked = X509_REVOKED_new();
	serial = _crl_serial_integer(entry->serial, entry->serial_length);
	revocation_date = ossl_asn1_time_from_epoch(entry->revoked_at);
	if (revoked == nullptr || serial == nullptr
	    || revocation_date == nullptr
	    || X509_REVOKED_set_serialNumber(revoked, serial) != 1
	    || X509_REVOKED_set_revocationDate(revoked, revocation_date) != 1)
		goto fail;

	if (entry->reason != 0
	    && !_crl_revoked_add_reason(revoked, entry->reason))
		goto fail;

	ASN1_INTEGER_free(serial);
	ASN1_TIME_free(revocation_date);
	return revoked;

fail:
	ASN1_INTEGER_free(serial);
	ASN1_TIME_free(revocation_date);
	X509_REVOKED_free(revoked);
	return nullptr;
}

static void _crl_tbs_release(crl_tbs_t *tbs)
{
	if (tbs == nullptr)
		return;

	ASN1_INTEGER_free(tbs->version);
	X509_ALGOR_free(tbs->signature);
	X509_NAME_free(tbs->issuer);
	ASN1_TIME_free(tbs->this_update);
	ASN1_TIME_free(tbs->next_update);
	sk_X509_REVOKED_pop_free(tbs->revoked, X509_REVOKED_free);
	sk_X509_EXTENSION_pop_free(tbs->extensions, X509_EXTENSION_free);
	osal_free(tbs);
}

static void _crl_certificate_release(crl_certificate_t *certificate)
{
	if (certificate == nullptr)
		return;

	/*
	 * container->tbs is decoded by crl_builder_assemble() with
	 * ASN1_item_d2i(), so it must be released with the OpenSSL allocator.
	 */
	if (certificate->tbs != nullptr)
		ASN1_item_free((ASN1_VALUE *) certificate->tbs,
			       ASN1_ITEM_rptr(crl_tbs_t));
	X509_ALGOR_free(certificate->signature_algorithm);
	ASN1_BIT_STRING_free(certificate->signature);
	osal_free(certificate);
}

static crl_tbs_t *_crl_build_tbs(const crl_builder_t *builder,
				 crl_signature_scheme_t scheme,
				 crl_digest_algorithm_t digest)
{
	X509_ALGOR *signature = nullptr;
	X509_NAME *issuer = nullptr;
	ASN1_TIME *this_update = nullptr;
	ASN1_TIME *next_update = nullptr;
	crl_tbs_t *tbs = nullptr;
	bool ok = false;

	if (builder->issuer == nullptr) {
		LOGE("The CRL issuer is not set");
		return nullptr;
	}

	signature = _crl_signature_algorithm(scheme, digest);
	if (signature == nullptr) {
		LOGE("Unsupported CRL signature algorithm");
		goto done;
	}
	issuer = X509_NAME_dup(builder->issuer);
	if (issuer == nullptr) {
		LOGE("Out of memory while copying the CRL issuer");
		goto done;
	}
	this_update = builder->this_update != 0
		? ossl_asn1_time_from_epoch(builder->this_update)
		: ossl_asn1_time_now();
	if (this_update == nullptr) {
		LOGE("Invalid CRL thisUpdate time");
		goto done;
	}
	if (builder->next_update != 0) {
		next_update = ossl_asn1_time_from_epoch(builder->next_update);
		if (next_update == nullptr) {
			LOGE("Invalid CRL nextUpdate time");
			goto done;
		}
	}

	tbs = osal_calloc(1, sizeof *tbs);
	if (tbs == nullptr) {
		LOGE("Out of memory while building the CRL");
		goto done;
	}

	tbs->version = ASN1_INTEGER_new();
	if (tbs->version == nullptr || ASN1_INTEGER_set(tbs->version, 1) != 1) {
		LOGE("Cannot encode the CRL version");
		goto done;
	}
	tbs->signature = signature;
	signature = nullptr;
	tbs->issuer = issuer;
	issuer = nullptr;
	tbs->this_update = this_update;
	this_update = nullptr;
	tbs->next_update = next_update;
	next_update = nullptr;

	if (builder->entry_count != 0) {
		tbs->revoked = sk_X509_REVOKED_new_null();
		if (tbs->revoked == nullptr) {
			LOGE("Out of memory while building the CRL entries");
			goto done;
		}
		for (size_t i = 0; i < builder->entry_count; i++) {
			X509_REVOKED *revoked =
				_crl_revoked_entry(&builder->entries[i]);

			if (revoked == nullptr
			    || sk_X509_REVOKED_push(tbs->revoked, revoked)
				       <= 0) {
				X509_REVOKED_free(revoked);
				LOGE("Cannot encode the CRL entries");
				goto done;
			}
		}
	}

	if (builder->extensions != nullptr
	    && sk_X509_EXTENSION_num(builder->extensions) > 0) {
		tbs->extensions = ossl_x509_extension_copy_stack(
			builder->extensions);
		if (tbs->extensions == nullptr) {
			LOGE("Out of memory while copying CRL extensions");
			goto done;
		}
	}

	ok = true;

done:
	X509_ALGOR_free(signature);
	X509_NAME_free(issuer);
	ASN1_TIME_free(this_update);
	ASN1_TIME_free(next_update);
	if (!ok) {
		_crl_tbs_release(tbs);
		tbs = nullptr;
	}
	return tbs;
}

static bool _crl_validate(const unsigned char *der, size_t length,
			  const X509 *issuer)
{
	X509_CRL *crl;
	bool ok;

	if (issuer == nullptr)
		return false;

	crl = ossl_x509_crl_load_der(der, length);
	if (crl == nullptr)
		return false;

	ok = ossl_x509_crl_issued_by(crl, issuer);
	X509_CRL_free(crl);
	return ok;
}

crl_builder_t *crl_builder_new(void)
{
	return osal_calloc(1, sizeof(crl_builder_t));
}

void crl_builder_free(crl_builder_t *builder)
{
	if (builder == nullptr)
		return;

	for (size_t i = 0; i < builder->entry_count; i++)
		osal_free(builder->entries[i].serial);
	osal_free(builder->entries);
	sk_X509_EXTENSION_pop_free(builder->extensions, X509_EXTENSION_free);
	X509_NAME_free(builder->issuer);
	X509_free(builder->issuer_certificate);
	osal_free(builder);
}

bool crl_builder_set_issuer_certificate(crl_builder_t *builder,
					const unsigned char *der, size_t length)
{
	X509 *certificate;
	X509_NAME *name;

	if (builder == nullptr || der == nullptr || length == 0)
		return false;

	certificate = ossl_x509_load_der(der, length);
	if (certificate == nullptr) {
		LOGE("Cannot parse the CRL issuer certificate");
		return false;
	}
	if (X509_check_ca(certificate) <= 0) {
		LOGE("The CRL issuer certificate is not a CA");
		X509_free(certificate);
		return false;
	}

	name = X509_NAME_dup(X509_get_subject_name(certificate));
	if (name == nullptr) {
		LOGE("Out of memory while copying the CRL issuer name");
		X509_free(certificate);
		return false;
	}

	X509_NAME_free(builder->issuer);
	X509_free(builder->issuer_certificate);
	builder->issuer = name;
	builder->issuer_certificate = certificate;
	return true;
}

bool crl_builder_set_update_times(crl_builder_t *builder, int64_t this_update,
				  int64_t next_update)
{
	ASN1_TIME *asn1_time;

	if (builder == nullptr)
		return false;

	/*
	 * RFC 5280 section 5.1.2.5 requires every conforming CRL to carry
	 * nextUpdate; without it clients can neither refresh nor expire the CRL.
	 */
	if (next_update == 0) {
		LOGE("A CRL must include nextUpdate");
		return false;
	}

	if (this_update != 0) {
		asn1_time = ossl_asn1_time_from_epoch(this_update);
		if (asn1_time == nullptr) {
			LOGE("Invalid CRL thisUpdate time");
			return false;
		}
		ASN1_TIME_free(asn1_time);
	}
	asn1_time = ossl_asn1_time_from_epoch(next_update);
	if (asn1_time == nullptr) {
		LOGE("Invalid CRL nextUpdate time");
		return false;
	}
	ASN1_TIME_free(asn1_time);

	if (this_update != 0) {
		if (next_update <= this_update) {
			LOGE("CRL nextUpdate must follow thisUpdate");
			return false;
		}
	} else {
		time_t now = time(nullptr);

		/*
		 * With thisUpdate omitted the builder uses the wall clock, so
		 * nextUpdate must still be in the future.
		 */
		if (now != (time_t) -1 && next_update <= (int64_t) now) {
			LOGE("CRL nextUpdate must be in the future");
			return false;
		}
	}

	builder->this_update = this_update;
	builder->next_update = next_update;
	return true;
}

bool crl_builder_add_revoked_certificate(crl_builder_t *builder,
					 const unsigned char *serial,
					 size_t serial_length,
					 int64_t revoked_at, int reason)
{
	ASN1_TIME *time;
	unsigned char *copy;
	bool nonzero = false;

	if (builder == nullptr || serial == nullptr || serial_length == 0
	    || serial_length > CRL_MAX_SERIAL_LENGTH)
		return false;
	if (serial_length == CRL_MAX_SERIAL_LENGTH
	    && (serial[0] & 0x80) != 0)
		return false;
	for (size_t i = 0; i < serial_length; i++) {
		if (serial[i] != 0) {
			nonzero = true;
			break;
		}
	}
	if (!nonzero)
		return false;
	if (reason < 0 || reason > 10 || reason == 7) {
		LOGE("Invalid CRL reason code: %d", reason);
		return false;
	}
	time = ossl_asn1_time_from_epoch(revoked_at);
	if (time == nullptr) {
		LOGE("Invalid certificate revocation time");
		return false;
	}
	ASN1_TIME_free(time);

	if (builder->entry_count == builder->entry_capacity) {
		size_t capacity = builder->entry_capacity == 0
			? 16
			: builder->entry_capacity * 2;
		crl_entry_t *entries;

		if (capacity < builder->entry_capacity
		    || capacity > SIZE_MAX / sizeof *entries) {
			LOGE("Too many CRL entries");
			return false;
		}
		entries = osal_realloc(builder->entries,
				       capacity * sizeof *entries);
		if (entries == nullptr) {
			LOGE("Out of memory while adding a CRL entry");
			return false;
		}
		builder->entries = entries;
		builder->entry_capacity = capacity;
	}

	copy = osal_malloc(serial_length);
	if (copy == nullptr) {
		LOGE("Out of memory while copying a certificate serial");
		return false;
	}
	memcpy(copy, serial, serial_length);
	builder->entries[builder->entry_count].serial = copy;
	builder->entries[builder->entry_count].serial_length = serial_length;
	builder->entries[builder->entry_count].revoked_at = revoked_at;
	builder->entries[builder->entry_count].reason = reason;
	builder->entry_count++;
	return true;
}

bool crl_builder_add_crl_number(crl_builder_t *builder, uint64_t number)
{
	ASN1_INTEGER *integer;
	X509_EXTENSION *extension;

	if (builder == nullptr)
		return false;

	integer = ossl_asn1_integer_from_uint64(number);
	if (integer == nullptr) {
		LOGE("Cannot encode the CRL number");
		return false;
	}
	extension = ossl_x509_extension_new_by_nid(NID_crl_number, false,
						   integer);
	ASN1_INTEGER_free(integer);
	if (extension == nullptr) {
		LOGE("Cannot encode the CRL number extension");
		return false;
	}
	return ossl_x509_extension_push(&builder->extensions, extension);
}

bool crl_builder_add_authority_key_identifier(crl_builder_t *builder)
{
	X509_EXTENSION *extension;

	if (builder == nullptr || builder->issuer_certificate == nullptr) {
		LOGE("The issuer certificate must be set before the "
		     "authority key identifier");
		return false;
	}

	extension = ossl_x509_authority_key_identifier(
		builder->issuer_certificate);
	if (extension == nullptr)
		return false;
	return ossl_x509_extension_push(&builder->extensions, extension);
}

bool crl_builder_add_extension(crl_builder_t *builder, const char *oid,
			       bool critical, const unsigned char *der,
			       size_t length)
{
	X509_EXTENSION *extension;

	if (builder == nullptr || oid == nullptr
	    || (der == nullptr && length != 0) || length > INT_MAX)
		return false;

	extension = ossl_x509_extension_new_der(oid, critical, der, length);
	if (extension == nullptr) {
		LOGE("Cannot encode CRL extension %s", oid);
		return false;
	}
	return ossl_x509_extension_push(&builder->extensions, extension);
}

bool crl_builder_tbs(const crl_builder_t *builder, crl_signature_scheme_t scheme,
		     crl_digest_algorithm_t digest, crl_blob_t *tbs_blob)
{
	crl_tbs_t *tbs;
	ossl_der_t der = { 0 };
	bool ok = false;

	if (tbs_blob == nullptr)
		return false;
	tbs_blob->data = nullptr;
	tbs_blob->length = 0;

	if (builder == nullptr)
		return false;

	tbs = _crl_build_tbs(builder, scheme, digest);
	if (tbs == nullptr)
		return false;

	if (!ossl_der_encode_item(ASN1_ITEM_rptr(crl_tbs_t), tbs, &der)) {
		LOGE("Cannot encode the TBSCertList");
		goto done;
	}

	tbs_blob->data = der.data;
	tbs_blob->length = der.length;
	der.data = nullptr;
	der.length = 0;
	ok = true;

done:
	ossl_der_release(&der);
	_crl_tbs_release(tbs);
	return ok;
}

bool crl_builder_assemble(const crl_builder_t *builder,
			  crl_signature_scheme_t scheme,
			  crl_digest_algorithm_t digest,
			  const unsigned char *tbs_der, size_t tbs_length,
			  const unsigned char *signature,
			  size_t signature_length, crl_blob_t *crl)
{
	const unsigned char *cursor;
	const unsigned char *signature_bytes = signature;
	size_t signature_bytes_length = signature_length;
	crl_tbs_t *tbs = nullptr;
	X509_ALGOR *signature_algorithm = nullptr;
	ASN1_BIT_STRING *asn1_signature = nullptr;
	crl_certificate_t *container = nullptr;
	ossl_der_t encoded_signature = { 0 };
	ossl_der_t crl_der = { 0 };
	bool ok = false;

	if (crl == nullptr)
		return false;
	crl->data = nullptr;
	crl->length = 0;

	if (builder == nullptr || builder->issuer_certificate == nullptr
	    || tbs_der == nullptr || tbs_length == 0
	    || tbs_length > LONG_MAX || signature == nullptr
	    || signature_length == 0)
		return false;

	cursor = tbs_der;
	tbs = (crl_tbs_t *) ASN1_item_d2i(nullptr, &cursor, (long) tbs_length,
					  ASN1_ITEM_rptr(crl_tbs_t));
	if (tbs == nullptr || cursor != tbs_der + tbs_length) {
		LOGE("Cannot parse the TBSCertList");
		goto done;
	}

	if (scheme == CRL_SIGNATURE_ECDSA) {
		if (!ossl_der_encode_ecdsa_signature(signature, signature_length,
						     &encoded_signature))
			goto done;
		signature_bytes = encoded_signature.data;
		signature_bytes_length = encoded_signature.length;
	} else if (scheme != CRL_SIGNATURE_RSA
		   && scheme != CRL_SIGNATURE_ML_DSA_44
		   && scheme != CRL_SIGNATURE_ML_DSA_65
		   && scheme != CRL_SIGNATURE_ML_DSA_87) {
		LOGE("Unsupported CRL signature algorithm");
		goto done;
	}

	if (signature_bytes_length > INT_MAX) {
		LOGE("Cannot encode the CRL signature");
		goto done;
	}
	asn1_signature = ossl_asn1_bit_string_from_bytes(signature_bytes,
							 signature_bytes_length);
	if (asn1_signature == nullptr) {
		LOGE("Cannot encode the CRL signature");
		goto done;
	}

	signature_algorithm = _crl_signature_algorithm(scheme, digest);
	if (signature_algorithm == nullptr) {
		LOGE("Cannot encode the outer CRL signature algorithm");
		goto done;
	}

	container = osal_calloc(1, sizeof *container);
	if (container == nullptr) {
		LOGE("Out of memory while building the CRL");
		goto done;
	}
	container->tbs = tbs;
	tbs = nullptr;
	container->signature_algorithm = signature_algorithm;
	signature_algorithm = nullptr;
	container->signature = asn1_signature;
	asn1_signature = nullptr;

	if (!ossl_der_encode_item(ASN1_ITEM_rptr(crl_certificate_t), container,
				  &crl_der)) {
		LOGE("Cannot encode the CRL");
		goto done;
	}
	if (!_crl_validate(crl_der.data, crl_der.length,
			   builder->issuer_certificate)) {
		LOGE("The generated CRL failed signature verification");
		goto done;
	}

	crl->data = crl_der.data;
	crl->length = crl_der.length;
	crl_der.data = nullptr;
	crl_der.length = 0;
	ok = true;

done:
	ossl_der_release(&crl_der);
	ossl_der_release(&encoded_signature);
	ASN1_BIT_STRING_free(asn1_signature);
	X509_ALGOR_free(signature_algorithm);
	_crl_certificate_release(container);
	/*
	 * tbs was decoded with ASN1_item_d2i() in this function, so release it
	 * with the OpenSSL allocator rather than _crl_tbs_release().
	 */
	if (tbs != nullptr)
		ASN1_item_free((ASN1_VALUE *) tbs,
			       ASN1_ITEM_rptr(crl_tbs_t));
	return ok;
}

void crl_blob_free(crl_blob_t *crl)
{
	if (crl == nullptr)
		return;

	osal_free(crl->data);
	crl->data = nullptr;
	crl->length = 0;
}
