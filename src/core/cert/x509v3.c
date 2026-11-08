/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <anyca/osal/log.h>
#include <anyca/osal/memory.h>

#include <anyca/cert.h>
#include <anyca/ossl/asn1.h>
#include <anyca/ossl/der.h>
#include <anyca/ossl/x509.h>

#define CERT_DEFAULT_VALIDITY_DAYS 3650U
#define CERT_MAX_VALIDITY_DAYS 365000U
#define CERT_MAX_SERIAL_LENGTH 20
#define CERT_RANDOM_SERIAL_LENGTH 16
#define CERT_SECONDS_PER_DAY 86400

/*
 * OpenSSL has no public setter for the signature algorithm inside
 * TBSCertificate, so certificates are encoded with local ASN.1 templates and
 * signed by the caller instead of X509_sign().
 */
typedef struct cert_tbs {
	ASN1_INTEGER *version;
	ASN1_INTEGER *serial;
	X509_ALGOR *signature;
	X509_NAME *issuer;
	X509_VAL *validity;
	X509_NAME *subject;
	X509_PUBKEY *public_key;
	STACK_OF(X509_EXTENSION) *extensions;
} cert_tbs_t;

ASN1_SEQUENCE(cert_tbs_t) = {
	ASN1_EXP_OPT(cert_tbs_t, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(cert_tbs_t, serial, ASN1_INTEGER),
	ASN1_SIMPLE(cert_tbs_t, signature, X509_ALGOR),
	ASN1_SIMPLE(cert_tbs_t, issuer, X509_NAME),
	ASN1_SIMPLE(cert_tbs_t, validity, X509_VAL),
	ASN1_SIMPLE(cert_tbs_t, subject, X509_NAME),
	ASN1_SIMPLE(cert_tbs_t, public_key, X509_PUBKEY),
	ASN1_EXP_SEQUENCE_OF_OPT(cert_tbs_t, extensions, X509_EXTENSION, 3),
} ASN1_SEQUENCE_END(cert_tbs_t)

typedef struct cert_certificate {
	cert_tbs_t *tbs;
	X509_ALGOR *signature_algorithm;
	ASN1_BIT_STRING *signature;
} cert_certificate_t;

ASN1_SEQUENCE(cert_certificate_t) = {
	ASN1_SIMPLE(cert_certificate_t, tbs, cert_tbs_t),
	ASN1_SIMPLE(cert_certificate_t, signature_algorithm, X509_ALGOR),
	ASN1_SIMPLE(cert_certificate_t, signature, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(cert_certificate_t)

/* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
typedef struct cert_rsa_public_key {
	BIGNUM *modulus;
	BIGNUM *exponent;
} cert_rsa_public_key_t;

ASN1_SEQUENCE(cert_rsa_public_key_t) = {
	ASN1_SIMPLE(cert_rsa_public_key_t, modulus, BIGNUM),
	ASN1_SIMPLE(cert_rsa_public_key_t, exponent, BIGNUM),
} ASN1_SEQUENCE_END(cert_rsa_public_key_t)

/* SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
 *                                      subjectPublicKey BIT STRING } */
typedef struct cert_subject_public_key {
	X509_ALGOR *algorithm;
	ASN1_BIT_STRING *public_key;
} cert_subject_public_key_t;

ASN1_SEQUENCE(cert_subject_public_key_t) = {
	ASN1_SIMPLE(cert_subject_public_key_t, algorithm, X509_ALGOR),
	ASN1_SIMPLE(cert_subject_public_key_t, public_key, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(cert_subject_public_key_t)

struct cert_builder {
	unsigned char *serial;
	size_t serial_length;
	X509_NAME *subject;
	X509_NAME *issuer;
	X509 *issuer_certificate;
	X509_PUBKEY *public_key;
	STACK_OF(X509_EXTENSION) *extensions;
	int64_t not_before;
	uint32_t validity_days;
};

static bool _cert_add_subject_entry(X509_NAME *name, const char *component,
				    size_t length)
{
	char *copy;
	char *start;
	char *end;
	char *equals;
	char *type;
	char *value;
	char *read;
	char *write;
	bool ok = false;

	copy = osal_malloc(length + 1);
	if (copy == nullptr) {
		LOGE("Out of memory while parsing the subject");
		return false;
	}
	memcpy(copy, component, length);
	copy[length] = '\0';

	start = copy;
	while (*start == ' ' || *start == '\t')
		start++;
	end = start + strlen(start);
	while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
		*--end = '\0';
	if (*start == '\0')
		goto done;

	equals = strchr(start, '=');
	if (equals == nullptr)
		goto done;
	*equals = '\0';

	type = start;
	end = type + strlen(type);
	while (end > type && (end[-1] == ' ' || end[-1] == '\t'))
		*--end = '\0';

	value = equals + 1;
	while (*value == ' ' || *value == '\t')
		value++;
	end = value + strlen(value);
	while (end > value && (end[-1] == ' ' || end[-1] == '\t'))
		*--end = '\0';
	if (*type == '\0' || *value == '\0')
		goto done;

	/* Remove RFC 2253-style backslash escapes. */
	read = value;
	write = value;
	while (*read != '\0') {
		if (*read == '\\') {
			read++;
			if (*read == '\0')
				goto done;
		}
		*write++ = *read++;
	}
	*write = '\0';

	if (X509_NAME_add_entry_by_txt(
		    name, type, MBSTRING_UTF8, (const unsigned char *) value,
		    -1, -1, 0)
	    != 1) {
		LOGE("Invalid subject attribute: %s=%s", type, value);
		goto done;
	}

	ok = true;

done:
	osal_free(copy);
	return ok;
}

static X509_NAME *_cert_subject_name(const char *subject)
{
	X509_NAME *name;
	const char *cursor;
	char delimiter;

	if (subject == nullptr || subject[0] == '\0') {
		LOGE("The subject must not be empty");
		return nullptr;
	}

	name = X509_NAME_new();
	if (name == nullptr)
		return nullptr;

	delimiter = subject[0] == '/' ? '/' : ',';
	cursor = subject[0] == '/' ? subject + 1 : subject;
	if (*cursor == '\0')
		goto fail;

	while (*cursor != '\0') {
		const char *end = cursor;

		while (*end != '\0') {
			if (*end == '\\' && end[1] != '\0') {
				end += 2;
				continue;
			}
			if (*end == delimiter)
				break;
			end++;
		}
		if (end == cursor)
			goto fail;
		if (!_cert_add_subject_entry(name, cursor,
					     (size_t) (end - cursor)))
			goto fail;
		if (*end == '\0')
			break;
		cursor = end + 1;
		if (*cursor == '\0')
			goto fail;
	}

	return name;

fail:
	LOGE("Invalid subject name: %s", subject);
	X509_NAME_free(name);
	return nullptr;
}

static X509_PUBKEY *_cert_spki(X509_ALGOR *algorithm,
			       const unsigned char *key, size_t key_length)
{
	cert_subject_public_key_t info = { 0 };
	ossl_der_t der = { 0 };
	X509_PUBKEY *public_key = nullptr;

	if (algorithm == nullptr || key == nullptr || key_length == 0
	    || key_length > INT_MAX)
		return nullptr;

	info.algorithm = algorithm;
	info.public_key = ossl_asn1_bit_string_from_bytes(key, key_length);
	if (info.public_key == nullptr)
		goto done;

	if (ossl_der_encode_item(ASN1_ITEM_rptr(cert_subject_public_key_t),
				 &info, &der))
		(void) ossl_x509_pubkey_decode(der.data, der.length,
					       &public_key);

done:
	ossl_der_release(&der);
	ASN1_BIT_STRING_free(info.public_key);
	return public_key;
}

static X509_PUBKEY *_cert_rsa_public_key(const unsigned char *modulus,
					 size_t modulus_length,
					 const unsigned char *exponent,
					 size_t exponent_length)
{
	cert_rsa_public_key_t rsa = { 0 };
	ossl_der_t encoded = { 0 };
	X509_ALGOR *algorithm = nullptr;
	X509_PUBKEY *public_key = nullptr;

	if (modulus == nullptr || exponent == nullptr || modulus_length == 0
	    || exponent_length == 0 || modulus_length > INT_MAX
	    || exponent_length > INT_MAX)
		return nullptr;

	rsa.modulus = BN_bin2bn(modulus, (int) modulus_length, nullptr);
	rsa.exponent = BN_bin2bn(exponent, (int) exponent_length, nullptr);
	if (rsa.modulus == nullptr || rsa.exponent == nullptr
	    || BN_is_zero(rsa.modulus) || BN_is_zero(rsa.exponent))
		goto done;
	if (!ossl_der_encode_item(ASN1_ITEM_rptr(cert_rsa_public_key_t), &rsa,
				  &encoded))
		goto done;

	algorithm = X509_ALGOR_new();
	if (algorithm == nullptr
	    || X509_ALGOR_set0(algorithm, OBJ_nid2obj(NID_rsaEncryption),
			       V_ASN1_NULL, nullptr)
		       != 1)
		goto done;
	public_key = _cert_spki(algorithm, encoded.data, encoded.length);

done:
	X509_ALGOR_free(algorithm);
	BN_free(rsa.modulus);
	BN_free(rsa.exponent);
	ossl_der_release(&encoded);
	return public_key;
}

static X509_PUBKEY *_cert_ec_public_key(const unsigned char *ec_params,
					size_t ec_params_length,
					const unsigned char *ec_point,
					size_t ec_point_length)
{
	const unsigned char *cursor = ec_params;
	X509_ALGOR *algorithm = nullptr;
	X509_PUBKEY *public_key = nullptr;
	ASN1_OBJECT *curve;

	if (ec_params == nullptr || ec_point == nullptr || ec_params_length == 0
	    || ec_params_length > LONG_MAX || ec_point_length == 0)
		return nullptr;

	curve = d2i_ASN1_OBJECT(nullptr, &cursor, (long) ec_params_length);
	if (curve == nullptr || cursor != ec_params + ec_params_length) {
		ASN1_OBJECT_free(curve);
		return nullptr;
	}

	algorithm = X509_ALGOR_new();
	if (algorithm == nullptr
	    || X509_ALGOR_set0(algorithm,
			       OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
			       V_ASN1_OBJECT, curve)
		       != 1) {
		ASN1_OBJECT_free(curve);
		X509_ALGOR_free(algorithm);
		return nullptr;
	}
	public_key = _cert_spki(algorithm, ec_point, ec_point_length);
	X509_ALGOR_free(algorithm);
	return public_key;
}

/*
 * X509_PUBKEY_dup() drops ASN1_STRING_FLAG_BITS_LEFT, so the copied BIT STRING
 * reports its trailing zero bits as unused; an EC point ending in a zero byte
 * would then be encoded incorrectly.  Copy through DER instead.
 */
static X509_PUBKEY *_cert_public_key_copy(const X509_PUBKEY *public_key)
{
	ossl_der_t der = { 0 };
	X509_PUBKEY *copy = nullptr;

	if (public_key == nullptr
	    || !ossl_x509_pubkey_encode(public_key, &der))
		return nullptr;

	(void) ossl_x509_pubkey_decode(der.data, der.length, &copy);
	ossl_der_release(&der);
	return copy;
}

static int _cert_rsa_signature_nid(cert_digest_algorithm_t digest)
{
	switch (digest) {
	case CERT_DIGEST_SHA1:
		return NID_sha1WithRSAEncryption;
	case CERT_DIGEST_SHA256:
		return NID_sha256WithRSAEncryption;
	case CERT_DIGEST_SHA384:
		return NID_sha384WithRSAEncryption;
	case CERT_DIGEST_SHA512:
		return NID_sha512WithRSAEncryption;
	}
	return NID_undef;
}

static int _cert_ecdsa_signature_nid(cert_digest_algorithm_t digest)
{
	switch (digest) {
	case CERT_DIGEST_SHA1:
		return NID_ecdsa_with_SHA1;
	case CERT_DIGEST_SHA256:
		return NID_ecdsa_with_SHA256;
	case CERT_DIGEST_SHA384:
		return NID_ecdsa_with_SHA384;
	case CERT_DIGEST_SHA512:
		return NID_ecdsa_with_SHA512;
	}
	return NID_undef;
}

static X509_ALGOR *_cert_signature_algorithm(cert_signature_scheme_t scheme,
					     cert_digest_algorithm_t digest)
{
	int nid = NID_undef;

	if (scheme == CERT_SIGNATURE_RSA)
		nid = _cert_rsa_signature_nid(digest);
	else if (scheme == CERT_SIGNATURE_ECDSA)
		nid = _cert_ecdsa_signature_nid(digest);
	else if (scheme == CERT_SIGNATURE_ML_DSA_44)
		nid = NID_ML_DSA_44;
	else if (scheme == CERT_SIGNATURE_ML_DSA_65)
		nid = NID_ML_DSA_65;
	else if (scheme == CERT_SIGNATURE_ML_DSA_87)
		nid = NID_ML_DSA_87;

	return ossl_x509_signature_algorithm_new(nid);
}

static ASN1_INTEGER *_cert_serial_integer(const unsigned char *serial,
					  size_t serial_length)
{
	if (serial == nullptr || serial_length == 0
	    || serial_length > CERT_MAX_SERIAL_LENGTH
	    || serial_length > INT_MAX)
		return nullptr;
	if (serial_length == CERT_MAX_SERIAL_LENGTH
	    && (serial[0] & 0x80) != 0)
		return nullptr;

	return ossl_asn1_integer_from_bytes(serial, serial_length);
}

static X509_VAL *_cert_validity(int64_t not_before, uint32_t validity_days)
{
	X509_VAL *validity;
	ASN1_TIME *start_time;
	ASN1_TIME *end_time;
	time_t start;
	int64_t end_value;
	int64_t increment;

	if (validity_days == 0)
		validity_days = CERT_DEFAULT_VALIDITY_DAYS;
	if (validity_days > CERT_MAX_VALIDITY_DAYS)
		return nullptr;

	if (not_before == 0) {
		start = time(nullptr);
		if (start == (time_t) -1)
			return nullptr;
	} else {
		start = (time_t) not_before;
		if ((int64_t) start != not_before)
			return nullptr;
	}

	/* Reject a validity period that would overflow end_value. */
	increment = (int64_t) validity_days * CERT_SECONDS_PER_DAY;
	if ((int64_t) start > INT64_MAX - increment)
		return nullptr;
	end_value = (int64_t) start + increment;
	if (end_value <= (int64_t) start)
		return nullptr;

	validity = X509_VAL_new();
	if (validity == nullptr)
		return nullptr;

	start_time = ossl_asn1_time_from_epoch((int64_t) start);
	end_time = ossl_asn1_time_from_epoch(end_value);
	if (start_time == nullptr || end_time == nullptr) {
		ASN1_TIME_free(start_time);
		ASN1_TIME_free(end_time);
		X509_VAL_free(validity);
		return nullptr;
	}

	ASN1_TIME_free(validity->notBefore);
	ASN1_TIME_free(validity->notAfter);
	validity->notBefore = start_time;
	validity->notAfter = end_time;
	return validity;
}

static void _cert_tbs_release(cert_tbs_t *tbs)
{
	if (tbs == nullptr)
		return;

	ASN1_INTEGER_free(tbs->version);
	ASN1_INTEGER_free(tbs->serial);
	X509_ALGOR_free(tbs->signature);
	X509_NAME_free(tbs->issuer);
	X509_VAL_free(tbs->validity);
	X509_NAME_free(tbs->subject);
	X509_PUBKEY_free(tbs->public_key);
	sk_X509_EXTENSION_pop_free(tbs->extensions, X509_EXTENSION_free);
	osal_free(tbs);
}

static void _cert_certificate_release(cert_certificate_t *certificate)
{
	if (certificate == nullptr)
		return;

	/*
	 * container->tbs is decoded by cert_builder_assemble() with
	 * ASN1_item_d2i(), so it must be released with the OpenSSL allocator.
	 */
	if (certificate->tbs != nullptr)
		ASN1_item_free((ASN1_VALUE *) certificate->tbs,
			       ASN1_ITEM_rptr(cert_tbs_t));
	X509_ALGOR_free(certificate->signature_algorithm);
	ASN1_BIT_STRING_free(certificate->signature);
	osal_free(certificate);
}

/*
 * An issuer must still be valid and, when the issued certificate is a CA,
 * its pathLenConstraint must allow another CA below it (RFC 5280 4.2.1.9).
 */
static bool _cert_issuer_permits(const X509 *certificate, const X509 *issuer)
{
	BASIC_CONSTRAINTS *issued = nullptr;
	BASIC_CONSTRAINTS *constraints = nullptr;
	bool permits = true;

	if (!ossl_x509_valid_now(issuer)) {
		LOGE("The issuer certificate is not currently valid");
		return false;
	}

	issued = X509_get_ext_d2i(certificate, NID_basic_constraints, nullptr,
				  nullptr);
	if (issued != nullptr && issued->ca != 0) {
		constraints = X509_get_ext_d2i(issuer, NID_basic_constraints,
					      nullptr, nullptr);
		if (constraints != nullptr && constraints->pathlen != nullptr
		    && ASN1_INTEGER_get(constraints->pathlen) <= 0) {
			LOGE("The issuer pathLenConstraint does not allow a "
			     "subordinate CA");
			permits = false;
		}
	}

	BASIC_CONSTRAINTS_free(issued);
	BASIC_CONSTRAINTS_free(constraints);
	return permits;
}

static bool _cert_validate(const unsigned char *der, size_t length,
			   const X509 *issuer)
{
	X509 *certificate;
	bool ok;

	certificate = ossl_x509_load_der(der, length);
	if (certificate == nullptr)
		return false;

	if (issuer != nullptr)
		ok = ossl_x509_issued_by(certificate, issuer)
			&& _cert_issuer_permits(certificate, issuer);
	else
		ok = ossl_x509_verify_self_signature(certificate);

	X509_free(certificate);
	return ok;
}

static bool _cert_random_serial(unsigned char *serial, size_t length)
{
	bool nonzero = false;

	if (serial == nullptr || length == 0 || length > INT_MAX
	    || RAND_bytes(serial, (int) length) != 1)
		return false;
	serial[0] &= 0x7f;
	for (size_t i = 0; i < length; i++) {
		if (serial[i] != 0) {
			nonzero = true;
			break;
		}
	}
	if (!nonzero)
		serial[length - 1] = 0x01;
	return true;
}

cert_builder_t *cert_builder_new(void)
{
	return osal_calloc(1, sizeof(cert_builder_t));
}

void cert_builder_free(cert_builder_t *builder)
{
	if (builder == nullptr)
		return;

	osal_free(builder->serial);
	X509_NAME_free(builder->subject);
	X509_NAME_free(builder->issuer);
	X509_free(builder->issuer_certificate);
	X509_PUBKEY_free(builder->public_key);
	sk_X509_EXTENSION_pop_free(builder->extensions, X509_EXTENSION_free);
	osal_free(builder);
}

bool cert_builder_set_serial(cert_builder_t *builder,
			     const unsigned char *serial, size_t serial_length)
{
	unsigned char *copy = nullptr;
	bool nonzero = false;

	if (builder == nullptr)
		return false;
	if (serial == nullptr && serial_length != 0)
		return false;
	if (serial_length == 0) {
		osal_free(builder->serial);
		builder->serial = nullptr;
		builder->serial_length = 0;
		return true;
	}
	if (serial_length > CERT_MAX_SERIAL_LENGTH) {
		LOGE("The certificate serial is too long");
		return false;
	}
	if (serial_length == CERT_MAX_SERIAL_LENGTH
	    && (serial[0] & 0x80) != 0) {
		LOGE("The certificate serial is too long");
		return false;
	}
	for (size_t i = 0; i < serial_length; i++) {
		if (serial[i] != 0) {
			nonzero = true;
			break;
		}
	}
	if (!nonzero) {
		LOGE("The certificate serial must be positive");
		return false;
	}

	copy = osal_malloc(serial_length);
	if (copy == nullptr) {
		LOGE("Out of memory while copying the certificate serial");
		return false;
	}
	memcpy(copy, serial, serial_length);
	osal_free(builder->serial);
	builder->serial = copy;
	builder->serial_length = serial_length;
	return true;
}

bool cert_builder_set_subject(cert_builder_t *builder, const char *subject)
{
	X509_NAME *name;

	if (builder == nullptr || subject == nullptr)
		return false;

	name = _cert_subject_name(subject);
	if (name == nullptr)
		return false;
	X509_NAME_free(builder->subject);
	builder->subject = name;
	return true;
}

bool cert_builder_set_subject_der(cert_builder_t *builder,
				  const unsigned char *der, size_t length)
{
	X509_NAME *name;

	if (builder == nullptr)
		return false;
	if (!ossl_x509_name_decode(der, length, &name))
		return false;

	X509_NAME_free(builder->subject);
	builder->subject = name;
	return true;
}

bool cert_builder_set_issuer(cert_builder_t *builder, const char *issuer)
{
	X509_NAME *name;

	if (builder == nullptr || issuer == nullptr)
		return false;

	name = _cert_subject_name(issuer);
	if (name == nullptr)
		return false;
	X509_NAME_free(builder->issuer);
	X509_free(builder->issuer_certificate);
	builder->issuer = name;
	builder->issuer_certificate = nullptr;
	return true;
}

bool cert_builder_set_issuer_certificate(cert_builder_t *builder,
					 const unsigned char *der,
					 size_t length)
{
	X509 *certificate;
	X509_NAME *name;

	if (builder == nullptr || der == nullptr || length == 0)
		return false;

	certificate = ossl_x509_load_der(der, length);
	if (certificate == nullptr) {
		LOGE("Cannot parse the issuer certificate");
		return false;
	}
	if (X509_check_ca(certificate) <= 0) {
		LOGE("The issuer certificate is not a CA");
		X509_free(certificate);
		return false;
	}

	name = X509_NAME_dup(X509_get_subject_name(certificate));
	if (name == nullptr) {
		LOGE("Out of memory while copying the issuer name");
		X509_free(certificate);
		return false;
	}

	X509_NAME_free(builder->issuer);
	X509_free(builder->issuer_certificate);
	builder->issuer = name;
	builder->issuer_certificate = certificate;
	return true;
}

bool cert_builder_set_validity(cert_builder_t *builder, int64_t not_before,
			       uint32_t validity_days)
{
	X509_VAL *validity;

	if (builder == nullptr)
		return false;

	validity = _cert_validity(not_before, validity_days);
	if (validity == nullptr) {
		LOGE("Invalid certificate validity period");
		return false;
	}
	X509_VAL_free(validity);
	builder->not_before = not_before;
	builder->validity_days = validity_days;
	return true;
}

bool cert_builder_set_rsa_public_key(cert_builder_t *builder,
				     const unsigned char *modulus,
				     size_t modulus_length,
				     const unsigned char *exponent,
				     size_t exponent_length)
{
	X509_PUBKEY *public_key;

	if (builder == nullptr)
		return false;

	public_key = _cert_rsa_public_key(modulus, modulus_length, exponent,
					  exponent_length);
	if (public_key == nullptr) {
		LOGE("Cannot encode the RSA public key");
		return false;
	}
	X509_PUBKEY_free(builder->public_key);
	builder->public_key = public_key;
	return true;
}

bool cert_builder_set_ec_public_key(cert_builder_t *builder,
				    const unsigned char *ec_params,
				    size_t ec_params_length,
				    const unsigned char *ec_point,
				    size_t ec_point_length)
{
	X509_PUBKEY *public_key;

	if (builder == nullptr)
		return false;

	public_key = _cert_ec_public_key(ec_params, ec_params_length, ec_point,
					 ec_point_length);
	if (public_key == nullptr) {
		LOGE("Cannot encode the EC public key");
		return false;
	}
	X509_PUBKEY_free(builder->public_key);
	builder->public_key = public_key;
	return true;
}

bool cert_builder_set_ml_dsa_public_key(
	cert_builder_t *builder, cert_ml_dsa_parameter_set_t parameter_set,
	const unsigned char *key, size_t key_length)
{
	X509_ALGOR *algorithm = nullptr;
	X509_PUBKEY *public_key = nullptr;
	int nid;

	if (builder == nullptr || key == nullptr || key_length == 0)
		return false;

	switch (parameter_set) {
	case CERT_ML_DSA_44:
		nid = NID_ML_DSA_44;
		break;
	case CERT_ML_DSA_65:
		nid = NID_ML_DSA_65;
		break;
	case CERT_ML_DSA_87:
		nid = NID_ML_DSA_87;
		break;
	default:
		return false;
	}

	algorithm = X509_ALGOR_new();
	if (algorithm == nullptr
	    || X509_ALGOR_set0(algorithm, OBJ_nid2obj(nid), V_ASN1_UNDEF,
			       nullptr) != 1)
		goto done;

	/* ML-DSA SubjectPublicKeyInfo carries the raw public key bits and an
	 * algorithm OID without parameters (RFC 9881). */
	public_key = _cert_spki(algorithm, key, key_length);

done:
	X509_ALGOR_free(algorithm);
	if (public_key == nullptr) {
		LOGE("Cannot encode the ML-DSA public key");
		return false;
	}
	X509_PUBKEY_free(builder->public_key);
	builder->public_key = public_key;
	return true;
}

bool cert_builder_set_public_key_der(cert_builder_t *builder,
				     const unsigned char *der, size_t length)
{
	X509_PUBKEY *public_key;

	if (builder == nullptr)
		return false;

	public_key = nullptr;
	if (!ossl_x509_pubkey_decode(der, length, &public_key)) {
		LOGE("Cannot parse the subject public key");
		return false;
	}
	X509_PUBKEY_free(builder->public_key);
	builder->public_key = public_key;
	return true;
}

bool cert_builder_add_extension(cert_builder_t *builder, const char *oid,
				bool critical, const unsigned char *der,
				size_t length)
{
	X509_EXTENSION *extension;

	if (builder == nullptr || oid == nullptr
	    || (der == nullptr && length != 0) || length > INT_MAX)
		return false;

	extension = ossl_x509_extension_new_der(oid, critical, der, length);
	if (extension == nullptr) {
		LOGE("Cannot encode extension %s", oid);
		return false;
	}
	return ossl_x509_extension_push(&builder->extensions, extension);
}

bool cert_builder_add_subject_key_identifier(cert_builder_t *builder)
{
	X509_EXTENSION *extension;

	if (builder == nullptr || builder->public_key == nullptr) {
		LOGE("The subject public key must be set before the "
		     "subject key identifier");
		return false;
	}

	extension = ossl_x509_subject_key_identifier(builder->public_key);
	if (extension == nullptr)
		return false;
	return ossl_x509_extension_push(&builder->extensions, extension);
}

bool cert_builder_add_authority_key_identifier(cert_builder_t *builder)
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

bool cert_builder_add_basic_constraints(cert_builder_t *builder, bool is_ca,
					bool has_path_length,
					uint32_t path_length)
{
	BASIC_CONSTRAINTS *constraints = nullptr;
	X509_EXTENSION *extension = nullptr;
	bool ok = false;

	if (builder == nullptr || (has_path_length && !is_ca)) {
		LOGE("pathLenConstraint requires cA = true");
		return false;
	}

	constraints = BASIC_CONSTRAINTS_new();
	if (constraints == nullptr)
		return false;

	constraints->ca = is_ca ? 0xff : 0;
	if (has_path_length) {
		constraints->pathlen = ASN1_INTEGER_new();
		if (constraints->pathlen == nullptr
		    || ASN1_INTEGER_set_uint64(constraints->pathlen,
					       path_length)
			       != 1)
			goto done;
	}

	extension = ossl_x509_extension_new_by_nid(NID_basic_constraints, true,
						   constraints);
	if (extension == nullptr)
		goto done;
	ok = ossl_x509_extension_push(&builder->extensions, extension);
	extension = nullptr;

done:
	X509_EXTENSION_free(extension);
	BASIC_CONSTRAINTS_free(constraints);
	return ok;
}

bool cert_builder_add_key_usage(cert_builder_t *builder, uint32_t bits)
{
	ASN1_BIT_STRING *usage = nullptr;
	X509_EXTENSION *extension = nullptr;
	bool ok = false;

	if (builder == nullptr || bits == 0 || (bits & ~0x1ffU) != 0) {
		LOGE("Invalid key usage bits: 0x%x", bits);
		return false;
	}

	usage = ASN1_BIT_STRING_new();
	if (usage == nullptr)
		return false;

	for (unsigned bit = 0; bit < 9; bit++) {
		if ((bits & (1U << bit)) != 0
		    && ASN1_BIT_STRING_set_bit(usage, (int) bit, 1) != 1)
			goto done;
	}

	extension = ossl_x509_extension_new_by_nid(NID_key_usage, true,
						   usage);
	if (extension == nullptr)
		goto done;
	ok = ossl_x509_extension_push(&builder->extensions, extension);
	extension = nullptr;

done:
	X509_EXTENSION_free(extension);
	ASN1_BIT_STRING_free(usage);
	return ok;
}

bool cert_builder_add_extended_key_usage(cert_builder_t *builder,
					 const char *const *oids,
					 size_t count)
{
	EXTENDED_KEY_USAGE *usage = nullptr;
	X509_EXTENSION *extension = nullptr;
	bool ok = false;

	if (builder == nullptr || oids == nullptr || count == 0
	    || count > INT_MAX) {
		LOGE("An extended key usage needs at least one OID");
		return false;
	}

	usage = EXTENDED_KEY_USAGE_new();
	if (usage == nullptr)
		return false;

	for (size_t i = 0; i < count; i++) {
		ASN1_OBJECT *object;

		if (oids[i] == nullptr || oids[i][0] == '\0') {
			LOGE("Invalid extended key usage OID");
			goto done;
		}
		object = OBJ_txt2obj(oids[i], 0);
		if (object == nullptr) {
			LOGE("Invalid extended key usage OID: %s", oids[i]);
			goto done;
		}
		if (sk_ASN1_OBJECT_push(usage, object) <= 0) {
			ASN1_OBJECT_free(object);
			goto done;
		}
	}

	extension = ossl_x509_extension_new_by_nid(NID_ext_key_usage, false,
						   usage);
	if (extension == nullptr)
		goto done;
	ok = ossl_x509_extension_push(&builder->extensions, extension);
	extension = nullptr;

done:
	X509_EXTENSION_free(extension);
	EXTENDED_KEY_USAGE_free(usage);
	return ok;
}

/* Encode one certificate policy, including its optional CPS URI. */
static POLICYINFO *_cert_builder_policy(const cert_policy_t *policy)
{
	POLICYINFO *info = nullptr;
	ASN1_OBJECT *object = nullptr;
	POLICYQUALINFO *qualifier = nullptr;
	ASN1_IA5STRING *uri = nullptr;

	if (policy->oid == nullptr || policy->oid[0] == '\0') {
		LOGE("Invalid certificate policy OID");
		return nullptr;
	}

	object = OBJ_txt2obj(policy->oid, 0);
	if (object == nullptr) {
		LOGE("Invalid certificate policy OID: %s", policy->oid);
		return nullptr;
	}

	info = POLICYINFO_new();
	if (info == nullptr) {
		ASN1_OBJECT_free(object);
		return nullptr;
	}
	info->policyid = object;

	if (policy->cps_uri == nullptr || policy->cps_uri[0] == '\0')
		return info;

	info->qualifiers = sk_POLICYQUALINFO_new_null();
	qualifier = POLICYQUALINFO_new();
	uri = ASN1_IA5STRING_new();
	if (info->qualifiers == nullptr || qualifier == nullptr || uri == nullptr
	    || ASN1_STRING_set(uri, policy->cps_uri, -1) != 1) {
		LOGE("Cannot encode certificate policy CPS URI: %s",
		     policy->cps_uri);
		ASN1_IA5STRING_free(uri);
		POLICYQUALINFO_free(qualifier);
		POLICYINFO_free(info);
		return nullptr;
	}
	qualifier->d.cpsuri = uri;
	qualifier->pqualid = OBJ_dup(OBJ_nid2obj(NID_id_qt_cps));
	if (qualifier->pqualid == nullptr
	    || sk_POLICYQUALINFO_push(info->qualifiers, qualifier) <= 0) {
		LOGE("Cannot encode certificate policy CPS URI: %s",
		     policy->cps_uri);
		/* push() failed, so the stack does not own the qualifier. */
		POLICYQUALINFO_free(qualifier);
		POLICYINFO_free(info);
		return nullptr;
	}
	return info;
}

bool cert_builder_add_certificate_policies(cert_builder_t *builder,
					   const cert_policy_t *policies,
					   size_t count)
{
	STACK_OF(POLICYINFO) *encoded = nullptr;
	X509_EXTENSION *extension = nullptr;
	bool ok = false;

	if (builder == nullptr || policies == nullptr || count == 0
	    || count > INT_MAX) {
		LOGE("A certificate policy list needs at least one policy");
		return false;
	}

	encoded = sk_POLICYINFO_new_null();
	if (encoded == nullptr)
		return false;

	for (size_t i = 0; i < count; i++) {
		POLICYINFO *info = _cert_builder_policy(&policies[i]);

		if (info == nullptr) {
			LOGE("Cannot encode certificate policy: %s",
			     policies[i].oid != nullptr ? policies[i].oid
							: "<unset>");
			goto done;
		}
		if (sk_POLICYINFO_push(encoded, info) <= 0) {
			POLICYINFO_free(info);
			goto done;
		}
	}

	extension = ossl_x509_extension_new_by_nid(NID_certificate_policies,
						   false, encoded);
	if (extension == nullptr)
		goto done;
	ok = ossl_x509_extension_push(&builder->extensions, extension);
	extension = nullptr;

done:
	X509_EXTENSION_free(extension);
	sk_POLICYINFO_pop_free(encoded, POLICYINFO_free);
	return ok;
}

/* Encode one URI as a GeneralName of type uniformResourceIdentifier. */
static GENERAL_NAME *_cert_builder_uri_name(const char *uri)
{
	GENERAL_NAME *name = nullptr;
	ASN1_IA5STRING *value = nullptr;

	if (uri == nullptr || uri[0] == '\0') {
		LOGE("An access URI is not set");
		return nullptr;
	}

	name = GENERAL_NAME_new();
	value = ASN1_IA5STRING_new();
	if (name == nullptr || value == nullptr
	    || ASN1_STRING_set(value, uri, -1) != 1) {
		LOGE("Cannot encode access URI: %s", uri);
		GENERAL_NAME_free(name);
		ASN1_IA5STRING_free(value);
		return nullptr;
	}

	GENERAL_NAME_set0_value(name, GEN_URI, value);
	return name;
}

/* Encode a list of URIs as a GeneralNames stack. */
static GENERAL_NAMES *_cert_builder_uri_names(const char *const *uris,
					      size_t count)
{
	GENERAL_NAMES *names;

	if (count > INT_MAX) {
		LOGE("Too many access URIs");
		return nullptr;
	}

	names = sk_GENERAL_NAME_new_null();
	if (names == nullptr)
		return nullptr;

	for (size_t i = 0; i < count; i++) {
		GENERAL_NAME *name = _cert_builder_uri_name(uris[i]);

		if (name == nullptr || sk_GENERAL_NAME_push(names, name) <= 0) {
			GENERAL_NAME_free(name);
			sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
			return nullptr;
		}
	}
	return names;
}

/* Append id-ad-caIssuers or id-ad-OCSP access descriptions. */
static bool _cert_builder_append_access(AUTHORITY_INFO_ACCESS *access,
					int method_nid,
					const char *const *uris, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		ACCESS_DESCRIPTION *description = nullptr;
		GENERAL_NAME *location = nullptr;
		ASN1_OBJECT *method = nullptr;

		location = _cert_builder_uri_name(uris[i]);
		if (location == nullptr)
			return false;

		description = ACCESS_DESCRIPTION_new();
		if (description == nullptr) {
			GENERAL_NAME_free(location);
			return false;
		}

		if (OBJ_nid2obj(method_nid) == nullptr) {
			GENERAL_NAME_free(location);
			ACCESS_DESCRIPTION_free(description);
			return false;
		}
		method = OBJ_dup(OBJ_nid2obj(method_nid));
		if (method == nullptr) {
			GENERAL_NAME_free(location);
			ACCESS_DESCRIPTION_free(description);
			return false;
		}
		/* ACCESS_DESCRIPTION_new() may preallocate method; do not leak it. */
		ASN1_OBJECT_free(description->method);
		description->method = method;
		description->location = location;
		if (sk_ACCESS_DESCRIPTION_push(access, description) <= 0) {
			ACCESS_DESCRIPTION_free(description);
			return false;
		}
	}
	return true;
}

bool cert_builder_add_authority_info_access(cert_builder_t *builder,
					    const char *const *issuer_uris,
					    size_t issuer_uris_count,
					    const char *const *ocsp_uris,
					    size_t ocsp_uris_count)
{
	AUTHORITY_INFO_ACCESS *access = nullptr;
	X509_EXTENSION *extension = nullptr;
	bool ok = false;

	if (builder == nullptr
	    || (issuer_uris == nullptr && issuer_uris_count != 0)
	    || (ocsp_uris == nullptr && ocsp_uris_count != 0)) {
		LOGE("Invalid authority information access arguments");
		return false;
	}
	if (issuer_uris_count == 0 && ocsp_uris_count == 0)
		return true;

	access = sk_ACCESS_DESCRIPTION_new_null();
	if (access == nullptr)
		return false;

	if (!_cert_builder_append_access(access, NID_ad_ca_issuers,
					 issuer_uris, issuer_uris_count)
	    || !_cert_builder_append_access(access, NID_ad_OCSP, ocsp_uris,
					    ocsp_uris_count))
		goto done;

	extension = ossl_x509_extension_new_by_nid(NID_info_access, false,
						   access);
	if (extension == nullptr)
		goto done;
	ok = ossl_x509_extension_push(&builder->extensions, extension);
	extension = nullptr;

done:
	X509_EXTENSION_free(extension);
	sk_ACCESS_DESCRIPTION_pop_free(access, ACCESS_DESCRIPTION_free);
	return ok;
}

bool cert_builder_add_crl_distribution_points(cert_builder_t *builder,
					      const char *const *uris,
					      size_t count)
{
	STACK_OF(DIST_POINT) *points = nullptr;
	GENERAL_NAMES *names = nullptr;
	DIST_POINT_NAME *name = nullptr;
	DIST_POINT *point = nullptr;
	X509_EXTENSION *extension = nullptr;
	bool ok = false;

	if (builder == nullptr || (uris == nullptr && count != 0)
	    || count > INT_MAX) {
		LOGE("Invalid CRL distribution point arguments");
		return false;
	}
	if (count == 0)
		return true;

	names = _cert_builder_uri_names(uris, count);
	points = sk_DIST_POINT_new_null();
	name = DIST_POINT_NAME_new();
	point = DIST_POINT_new();
	if (names == nullptr || points == nullptr || name == nullptr
	    || point == nullptr)
		goto done;

	name->type = 0; /* fullName */
	name->name.fullname = names;
	names = nullptr;

	point->distpoint = name;
	name = nullptr;

	if (sk_DIST_POINT_push(points, point) <= 0)
		goto done;
	point = nullptr;

	extension = ossl_x509_extension_new_by_nid(
		NID_crl_distribution_points, false, points);
	if (extension == nullptr)
		goto done;
	ok = ossl_x509_extension_push(&builder->extensions, extension);
	extension = nullptr;

done:
	X509_EXTENSION_free(extension);
	DIST_POINT_free(point);
	DIST_POINT_NAME_free(name);
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
	sk_DIST_POINT_pop_free(points, DIST_POINT_free);
	return ok;
}

static cert_tbs_t *_cert_build_tbs(const cert_builder_t *builder,
				   cert_signature_scheme_t scheme,
				   cert_digest_algorithm_t digest)
{
	X509_ALGOR *signature_algorithm = nullptr;
	X509_NAME *issuer = nullptr;
	X509_VAL *validity = nullptr;
	cert_tbs_t *tbs = nullptr;
	unsigned char random_serial[CERT_RANDOM_SERIAL_LENGTH];
	const unsigned char *serial;
	size_t serial_length;

	if (builder->subject == nullptr || builder->public_key == nullptr) {
		LOGE("The certificate subject or public key is not set");
		return nullptr;
	}

	signature_algorithm = _cert_signature_algorithm(scheme, digest);
	if (signature_algorithm == nullptr) {
		LOGE("Unsupported certificate signature algorithm");
		return nullptr;
	}

	serial = builder->serial;
	serial_length = builder->serial_length;
	if (serial == nullptr || serial_length == 0) {
		if (!_cert_random_serial(random_serial, sizeof random_serial)) {
			LOGE("Cannot generate the certificate serial");
			goto done;
		}
		serial = random_serial;
		serial_length = sizeof random_serial;
	}

	validity = _cert_validity(builder->not_before,
				  builder->validity_days);
	if (validity == nullptr) {
		LOGE("Invalid certificate validity period");
		goto done;
	}

	if (builder->issuer != nullptr)
		issuer = X509_NAME_dup(builder->issuer);
	else
		issuer = X509_NAME_dup(builder->subject);
	if (issuer == nullptr) {
		LOGE("Out of memory while copying the issuer name");
		goto done;
	}

	tbs = osal_calloc(1, sizeof *tbs);
	if (tbs == nullptr) {
		LOGE("Out of memory while building the certificate");
		goto done;
	}

	tbs->version = ASN1_INTEGER_new();
	if (tbs->version == nullptr || ASN1_INTEGER_set(tbs->version, 2) != 1) {
		LOGE("Cannot encode the certificate version");
		goto done;
	}
	tbs->serial = _cert_serial_integer(serial, serial_length);
	if (tbs->serial == nullptr) {
		LOGE("The certificate serial is invalid");
		goto done;
	}
	tbs->signature = signature_algorithm;
	signature_algorithm = nullptr;
	tbs->issuer = issuer;
	issuer = nullptr;
	tbs->subject = X509_NAME_dup(builder->subject);
	if (tbs->subject == nullptr) {
		LOGE("Out of memory while copying the subject name");
		goto done;
	}
	tbs->validity = validity;
	validity = nullptr;
	tbs->public_key = _cert_public_key_copy(builder->public_key);
	if (tbs->public_key == nullptr) {
		LOGE("Out of memory while copying the public key");
		goto done;
	}

	if (builder->extensions != nullptr
	    && sk_X509_EXTENSION_num(builder->extensions) > 0) {
		tbs->extensions = ossl_x509_extension_copy_stack(
			builder->extensions);
		if (tbs->extensions == nullptr) {
			LOGE("Out of memory while copying extensions");
			goto done;
		}
	}

	return tbs;

done:
	X509_ALGOR_free(signature_algorithm);
	X509_NAME_free(issuer);
	X509_VAL_free(validity);
	_cert_tbs_release(tbs);
	return nullptr;
}

bool cert_builder_tbs(const cert_builder_t *builder,
		      cert_signature_scheme_t scheme,
		      cert_digest_algorithm_t digest, cert_blob_t *tbs_blob)
{
	cert_tbs_t *tbs;
	ossl_der_t der = { 0 };
	bool ok = false;

	if (tbs_blob == nullptr)
		return false;
	tbs_blob->data = nullptr;
	tbs_blob->length = 0;

	if (builder == nullptr)
		return false;

	tbs = _cert_build_tbs(builder, scheme, digest);
	if (tbs == nullptr)
		return false;

	if (!ossl_der_encode_item(ASN1_ITEM_rptr(cert_tbs_t), tbs, &der)) {
		LOGE("Cannot encode the TBSCertificate");
		goto done;
	}

	tbs_blob->data = der.data;
	tbs_blob->length = der.length;
	der.data = nullptr;
	der.length = 0;
	ok = true;

done:
	ossl_der_release(&der);
	_cert_tbs_release(tbs);
	return ok;
}

bool cert_builder_assemble(const cert_builder_t *builder,
			   cert_signature_scheme_t scheme,
			   cert_digest_algorithm_t digest,
			   const unsigned char *tbs_der, size_t tbs_length,
			   const unsigned char *signature,
			   size_t signature_length, cert_blob_t *certificate)
{
	const unsigned char *cursor;
	const unsigned char *signature_bytes = signature;
	size_t signature_bytes_length = signature_length;
	cert_tbs_t *tbs = nullptr;
	X509_ALGOR *signature_algorithm = nullptr;
	ASN1_BIT_STRING *asn1_signature = nullptr;
	cert_certificate_t *container = nullptr;
	ossl_der_t encoded_signature = { 0 };
	ossl_der_t certificate_der = { 0 };
	bool ok = false;

	if (certificate == nullptr)
		return false;
	certificate->data = nullptr;
	certificate->length = 0;

	if (builder == nullptr || tbs_der == nullptr || tbs_length == 0
	    || tbs_length > LONG_MAX || signature == nullptr
	    || signature_length == 0)
		return false;

	cursor = tbs_der;
	tbs = (cert_tbs_t *) ASN1_item_d2i(nullptr, &cursor, (long) tbs_length,
					   ASN1_ITEM_rptr(cert_tbs_t));
	if (tbs == nullptr || cursor != tbs_der + tbs_length) {
		LOGE("Cannot parse the TBSCertificate");
		goto done;
	}

	if (scheme == CERT_SIGNATURE_ECDSA) {
		if (!ossl_der_encode_ecdsa_signature(signature, signature_length,
						     &encoded_signature))
			goto done;
		signature_bytes = encoded_signature.data;
		signature_bytes_length = encoded_signature.length;
	} else if (scheme != CERT_SIGNATURE_RSA
		   && scheme != CERT_SIGNATURE_ML_DSA_44
		   && scheme != CERT_SIGNATURE_ML_DSA_65
		   && scheme != CERT_SIGNATURE_ML_DSA_87) {
		LOGE("Unsupported certificate signature algorithm");
		goto done;
	}

	if (signature_bytes_length > INT_MAX) {
		LOGE("Cannot encode the certificate signature");
		goto done;
	}
	asn1_signature = ossl_asn1_bit_string_from_bytes(signature_bytes,
							 signature_bytes_length);
	if (asn1_signature == nullptr) {
		LOGE("Cannot encode the certificate signature");
		goto done;
	}

	signature_algorithm = _cert_signature_algorithm(scheme, digest);
	if (signature_algorithm == nullptr) {
		LOGE("Cannot encode the outer signature algorithm");
		goto done;
	}

	container = osal_calloc(1, sizeof *container);
	if (container == nullptr) {
		LOGE("Out of memory while building the certificate");
		goto done;
	}
	container->tbs = tbs;
	tbs = nullptr;
	container->signature_algorithm = signature_algorithm;
	signature_algorithm = nullptr;
	container->signature = asn1_signature;
	asn1_signature = nullptr;

	if (!ossl_der_encode_item(ASN1_ITEM_rptr(cert_certificate_t),
				  container, &certificate_der)) {
		LOGE("Cannot encode the certificate");
		goto done;
	}
	if (!_cert_validate(certificate_der.data, certificate_der.length,
			    builder->issuer_certificate)) {
		LOGE("The generated certificate failed signature "
		     "verification");
		goto done;
	}

	certificate->data = certificate_der.data;
	certificate->length = certificate_der.length;
	certificate_der.data = nullptr;
	certificate_der.length = 0;
	ok = true;

done:
	ossl_der_release(&certificate_der);
	ossl_der_release(&encoded_signature);
	ASN1_BIT_STRING_free(asn1_signature);
	X509_ALGOR_free(signature_algorithm);
	_cert_certificate_release(container);
	/*
	 * tbs was decoded with ASN1_item_d2i() in this function, so release it
	 * with the OpenSSL allocator rather than _cert_tbs_release().
	 */
	if (tbs != nullptr)
		ASN1_item_free((ASN1_VALUE *) tbs,
			       ASN1_ITEM_rptr(cert_tbs_t));
	return ok;
}

void cert_blob_free(cert_blob_t *certificate)
{
	if (certificate == nullptr)
		return;

	osal_free(certificate->data);
	certificate->data = nullptr;
	certificate->length = 0;
}
