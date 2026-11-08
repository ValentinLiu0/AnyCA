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

#include <anyca/cert.h>
#include <anyca/ossl/der.h>
#include <anyca/ossl/x509.h>

/** Requested extension whose data remains owned by the X509_REQ. */
typedef struct cert_request_extension_info {
	char *oid;
	bool critical;
	const unsigned char *value;
	size_t value_length;
} cert_request_extension_info_t;

struct cert_request {
	X509_REQ *request;
	/** Owns the extension values referenced by extensions[]. */
	STACK_OF(X509_EXTENSION) *extension_stack;
	cert_request_extension_info_t *extensions;
	size_t extension_count;
};

static bool _cert_request_collect_extensions(cert_request_t *request)
{
	STACK_OF(X509_EXTENSION) *extensions;
	int attribute;
	int count;

	/* Distinguish "no requested extensions" from a decode error. */
	attribute = X509_REQ_get_attr_by_NID(request->request, NID_ext_req,
					     -1);
	if (attribute == -1) {
		/*
		 * Some Windows tools use the Microsoft extensionRequest OID;
		 * X509_REQ_get_extensions() accepts it as well.
		 */
		attribute = X509_REQ_get_attr_by_NID(
			request->request, NID_ms_ext_req, -1);
	}
	if (attribute == -1)
		return true;
	if (attribute < 0) {
		LOGE("Cannot read the certificate request extensions");
		return false;
	}

	extensions = X509_REQ_get_extensions(request->request);
	if (extensions == nullptr) {
		LOGE("Cannot parse the certificate request extensions");
		return false;
	}

	count = sk_X509_EXTENSION_num(extensions);
	if (count == 0) {
		sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
		return true;
	}
	if (count < 0) {
		sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
		return false;
	}

	request->extensions = osal_calloc((size_t) count,
					  sizeof *request->extensions);
	if (request->extensions == nullptr) {
		sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
		LOGE("Out of memory while reading the certificate request");
		return false;
	}

	for (int i = 0; i < count; i++) {
		cert_request_extension_info_t *info = &request->extensions[i];
		X509_EXTENSION *extension =
			sk_X509_EXTENSION_value(extensions, i);

		/* Count the slot now so cert_request_free() releases its OID. */
		request->extension_count++;
		info->oid = ossl_x509_extension_oid(extension);
		if (info->oid == nullptr)
			goto fail;
		if (!ossl_x509_extension_data(extension, &info->critical,
					      &info->value,
					      &info->value_length))
			goto fail;
	}

	/* Keep the stack: extension values point into these objects. */
	request->extension_stack = extensions;
	return true;

fail:
	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	return false;
}

cert_request_t *cert_request_load_file(const char *path)
{
	cert_request_t *request;

	if (path == nullptr)
		return nullptr;

	request = osal_calloc(1, sizeof *request);
	if (request == nullptr) {
		LOGE("Out of memory while reading the certificate request");
		return nullptr;
	}

	request->request = ossl_x509_req_load_file(path);
	if (request->request == nullptr) {
		LOGE("Cannot parse the certificate request: %s", path);
		goto fail;
	}
	if (X509_REQ_get_version(request->request) != 0) {
		LOGE("Unsupported certificate request version");
		goto fail;
	}

	if (!ossl_x509_req_verify_self(request->request)) {
		LOGE("The certificate request signature is invalid");
		goto fail;
	}

	if (!_cert_request_collect_extensions(request))
		goto fail;
	return request;

fail:
	cert_request_free(request);
	return nullptr;
}

void cert_request_free(cert_request_t *request)
{
	if (request == nullptr)
		return;

	for (size_t i = 0; i < request->extension_count; i++)
		osal_free(request->extensions[i].oid);
	osal_free(request->extensions);
	if (request->extension_stack != nullptr)
		sk_X509_EXTENSION_pop_free(request->extension_stack,
					   X509_EXTENSION_free);
	X509_REQ_free(request->request);
	osal_free(request);
}

bool cert_request_set_subject(const cert_request_t *request,
			      cert_builder_t *builder)
{
	const X509_NAME *name;
	ossl_der_t der = { 0 };
	bool ok;

	if (request == nullptr || request->request == nullptr
	    || builder == nullptr)
		return false;

	name = X509_REQ_get_subject_name(request->request);
	if (name == nullptr || !ossl_x509_name_encode(name, &der))
		return false;

	ok = cert_builder_set_subject_der(builder, der.data, der.length);
	if (!ok)
		LOGE("Cannot set the certificate subject");
	ossl_der_release(&der);
	return ok;
}

bool cert_request_set_public_key(const cert_request_t *request,
				 cert_builder_t *builder)
{
	EVP_PKEY *public_key;
	ossl_der_t der = { 0 };
	bool ok;

	if (request == nullptr || request->request == nullptr
	    || builder == nullptr)
		return false;

	public_key = X509_REQ_get0_pubkey(request->request);
	if (public_key == nullptr || !ossl_x509_spki_encode(public_key, &der))
		return false;

	ok = cert_builder_set_public_key_der(builder, der.data, der.length);
	if (!ok)
		LOGE("Cannot set the certificate public key");
	ossl_der_release(&der);
	return ok;
}

bool cert_request_is_ca(const cert_request_t *request, bool *present,
			bool *is_ca)
{
	const cert_request_extension_info_t *info = nullptr;

	if (request == nullptr || present == nullptr || is_ca == nullptr)
		return false;

	*present = false;
	*is_ca = false;
	for (size_t i = 0; i < request->extension_count; i++) {
		const cert_request_extension_info_t *candidate =
			&request->extensions[i];

		if (strcmp(candidate->oid, "2.5.29.19") != 0)
			continue;
		if (info != nullptr) {
			LOGE("The certificate request contains duplicate "
			     "basicConstraints");
			return false;
		}
		info = candidate;
	}
	if (info == nullptr)
		return true;

	BASIC_CONSTRAINTS *constraints;
	void *decoded = nullptr;

	if (!ossl_der_decode_item(ASN1_ITEM_rptr(BASIC_CONSTRAINTS),
				  info->value, info->value_length,
				  &decoded)) {
		LOGE("The certificate request contains malformed basicConstraints");
		return false;
	}
	constraints = (BASIC_CONSTRAINTS *) decoded;

	*present = true;
	*is_ca = constraints->ca != 0;
	BASIC_CONSTRAINTS_free(constraints);
	return true;
}

size_t cert_request_extension_count(const cert_request_t *request)
{
	return request != nullptr ? request->extension_count : 0;
}

bool cert_request_extension(const cert_request_t *request, size_t index,
			    const char **oid, bool *critical,
			    const unsigned char **value, size_t *value_length)
{
	const cert_request_extension_info_t *info;

	if (request == nullptr || index >= request->extension_count
	    || oid == nullptr || critical == nullptr || value == nullptr
	    || value_length == nullptr)
		return false;

	info = &request->extensions[index];
	*oid = info->oid;
	*critical = info->critical;
	*value = info->value;
	*value_length = info->value_length;
	return true;
}
