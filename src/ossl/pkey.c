/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <anyca/ossl/pkey.h>

/* Build a public key from a parameter builder and an algorithm name. */
static EVP_PKEY *_ossl_pkey_from_params(const char *algorithm,
					OSSL_PARAM_BLD *builder)
{
	EVP_PKEY_CTX *context;
	OSSL_PARAM *params;
	EVP_PKEY *key = nullptr;

	if (algorithm == nullptr || builder == nullptr)
		return nullptr;

	context = EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr);
	if (context == nullptr)
		return nullptr;

	params = OSSL_PARAM_BLD_to_param(builder);
	if (params != nullptr && EVP_PKEY_fromdata_init(context) == 1) {
		if (EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params)
		    != 1) {
			EVP_PKEY_free(key);
			key = nullptr;
		}
	}

	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(context);
	return key;
}

EVP_PKEY *ossl_pkey_from_rsa_public(const unsigned char *modulus,
				    size_t modulus_length,
				    const unsigned char *exponent,
				    size_t exponent_length)
{
	BIGNUM *modulus_bn = nullptr;
	BIGNUM *exponent_bn = nullptr;
	OSSL_PARAM_BLD *builder = nullptr;
	EVP_PKEY *key = nullptr;

	if (modulus == nullptr || modulus_length == 0
	    || modulus_length > INT_MAX || exponent == nullptr
	    || exponent_length == 0 || exponent_length > INT_MAX)
		return nullptr;

	modulus_bn = BN_bin2bn(modulus, (int) modulus_length, nullptr);
	exponent_bn = BN_bin2bn(exponent, (int) exponent_length, nullptr);
	if (modulus_bn == nullptr || exponent_bn == nullptr)
		goto done;

	builder = OSSL_PARAM_BLD_new();
	if (builder == nullptr)
		goto done;
	if (OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N,
				   modulus_bn) != 1
	    || OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E,
				      exponent_bn) != 1)
		goto done;

	key = _ossl_pkey_from_params("RSA", builder);

done:
	OSSL_PARAM_BLD_free(builder);
	BN_free(modulus_bn);
	BN_free(exponent_bn);
	return key;
}

EVP_PKEY *ossl_pkey_from_ec_public(const char *group,
				   const unsigned char *point,
				   size_t point_length)
{
	OSSL_PARAM_BLD *builder;
	EVP_PKEY *key = nullptr;

	if (group == nullptr || point == nullptr || point_length == 0)
		return nullptr;

	builder = OSSL_PARAM_BLD_new();
	if (builder == nullptr)
		return nullptr;
	if (OSSL_PARAM_BLD_push_utf8_string(builder,
					    OSSL_PKEY_PARAM_GROUP_NAME, group, 0)
		    == 1
	    && OSSL_PARAM_BLD_push_octet_string(builder,
						OSSL_PKEY_PARAM_PUB_KEY, point,
						point_length)
		       == 1)
		key = _ossl_pkey_from_params("EC", builder);

	OSSL_PARAM_BLD_free(builder);
	return key;
}

EVP_PKEY *ossl_pkey_from_ml_dsa_public(const char *algorithm,
				       const unsigned char *key_data,
				       size_t key_length)
{
	if (algorithm == nullptr || key_data == nullptr || key_length == 0)
		return nullptr;
	return EVP_PKEY_new_raw_public_key_ex(nullptr, algorithm, nullptr,
					      key_data, key_length);
}

bool ossl_pkey_equal(const EVP_PKEY *left, const EVP_PKEY *right)
{
	return left != nullptr && right != nullptr
	       && EVP_PKEY_eq(left, right) == 1;
}
