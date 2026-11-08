/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <anyca/osal/compat.h>
#include <anyca/osal/memory.h>

#include <anyca/cert.h>
#include <anyca/config.h>
#include <anyca/hsm.h>
#include <anyca/ossl/x509.h>

#include "cli.h"

/* Map certificate_usages basic_usages names to keyUsage bits. */
static const struct {
	const char *name;
	uint32_t bit;
} _cli_key_usage_bits[] = {
	{ "digitalSignature", CERT_KU_DIGITAL_SIGNATURE },
	{ "nonRepudiation", CERT_KU_NON_REPUDIATION },
	{ "contentCommitment", CERT_KU_CONTENT_COMMITMENT },
	{ "keyEncipherment", CERT_KU_KEY_ENCIPHERMENT },
	{ "dataEncipherment", CERT_KU_DATA_ENCIPHERMENT },
	{ "keyAgreement", CERT_KU_KEY_AGREEMENT },
	{ "keyCertSign", CERT_KU_KEY_CERT_SIGN },
	{ "cRLSign", CERT_KU_CRL_SIGN },
	{ "encipherOnly", CERT_KU_ENCIPHER_ONLY },
	{ "decipherOnly", CERT_KU_DECIPHER_ONLY },
};

static bool _cli_ml_dsa_parameters(hsm_ml_dsa_parameter_set_t hsm_set,
				   cert_ml_dsa_parameter_set_t *cert_set)
{
	switch (hsm_set) {
	case HSM_ML_DSA_44:
		*cert_set = CERT_ML_DSA_44;
		return true;
	case HSM_ML_DSA_65:
		*cert_set = CERT_ML_DSA_65;
		return true;
	case HSM_ML_DSA_87:
		*cert_set = CERT_ML_DSA_87;
		return true;
	}
	return false;
}

static bool _cli_set_subject_public_key(cert_builder_t *builder,
					const hsm_public_key_t *key)
{
	cert_ml_dsa_parameter_set_t parameter_set;

	if (key->type == HSM_KEY_TYPE_RSA)
		return cert_builder_set_rsa_public_key(
			builder, key->modulus, key->modulus_length, key->exponent,
			key->exponent_length);
	if (key->type == HSM_KEY_TYPE_EC)
		return cert_builder_set_ec_public_key(
			builder, key->ec_params, key->ec_params_length,
			key->ec_point, key->ec_point_length);
	if (key->type == HSM_KEY_TYPE_ML_DSA
	    && _cli_ml_dsa_parameters(key->ml_dsa_parameter_set,
				      &parameter_set))
		return cert_builder_set_ml_dsa_public_key(
			builder, parameter_set, key->ml_dsa_key,
			key->ml_dsa_key_length);

	fprintf(stderr, "anyca_cli: unsupported HSM key type\n");
	return false;
}

static bool _cli_sign_algorithms(const hsm_public_key_t *key,
				 cert_digest_algorithm_t digest,
				 cert_signature_scheme_t *scheme,
				 hsm_sign_alg_t *hsm_algorithm)
{
	bool rsa = key->type == HSM_KEY_TYPE_RSA;

	if (key->type == HSM_KEY_TYPE_ML_DSA) {
		switch (key->ml_dsa_parameter_set) {
		case HSM_ML_DSA_44:
			*scheme = CERT_SIGNATURE_ML_DSA_44;
			*hsm_algorithm = HSM_SIGN_ML_DSA_44;
			return true;
		case HSM_ML_DSA_65:
			*scheme = CERT_SIGNATURE_ML_DSA_65;
			*hsm_algorithm = HSM_SIGN_ML_DSA_65;
			return true;
		case HSM_ML_DSA_87:
			*scheme = CERT_SIGNATURE_ML_DSA_87;
			*hsm_algorithm = HSM_SIGN_ML_DSA_87;
			return true;
		default:
			fprintf(stderr,
				"anyca_cli: unsupported ML-DSA parameter set\n");
			return false;
		}
	}

	if (!rsa && key->type != HSM_KEY_TYPE_EC) {
		fprintf(stderr, "anyca_cli: unsupported HSM key type\n");
		return false;
	}
	*scheme = rsa ? CERT_SIGNATURE_RSA : CERT_SIGNATURE_ECDSA;

	switch (digest) {
	case CERT_DIGEST_SHA1:
		*hsm_algorithm = rsa ? HSM_SIGN_RSA_PKCS1_SHA1
				     : HSM_SIGN_ECDSA_SHA1;
		return true;
	case CERT_DIGEST_SHA256:
		*hsm_algorithm = rsa ? HSM_SIGN_RSA_PKCS1_SHA256
				     : HSM_SIGN_ECDSA_SHA256;
		return true;
	case CERT_DIGEST_SHA384:
		*hsm_algorithm = rsa ? HSM_SIGN_RSA_PKCS1_SHA384
				     : HSM_SIGN_ECDSA_SHA384;
		return true;
	case CERT_DIGEST_SHA512:
		*hsm_algorithm = rsa ? HSM_SIGN_RSA_PKCS1_SHA512
				     : HSM_SIGN_ECDSA_SHA512;
		return true;
	}

	fprintf(stderr, "anyca_cli: unsupported signature digest\n");
	return false;
}

static bool _cli_random_serial(hsm_token_t *token, unsigned char *serial,
			       size_t length)
{
	hsm_status_t status;
	bool nonzero = false;

	status = hsm_random(token, serial, length);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_random", status);
		return false;
	}
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

static bool _cli_hsm_sign(hsm_token_t *token, hsm_sign_alg_t algorithm,
			  const char *key_label, const char *pin,
			  const unsigned char *data, size_t data_length,
			  unsigned char **signature,
			  size_t *signature_length)
{
	unsigned char *raw = nullptr;
	size_t raw_length = 0;
	hsm_status_t status;

	*signature = nullptr;
	*signature_length = 0;

	status = hsm_sign_with_pin(token, algorithm, key_label, pin, data,
				   data_length, nullptr, 0, &raw_length);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_sign", status);
		return false;
	}
	if (raw_length == 0 || raw_length > INT_MAX) {
		fprintf(stderr, "anyca_cli: invalid HSM signature length\n");
		return false;
	}

	raw = osal_malloc(raw_length);
	if (raw == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}

	status = hsm_sign_with_pin(token, algorithm, key_label, pin, data,
				   data_length, raw, raw_length, &raw_length);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_sign", status);
		osal_free(raw);
		return false;
	}

	*signature = raw;
	*signature_length = raw_length;
	return true;
}

static bool _cli_usage_bits(const config_certificate_usage_t *usage,
			    uint32_t *bits)
{
	const size_t mapping_count = sizeof _cli_key_usage_bits
		/ sizeof _cli_key_usage_bits[0];

	*bits = 0;
	if (usage->basic_usages_count == 0) {
		fprintf(stderr,
			"anyca_cli: certificate usage %s has no basic_usages\n",
			usage->name);
		return false;
	}

	for (unsigned i = 0; i < usage->basic_usages_count; i++) {
		const char *name = usage->basic_usages[i];
		bool found = false;

		if (name == nullptr)
			continue;
		for (size_t j = 0; j < mapping_count; j++) {
			if (strcmp(name, _cli_key_usage_bits[j].name) == 0) {
				*bits |= _cli_key_usage_bits[j].bit;
				found = true;
				break;
			}
		}
		if (!found) {
			fprintf(stderr,
				"anyca_cli: certificate usage %s contains "
				"unsupported basic usage %s\n",
				usage->name, name);
			return false;
		}
	}
	return true;
}

bool cli_generate_key_pair(const config_t *config, const cli_hsm_key_t *key,
			   const char *key_type, unsigned int rsa_bits,
			   const char *ec_curve)
{
	const config_hsm_provider_t *provider;
	cli_hsm_session_t session;
	hsm_status_t status;
	bool ok = false;

	if (config == nullptr || key == nullptr || key->hsm_provider == nullptr
	    || key->token_label == nullptr || key->pin == nullptr
	    || key->key_label == nullptr || key_type == nullptr) {
		fprintf(stderr, "anyca_cli: missing key generation parameter\n");
		return false;
	}

	provider = cli_hsm_provider_find(config, key->hsm_provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			key->hsm_provider);
		return false;
	}

	memset(&session, 0, sizeof session);
	if (!cli_hsm_session_open(&session, provider, key->token_label,
				   key->pin))
		return false;

	if (strcasecmp(key_type, "rsa") == 0) {
		status = hsm_generate_rsa_key_pair(session.token, rsa_bits,
						   key->key_label);
	} else if (strcasecmp(key_type, "ec") == 0) {
		hsm_ec_curve_t curve;

		if (ec_curve == nullptr || strcasecmp(ec_curve, "p256") == 0)
			curve = HSM_EC_CURVE_P256;
		else if (strcasecmp(ec_curve, "p384") == 0)
			curve = HSM_EC_CURVE_P384;
		else if (strcasecmp(ec_curve, "p521") == 0)
			curve = HSM_EC_CURVE_P521;
		else {
			fprintf(stderr,
				"anyca_cli: invalid --ec-curve: %s\n",
				ec_curve);
			goto done;
		}
		status = hsm_generate_ec_key_pair(session.token, curve,
						  key->key_label);
	} else if (strcasecmp(key_type, "ml-dsa-44") == 0
		   || strcasecmp(key_type, "ml-dsa-65") == 0
		   || strcasecmp(key_type, "ml-dsa-87") == 0) {
		hsm_ml_dsa_parameter_set_t parameter_set =
			strcasecmp(key_type, "ml-dsa-44") == 0
				? HSM_ML_DSA_44
			: strcasecmp(key_type, "ml-dsa-65") == 0
				? HSM_ML_DSA_65
				: HSM_ML_DSA_87;

		status = hsm_generate_ml_dsa_key_pair(session.token,
						      parameter_set,
						      key->key_label);
	} else {
		fprintf(stderr, "anyca_cli: invalid --key-type: %s\n",
			key_type);
		goto done;
	}

	if (status != HSM_OK) {
		cli_hsm_log("hsm_generate_key_pair", status);
		goto done;
	}
	ok = true;

done:
	cli_hsm_session_close(&session);
	return ok;
}

bool cli_delete_key_pair(const config_t *config, const cli_hsm_key_t *key)
{
	const config_hsm_provider_t *provider;
	cli_hsm_session_t session = { 0 };
	hsm_status_t status;
	bool ok = false;

	if (config == nullptr || key == nullptr || key->hsm_provider == nullptr
	    || key->token_label == nullptr || key->pin == nullptr
	    || key->key_label == nullptr) {
		fprintf(stderr, "anyca_cli: missing key deletion parameter\n");
		return false;
	}

	provider = cli_hsm_provider_find(config, key->hsm_provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			key->hsm_provider);
		return false;
	}

	if (!cli_hsm_session_open(&session, provider, key->token_label,
				   key->pin))
		return false;

	status = hsm_delete_key_pair(session.token, key->key_label);
	if (status != HSM_OK)
		cli_hsm_log("hsm_delete_key_pair", status);
	else
		ok = true;

	cli_hsm_session_close(&session);
	return ok;
}

bool cli_key_matches_certificate(const config_t *config,
				 const cli_hsm_key_t *key,
				 const X509 *certificate, const char *what)
{
	static const unsigned char challenge[] =
		"AnyCA key/certificate consistency check";
	const config_hsm_provider_t *provider;
	cli_hsm_session_t session = { 0 };
	hsm_public_key_t public_key = { 0 };
	hsm_sign_alg_t algorithm;
	unsigned char *signature = nullptr;
	size_t signature_length = 0;
	hsm_status_t status;
	bool matches = false;

	if (config == nullptr || key == nullptr || certificate == nullptr
	    || key->hsm_provider == nullptr || key->token_label == nullptr
	    || key->pin == nullptr || key->key_label == nullptr) {
		fprintf(stderr,
			"anyca_cli: missing key/certificate parameter\n");
		return false;
	}

	provider = cli_hsm_provider_find(config, key->hsm_provider);
	if (provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			key->hsm_provider);
		return false;
	}

	if (!cli_hsm_session_open(&session, provider, key->token_label,
				   key->pin))
		return false;

	status = hsm_get_public_key(session.token, key->key_label,
				    &public_key);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_get_public_key", status);
		goto done;
	}

	switch (public_key.type) {
	case HSM_KEY_TYPE_RSA:
		algorithm = HSM_SIGN_RSA_PKCS1_SHA256;
		break;
	case HSM_KEY_TYPE_EC:
		algorithm = HSM_SIGN_ECDSA_SHA256;
		break;
	case HSM_KEY_TYPE_ML_DSA:
		switch (public_key.ml_dsa_parameter_set) {
		case HSM_ML_DSA_44:
			algorithm = HSM_SIGN_ML_DSA_44;
			break;
		case HSM_ML_DSA_65:
			algorithm = HSM_SIGN_ML_DSA_65;
			break;
		case HSM_ML_DSA_87:
			algorithm = HSM_SIGN_ML_DSA_87;
			break;
		default:
			fprintf(stderr,
				"anyca_cli: %s key \"%s\" has an unsupported "
				"ML-DSA parameter set\n",
				what != nullptr ? what : "HSM",
				key->key_label);
			goto done;
		}
		break;
	default:
		fprintf(stderr,
			"anyca_cli: %s key \"%s\" has an unsupported type\n",
			what != nullptr ? what : "HSM", key->key_label);
		goto done;
	}
	hsm_public_key_free(&public_key);

	if (!_cli_hsm_sign(session.token, algorithm, key->key_label, key->pin,
			   challenge, sizeof challenge - 1, &signature,
			   &signature_length))
		goto done;

	matches = ossl_x509_verify_data(certificate, challenge,
					sizeof challenge - 1, signature,
					signature_length);
	if (!matches)
		fprintf(stderr,
			"anyca_cli: %s key \"%s\" does not match the certificate\n",
			what != nullptr ? what : "HSM", key->key_label);

done:
	osal_free(signature);
	hsm_public_key_free(&public_key);
	cli_hsm_session_close(&session);
	return matches;
}

bool cli_generate_certificate(const config_t *config,
			      const cli_cert_options_t *options,
			      cert_blob_t *certificate)
{
	const config_certificate_usage_t *usage = nullptr;
	const config_certificate_template_t *template = nullptr;
	const config_hsm_provider_t *issuer_provider;
	const config_hsm_provider_t *subject_provider;
	cli_hsm_key_t subject_key;
	cli_hsm_session_t session = { 0 };
	hsm_public_key_t public_key = { 0 };
	cert_signature_scheme_t cert_scheme;
	cert_digest_algorithm_t digest;
	hsm_sign_alg_t hsm_algorithm;
	unsigned char random_serial[16];
	unsigned char *signature = nullptr;
	size_t signature_length = 0;
	const char *const *enhanced_usage_oids = nullptr;
	size_t enhanced_usage_oids_count = 0;
	cert_blob_t tbs = { 0 };
	cert_builder_t *builder = nullptr;
	uint32_t key_usage;
	bool self_signed;
	hsm_status_t status;
	bool ok = false;

	if (certificate == nullptr)
		return false;
	certificate->data = nullptr;
	certificate->length = 0;

	if (config == nullptr || options == nullptr
	    || options->subject == nullptr || options->subject[0] == '\0'
	    || (options->certificate_usage == nullptr && options->key_usage == 0)
	    || options->issuer_key.hsm_provider == nullptr
	    || options->issuer_key.token_label == nullptr
	    || options->issuer_key.pin == nullptr
	    || options->issuer_key.key_label == nullptr
	    || options->subject_key.token_label == nullptr
	    || options->subject_key.pin == nullptr
	    || options->subject_key.key_label == nullptr) {
		fprintf(stderr, "anyca_cli: missing certificate parameter\n");
		return false;
	}
	self_signed = options->issuer_certificate == nullptr;
	digest = options->digest;
	if (!self_signed && options->issuer_certificate_length == 0) {
		fprintf(stderr, "anyca_cli: missing issuer certificate\n");
		return false;
	}
	if (options->has_path_length && !options->is_ca) {
		fprintf(stderr,
			"anyca_cli: --path-length requires --is-ca true\n");
		return false;
	}

	subject_key = options->subject_key;
	if (subject_key.hsm_provider == nullptr
	    || subject_key.hsm_provider[0] == '\0')
		subject_key.hsm_provider = options->issuer_key.hsm_provider;

	issuer_provider = cli_hsm_provider_find(
		config, options->issuer_key.hsm_provider);
	if (issuer_provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			options->issuer_key.hsm_provider);
		return false;
	}
	subject_provider = cli_hsm_provider_find(config,
						 subject_key.hsm_provider);
	if (subject_provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			subject_key.hsm_provider);
		return false;
	}

	if (options->certificate_usage != nullptr) {
		usage = cli_certificate_usage_find(config,
						   options->certificate_usage);
		if (usage == nullptr) {
			fprintf(stderr, "anyca_cli: unknown certificate usage: %s\n",
				options->certificate_usage);
			return false;
		}
		if (!_cli_usage_bits(usage, &key_usage))
			return false;
		enhanced_usage_oids =
			(const char *const *) usage->enhanced_usage_oids;
		enhanced_usage_oids_count = usage->enhanced_usage_oids_count;
	} else {
		key_usage = options->key_usage;
		enhanced_usage_oids = options->enhanced_usage_oids;
		enhanced_usage_oids_count = options->enhanced_usage_oids_count;
	}
	if (options->certificate_template != nullptr) {
		template = cli_certificate_template_find(
			config, options->certificate_template);
		if (template == nullptr) {
			fprintf(stderr,
				"anyca_cli: unknown certificate template: %s\n",
				options->certificate_template);
			return false;
		}
	}
	if ((key_usage & CERT_KU_KEY_CERT_SIGN) != 0 && !options->is_ca) {
		if (usage != nullptr)
			fprintf(stderr,
				"anyca_cli: certificate usage %s requires --is-ca true\n",
				usage->name);
		else
			fprintf(stderr,
				"anyca_cli: keyCertSign requires --is-ca true\n");
		return false;
	}

	builder = cert_builder_new();
	if (builder == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}
	if (!self_signed
	    && !cert_builder_set_issuer_certificate(
		    builder, options->issuer_certificate,
		    options->issuer_certificate_length))
		goto done;
	if (!cert_builder_set_subject(builder, options->subject))
		goto done;
	if (!cert_builder_set_validity(builder, options->not_before,
				       options->validity_days))
		goto done;

	memset(&session, 0, sizeof session);
	if (!cli_hsm_session_open(&session, subject_provider,
				   subject_key.token_label, subject_key.pin))
		goto done;
	status = hsm_get_public_key(session.token, subject_key.key_label,
				    &public_key);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_get_public_key", status);
		goto done;
	}
	ok = _cli_set_subject_public_key(builder, &public_key);
	hsm_public_key_free(&public_key);
	cli_hsm_session_close(&session);
	if (!ok) {
		fprintf(stderr,
			"anyca_cli: cannot encode the subject public key\n");
		goto done;
	}
	ok = false;

	if (!cert_builder_add_subject_key_identifier(builder))
		goto done;
	if (!self_signed
	    && !cert_builder_add_authority_key_identifier(builder))
		goto done;
	if (!cert_builder_add_basic_constraints(builder, options->is_ca,
						options->has_path_length,
						options->path_length))
		goto done;
	if (!cert_builder_add_key_usage(builder, key_usage))
		goto done;
	if (!self_signed && enhanced_usage_oids_count > 0
	    && !cert_builder_add_extended_key_usage(
		    builder, enhanced_usage_oids, enhanced_usage_oids_count))
		goto done;
	if (template != nullptr
	    && (!cert_builder_add_authority_info_access(
			builder,
			(const char *const *) template->aia.issuer_uris,
			template->aia.issuer_uris_count,
			(const char *const *) template->aia.ocsp_uris,
			template->aia.ocsp_uris_count)
		|| !cert_builder_add_crl_distribution_points(
			builder, (const char *const *) template->crl_uris,
			template->crl_uris_count)))
		goto done;

	if (!cli_hsm_session_open(&session, issuer_provider,
				   options->issuer_key.token_label,
				   options->issuer_key.pin))
		goto done;
	status = hsm_get_public_key(session.token,
				    options->issuer_key.key_label,
				    &public_key);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_get_public_key", status);
		goto done;
	}
	ok = _cli_sign_algorithms(&public_key, digest, &cert_scheme,
				  &hsm_algorithm);
	hsm_public_key_free(&public_key);
	if (!ok)
		goto done;
	ok = false;

	if (options->serial != nullptr && options->serial_length != 0) {
		if (!cert_builder_set_serial(builder, options->serial,
					     options->serial_length))
			goto done;
	} else {
		if (!_cli_random_serial(session.token, random_serial,
					sizeof random_serial))
			goto done;
		if (!cert_builder_set_serial(builder, random_serial,
					     sizeof random_serial))
			goto done;
	}

	if (!cert_builder_tbs(builder, cert_scheme, digest, &tbs))
		goto done;
	if (!_cli_hsm_sign(session.token, hsm_algorithm,
			   options->issuer_key.key_label,
			   options->issuer_key.pin, tbs.data, tbs.length,
			   &signature, &signature_length))
		goto done;
	if (!cert_builder_assemble(builder, cert_scheme, digest, tbs.data,
				   tbs.length, signature, signature_length,
				   certificate))
		goto done;
	ok = true;

done:
	cli_hsm_session_close(&session);
	hsm_public_key_free(&public_key);
	osal_free(signature);
	cert_blob_free(&tbs);
	cert_builder_free(builder);
	return ok;
}

typedef struct cli_csr_requested_ski {
	bool present;
	bool critical;
	const unsigned char *value;
	size_t value_length;
} cli_csr_requested_ski_t;

/*
 * Copy the requested extensions of a CSR, skipping subjectKeyIdentifier and
 * authorityKeyIdentifier.  keyUsage and basicConstraints are made critical.
 * The first requested subjectKeyIdentifier is returned in ski.
 */
static bool _cli_csr_copy_extensions(cert_builder_t *builder,
				     const cert_request_t *request,
				     cli_csr_requested_ski_t *ski)
{
	size_t count = cert_request_extension_count(request);
	const char **seen = nullptr;
	bool ok = false;

	memset(ski, 0, sizeof *ski);
	if (count == 0)
		return true;

	seen = osal_calloc(count, sizeof *seen);
	if (seen == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}

	for (size_t i = 0; i < count; i++) {
		const char *oid;
		const unsigned char *value;
		size_t value_length;
		bool critical;

		if (!cert_request_extension(request, i, &oid, &critical, &value,
					    &value_length)) {
			fprintf(stderr,
				"anyca_cli: cannot read CSR extension #%zu\n", i);
			goto done;
		}

		if (strcmp(oid, "2.5.29.14") == 0) {
			if (ski->present) {
				fprintf(stderr,
					"anyca_cli: duplicate subjectKeyIdentifier in CSR\n");
				goto done;
			}
			ski->present = true;
			ski->critical = critical;
			ski->value = value;
			ski->value_length = value_length;
			continue;
		}
		if (strcmp(oid, "2.5.29.35") == 0)
			continue;

		for (size_t j = 0; j < i; j++) {
			if (seen[j] != nullptr && strcmp(seen[j], oid) == 0) {
				fprintf(stderr,
					"anyca_cli: duplicate %s extension in CSR\n",
					oid);
				goto done;
			}
		}
		seen[i] = oid;

		if (strcmp(oid, "2.5.29.15") == 0
		    || strcmp(oid, "2.5.29.19") == 0)
			critical = true;
		if (!cert_builder_add_extension(builder, oid, critical, value,
						value_length)) {
			fprintf(stderr,
				"anyca_cli: cannot copy CSR extension %s\n", oid);
			goto done;
		}
	}
	ok = true;

done:
	osal_free(seen);
	return ok;
}

static bool _cli_csr_add_policy(cert_builder_t *builder,
				const config_certificate_policy_t *policy)
{
	cert_policy_t *policies = nullptr;
	bool ok = false;

	if (policy->cps_count == 0 || policy->cps == nullptr) {
		fprintf(stderr,
			"anyca_cli: certificate policy %s has no cps entries\n",
			policy->name != nullptr ? policy->name : "<unset>");
		return false;
	}

	policies = osal_calloc(policy->cps_count, sizeof *policies);
	if (policies == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}

	for (unsigned i = 0; i < policy->cps_count; i++) {
		if (policy->cps[i].oid == nullptr || policy->cps[i].oid[0] == '\0') {
			fprintf(stderr,
				"anyca_cli: certificate policy %s has an empty OID\n",
				policy->name != nullptr ? policy->name : "<unset>");
			goto done;
		}
		policies[i].oid = policy->cps[i].oid;
		policies[i].cps_uri = policy->cps[i].uri;
	}

	ok = cert_builder_add_certificate_policies(builder, policies,
						   policy->cps_count);
	if (!ok) {
		fprintf(stderr,
			"anyca_cli: cannot add certificate policy %s\n",
			policy->name != nullptr ? policy->name : "<unset>");
	}

done:
	osal_free(policies);
	return ok;
}

bool cli_sign_certificate_request(const config_t *config,
				  const cli_csr_sign_options_t *options,
				  cert_blob_t *certificate)
{
	const config_certificate_usage_t *usage = nullptr;
	const config_certificate_template_t *template = nullptr;
	const config_certificate_policy_t *policy = nullptr;
	const config_hsm_provider_t *issuer_provider;
	cli_hsm_session_t session = { 0 };
	cli_csr_requested_ski_t requested_ski;
	hsm_public_key_t public_key = { 0 };
	cert_signature_scheme_t cert_scheme;
	cert_digest_algorithm_t digest;
	hsm_sign_alg_t hsm_algorithm;
	unsigned char random_serial[16];
	unsigned char *signature = nullptr;
	size_t signature_length = 0;
	cert_blob_t tbs = { 0 };
	cert_builder_t *builder = nullptr;
	uint32_t key_usage = 0;
	bool is_ca;
	hsm_status_t status;
	bool ok = false;

	if (certificate == nullptr)
		return false;
	certificate->data = nullptr;
	certificate->length = 0;

	if (config == nullptr || options == nullptr || options->request == nullptr
	    || options->issuer_certificate == nullptr
	    || options->issuer_certificate_length == 0
	    || options->issuer_key.hsm_provider == nullptr
	    || options->issuer_key.token_label == nullptr
	    || options->issuer_key.pin == nullptr
	    || options->issuer_key.key_label == nullptr) {
		fprintf(stderr, "anyca_cli: missing certificate parameter\n");
		return false;
	}
	if (options->has_path_length && !options->is_ca) {
		fprintf(stderr,
			"anyca_cli: --path-length requires --is-ca true\n");
		return false;
	}

	if (options->basic) {
		if (options->certificate_usage == nullptr) {
			fprintf(stderr,
				"anyca_cli: --certificate-usage is required\n");
			return false;
		}
		usage = cli_certificate_usage_find(config,
						   options->certificate_usage);
		if (usage == nullptr) {
			fprintf(stderr,
				"anyca_cli: unknown certificate usage: %s\n",
				options->certificate_usage);
			return false;
		}
		if (options->certificate_template != nullptr) {
			template = cli_certificate_template_find(
				config, options->certificate_template);
			if (template == nullptr) {
				fprintf(stderr,
					"anyca_cli: unknown certificate template: %s\n",
					options->certificate_template);
				return false;
			}
		}
		if (options->certificate_policy != nullptr) {
			policy = cli_certificate_policy_find(
				config, options->certificate_policy);
			if (policy == nullptr) {
				fprintf(stderr,
					"anyca_cli: unknown certificate policy: %s\n",
					options->certificate_policy);
				return false;
			}
		}
		if (!_cli_usage_bits(usage, &key_usage))
			return false;
		if ((key_usage & CERT_KU_KEY_CERT_SIGN) != 0
		    && !options->is_ca) {
			fprintf(stderr,
				"anyca_cli: certificate usage %s requires "
				"--is-ca true\n",
				usage->name);
			return false;
		}
	}

	builder = cert_builder_new();
	if (builder == nullptr) {
		fprintf(stderr, "anyca_cli: out of memory\n");
		return false;
	}
	if (!cert_builder_set_issuer_certificate(
		    builder, options->issuer_certificate,
		    options->issuer_certificate_length))
		goto done;
	if (!cert_request_set_subject(options->request, builder))
		goto done;
	if (!cert_request_set_public_key(options->request, builder))
		goto done;
	if (!cert_builder_set_validity(builder, options->not_before,
				       options->validity_days))
		goto done;

	if (options->basic) {
		is_ca = options->is_ca;
		if (is_ca && options->add_ski
		    && !cert_builder_add_subject_key_identifier(builder))
			goto done;
		if (options->add_aki
		    && !cert_builder_add_authority_key_identifier(builder))
			goto done;
		if (!cert_builder_add_basic_constraints(
			    builder, is_ca, options->has_path_length,
			    options->path_length))
			goto done;
		if (!cert_builder_add_key_usage(builder, key_usage))
			goto done;
		if (usage->enhanced_usage_oids_count > 0
		    && !cert_builder_add_extended_key_usage(
			    builder,
			    (const char *const *) usage->enhanced_usage_oids,
			    usage->enhanced_usage_oids_count))
			goto done;
		if (policy != nullptr && !_cli_csr_add_policy(builder, policy))
			goto done;
		if (template != nullptr
		    && (!cert_builder_add_authority_info_access(
				builder,
				(const char *const *) template->aia.issuer_uris,
				template->aia.issuer_uris_count,
				(const char *const *) template->aia.ocsp_uris,
				template->aia.ocsp_uris_count)
			|| !cert_builder_add_crl_distribution_points(
				builder, (const char *const *) template->crl_uris,
				template->crl_uris_count)))
			goto done;
	} else {
		bool present;

		if (!cert_request_is_ca(options->request, &present, &is_ca))
			goto done;
		if (is_ca && options->add_ski
		    && !cert_builder_add_subject_key_identifier(builder))
			goto done;
		if (options->add_aki
		    && !cert_builder_add_authority_key_identifier(builder))
			goto done;
		if (!_cli_csr_copy_extensions(builder, options->request,
					      &requested_ski))
			goto done;
		if (!is_ca && options->add_ski && requested_ski.present
		    && !cert_builder_add_extension(
			    builder, "2.5.29.14", requested_ski.critical,
			    requested_ski.value, requested_ski.value_length))
			goto done;
	}

	issuer_provider = cli_hsm_provider_find(
		config, options->issuer_key.hsm_provider);
	if (issuer_provider == nullptr) {
		fprintf(stderr, "anyca_cli: unknown HSM provider: %s\n",
			options->issuer_key.hsm_provider);
		goto done;
	}

	memset(&session, 0, sizeof session);
	if (!cli_hsm_session_open(&session, issuer_provider,
				   options->issuer_key.token_label,
				   options->issuer_key.pin))
		goto done;
	status = hsm_get_public_key(session.token,
				    options->issuer_key.key_label, &public_key);
	if (status != HSM_OK) {
		cli_hsm_log("hsm_get_public_key", status);
		goto done;
	}
	digest = options->digest;
	ok = _cli_sign_algorithms(&public_key, digest, &cert_scheme,
				  &hsm_algorithm);
	hsm_public_key_free(&public_key);
	if (!ok)
		goto done;
	ok = false;

	if (options->serial != nullptr && options->serial_length != 0) {
		if (!cert_builder_set_serial(builder, options->serial,
					     options->serial_length))
			goto done;
	} else {
		if (!_cli_random_serial(session.token, random_serial,
					sizeof random_serial))
			goto done;
		if (!cert_builder_set_serial(builder, random_serial,
					     sizeof random_serial))
			goto done;
	}

	if (!cert_builder_tbs(builder, cert_scheme, digest, &tbs))
		goto done;
	if (!_cli_hsm_sign(session.token, hsm_algorithm,
			   options->issuer_key.key_label,
			   options->issuer_key.pin, tbs.data, tbs.length,
			   &signature, &signature_length))
		goto done;
	if (!cert_builder_assemble(builder, cert_scheme, digest, tbs.data,
				   tbs.length, signature, signature_length,
				   certificate))
		goto done;
	ok = true;

done:
	cli_hsm_session_close(&session);
	hsm_public_key_free(&public_key);
	osal_free(signature);
	cert_blob_free(&tbs);
	cert_builder_free(builder);
	return ok;
}
