/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <anyca/osal/memory.h>

#include <anyca/cert.h>
#include <anyca/config.h>

#include "cli.h"

/* Characters that must be escaped in an RFC 2253 distinguished-name value. */
static bool _cli_dn_needs_escape(unsigned char value)
{
	switch (value) {
	case ',':
	case '+':
	case '"':
	case '\\':
	case '<':
	case '>':
	case ';':
	case '=':
		return true;
	default:
		return false;
	}
}

char *cli_ocsp_signer_subject(const char *ca_name)
{
	static const char prefix[] = "CN=";
	static const char suffix[] = " OCSP Signer";
	size_t name_length;
	size_t position;
	char *subject;

	if (ca_name == nullptr || ca_name[0] == '\0')
		return nullptr;

	name_length = strlen(ca_name);
	subject = osal_malloc((sizeof prefix - 1) + name_length * 2
			      + sizeof suffix);
	if (subject == nullptr)
		return nullptr;

	memcpy(subject, prefix, sizeof prefix - 1);
	position = sizeof prefix - 1;
	for (size_t i = 0; i < name_length; i++) {
		unsigned char value = (unsigned char) ca_name[i];

		if (_cli_dn_needs_escape(value)
		    || (i == 0 && (value == '#' || value == ' ')))
			subject[position++] = '\\';
		subject[position++] = (char) value;
	}
	memcpy(subject + position, suffix, sizeof suffix);
	return subject;
}

bool cli_generate_ocsp_signer_certificate(
	const config_t *config, const char *ca_name,
	const unsigned char *issuer_certificate,
	size_t issuer_certificate_length,
	const cli_hsm_key_t *issuer_key,
	const cli_hsm_key_t *signer_key, cert_digest_algorithm_t digest,
	const char *subject, uint32_t validity_days,
	const unsigned char *serial, size_t serial_length,
	cert_blob_t *certificate)
{
	static const char *const ocsp_signing_eku[] = {
		CLI_OCSP_SIGNING_EKU,
	};
	cli_cert_options_t options = { 0 };
	const char *subject_value = subject;
	char *default_subject = nullptr;
	time_t now;
	bool ok;

	if (config == nullptr || ca_name == nullptr
	    || issuer_certificate == nullptr || issuer_certificate_length == 0
	    || issuer_key == nullptr || signer_key == nullptr
	    || certificate == nullptr)
		return false;

	if (subject_value == nullptr || subject_value[0] == '\0') {
		default_subject = cli_ocsp_signer_subject(ca_name);
		if (default_subject == nullptr) {
			fprintf(stderr, "anyca_cli: out of memory\n");
			return false;
		}
		subject_value = default_subject;
	}

	now = time(nullptr);
	options.issuer_certificate = issuer_certificate;
	options.issuer_certificate_length = issuer_certificate_length;
	options.issuer_key = *issuer_key;
	options.subject = subject_value;
	options.subject_key = *signer_key;
	/*
	 * Use the fixed OCSP signing profile instead of a certificate_usages
	 * entry: keyUsage digitalSignature and basicConstraints cA=false are
	 * critical, and the OCSPSigning EKU identifies the signer.
	 */
	options.certificate_usage = nullptr;
	options.key_usage = CERT_KU_DIGITAL_SIGNATURE;
	options.enhanced_usage_oids = ocsp_signing_eku;
	options.enhanced_usage_oids_count = 1;
	options.digest = digest;
	options.is_ca = false;
	options.serial = serial;
	options.serial_length = serial_length;
	options.validity_days = validity_days;
	/* Backdate by one hour so the certificate is immediately valid. */
	if (now != (time_t) -1 && (int64_t) now > 3600)
		options.not_before = (int64_t) now - 3600;
	else
		options.not_before = 0;

	ok = cli_generate_certificate(config, &options, certificate);
	osal_free(default_subject);
	return ok;
}
