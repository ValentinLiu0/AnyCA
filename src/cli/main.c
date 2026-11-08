/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <anyca/core.h>
#include <anyca/osal/log.h>

#include "cli.h"

/* Help output is wrapped to this width, including the leading indent. */
#define CLI_HELP_WIDTH 80U
/* Width reserved for an option name before its description. */
#define CLI_HELP_OPTION_WIDTH 32U
/* Column where descriptions start: two spaces, the option, two spaces. */
#define CLI_HELP_DESCRIPTION_COLUMN (CLI_HELP_OPTION_WIDTH + 4U)
/* Width reserved for a command group name in the top-level command list. */
#define CLI_HELP_GROUP_WIDTH 7U
/* Width reserved for a subcommand name in group help. */
#define CLI_HELP_COMMAND_WIDTH 12U

/** One option line in a command's help. */
typedef struct cli_option_help {
	/** Option syntax, e.g. "--ca-name <name>". */
	const char *option;
	const char *description;
} cli_option_help_t;

typedef struct cli_command {
	const char *group;
	const char *name;
	/** One-line description used in command listings. */
	const char *summary;
	/** Synopsis after the command name; NULL when there are no arguments. */
	const char *usage;
	const cli_option_help_t *options;
	size_t option_count;
	/** Extra paragraphs printed after the options; '\n' separates lines. */
	const char *details;
	int (*run)(cli_global_options_t *global, int argc, char **argv,
		   int first);
} cli_command_t;

typedef struct cli_group {
	const char *name;
	/** One-line description used in the group's help. */
	const char *summary;
} cli_group_t;

static const cli_option_help_t _cli_global_options[] = {
	{ "-c, --config <path>", "configuration file (default: "
	  CONFIG_DEFAULT_PATH ")" },
	{ "-h, --help", "show this help" },
	{ "-V, --version", "show the version" },
};

static const cli_option_help_t _cli_ca_create_options[] = {
	{ "--name <name>", "CA name (required)" },
	{ "--key-uri <uri>", "CA key URI; the key pair is created in this "
	  "token (required)" },
	{ "--ocsp-key-uri <uri>", "OCSP signer key URI; the key pair is "
	  "created (required)" },
	{ "--ocsp-responder-endpoint <name>", "HTTP endpoint, no '/' (required)" },
	{ "--subject <dn>", "CA subject (default: CN=<name>)" },
	{ "--certificate-usage <name>", "certificate_usages entry "
	  "(default: ca)" },
	{ "--key-type <rsa|ec|ml-dsa-44|ml-dsa-65|ml-dsa-87>",
	  "generated key type (default: rsa)" },
	{ "--rsa-bits <n>", "RSA modulus size, 2048..16384 (default: 3072)" },
	{ "--ec-curve <p256|p384|p521>", "EC curve (default: p384)" },
	{ "--ocsp-signer-hash-algorithm <alg>", "hash algorithm for the CA "
	  "and OCSP signing certificates, sha1|sha256|sha384|sha512 "
	  "(default: sha384)" },
	{ "--crl-publish-period-min <n>", "CRL nextUpdate period "
	  "(default: 10080, 7 days)" },
	{ "--ocsp-update-period-min <n>", "OCSP nextUpdate period "
	  "(default: 10)" },
};

static const cli_option_help_t _cli_ca_import_options[] = {
	{ "--name <name>", "CA name (required)" },
	{ "--key-uri <uri>", "CA private key URI (required)" },
	{ "--in <path>", "CA certificate, DER (required)" },
	{ "--ocsp-key-uri <uri>", "OCSP signer key URI (required)" },
	{ "--ocsp-responder-endpoint <name>", "HTTP endpoint, no '/' (required)" },
	{ "--ocsp-signer-hash-algorithm <alg>", "OCSP signing hash "
	  "algorithm, sha1|sha256|sha384|sha512 (default: sha384)" },
	{ "--crl-publish-period-min <n>", "CRL nextUpdate period "
	  "(default: 10080, 7 days)" },
	{ "--ocsp-update-period-min <n>", "OCSP nextUpdate period "
	  "(default: 10)" },
};

static const cli_option_help_t _cli_ca_update_options[] = {
	{ "--ca-name <name>", "CA to update" },
	{ "--ca-id <id>", "CA id from 'ca list'" },
	{ "--key-uri <uri>", "replace the CA provider, token, PIN and key "
	  "label" },
	{ "--in <path>", "replace the stored CA certificate, DER" },
	{ "--ocsp-key-uri <uri>", "replace the OCSP signer provider, token, "
	  "PIN and key label" },
	{ "--ocsp-signer-hash-algorithm <alg>", "OCSP signing hash "
	  "algorithm, sha1|sha256|sha384|sha512" },
	{ "--crl-publish-period-min <n>", "CRL nextUpdate period in minutes" },
	{ "--ocsp-update-period-min <n>", "OCSP nextUpdate period in minutes" },
	{ "--ocsp-responder-endpoint <name>", "HTTP endpoint, no '/'" },
};

static const cli_option_help_t _cli_ca_selector_options[] = {
	{ "--ca-name <name>", "CA name from the store" },
	{ "--ca-id <id>", "CA id from 'ca list'" },
};

static const cli_option_help_t _cli_ca_publish_crl_options[] = {
	{ "--ca-name <name>", "publish one CA's CRL" },
	{ "--ca-id <id>", "publish the CRL of the CA with this id" },
};

static const cli_option_help_t _cli_ca_ocsp_renew_options[] = {
	{ "--ca-name <name>", "CA from the store" },
	{ "--ca-id <id>", "CA id from 'ca list'" },
	{ "--subject <dn>", "subject (default: CN=<CA name> OCSP Signer)" },
	{ "--days <n>", "validity in days, 1..365000 (default: 3650)" },
	{ "--ocsp-signer-hash-algorithm <alg>", "signature hash algorithm "
	  "(default: the CA's stored value, sha384 when unset)" },
	{ "--serial <hex>", "serial, at most 20 bytes (default: random)" },
	{ "--out <path>", "also write the DER certificate" },
};

static const cli_option_help_t _cli_cert_issue_options[] = {
	{ "--ca-name <name>", "issuing CA from the store" },
	{ "--ca-id <id>", "issuing CA id from 'ca list'" },
	{ "--in <path>", "PKCS #10 request, DER or PEM (required)" },
	{ "--basic", "copy only the CSR subject; build extensions from "
	  "profiles" },
	{ "--enforce", "sign the CSR and copy its requested extensions" },
	{ "--is-ca <true|false>", "basicConstraints cA (required with "
	  "--basic)" },
	{ "--path-length <n|none>", "basicConstraints pathLenConstraint "
	  "(default: none)" },
	{ "--certificate-usage <name>", "certificate_usages entry (required "
	  "with --basic)" },
	{ "--certificate-template <name>", "certificate_templates entry "
	  "supplying AIA and CRL URIs" },
	{ "--certificate-policy <name>", "certificate_policies entry "
	  "supplying policy OIDs" },
	{ "--days <n>", "validity in days, 1..365000 (default: 3650)" },
	{ "--digest <alg>", "signature digest, sha1|sha256|sha384|sha512 "
	  "(default: sha384)" },
	{ "--serial <hex>", "serial, at most 20 bytes (default: random)" },
	{ "--out <path>", "output DER certificate (required)" },
	{ "--no-aki", "do not add authorityKeyIdentifier" },
	{ "--no-ski", "do not add subjectKeyIdentifier" },
};

static const cli_option_help_t _cli_cert_new_root_options[] = {
	{ "--subject <dn>", "subject, comma or '/' separated (required)" },
	{ "--key-uri <uri>", "HSM key used for the subject and signature "
	  "(required)" },
	{ "--certificate-usage <name>", "certificate_usages entry (required)" },
	{ "--certificate-template <name>", "certificate_templates entry "
	  "supplying AIA and CRL URIs" },
	{ "--is-ca <true|false>", "basicConstraints cA (default: true)" },
	{ "--path-length <n|none>", "basicConstraints pathLenConstraint "
	  "(default: none)" },
	{ "--days <n>", "validity in days, 1..365000 (default: 3650)" },
	{ "--digest <alg>", "signature digest, sha1|sha256|sha384|sha512 "
	  "(default: sha384)" },
	{ "--serial <hex>", "serial, at most 20 bytes (default: random)" },
	{ "--out <path>", "output DER certificate (required)" },
};

static const cli_option_help_t _cli_cert_record_options[] = {
	{ "--add", "add the certificate record" },
	{ "--delete", "delete the certificate record" },
	{ "--ca-name <name>", "issuing CA from the store" },
	{ "--ca-id <id>", "issuing CA id from 'ca list'" },
	{ "--in <path>", "DER certificate; derives the CA, serial and notAfter" },
	{ "--serial <hex>", "certificate serial; 0x prefix optional" },
	{ "--not-after <time>", "notAfter as Unix time (default: 0, or the "
	  "value from --in)" },
};

static const cli_option_help_t _cli_cert_revoke_options[] = {
	{ "--add", "add the revocation record" },
	{ "--delete", "delete the revocation record" },
	{ "--ca-name <name>", "issuing CA from the store" },
	{ "--ca-id <id>", "issuing CA id from 'ca list'" },
	{ "--in <path>", "DER certificate; derives the CA and serial" },
	{ "--serial <hex>", "certificate serial; 0x prefix optional" },
	{ "--revoked-at <time>", "revocation time as Unix time (default: now)" },
	{ "--reason <n>", "RFC 5280 reasonCode, 0..10 except 7 (default: 0)" },
};

static const cli_option_help_t _cli_cert_list_options[] = {
	{ "--ca-name <name>", "CA name from the store" },
	{ "--ca-id <id>", "CA id from 'ca list'" },
	{ "--revocation", "list revocation records instead of certificates" },
	{ "--n <count>", "list the most recent <count> records" },
};

static const cli_option_help_t _cli_crl_publish_options[] = {
	{ "--ca-name <name>", "publish one CA's CRL" },
	{ "--ca-id <id>", "publish the CRL of the CA with this id" },
	{ "--all", "publish every CA's CRL" },
};

static const cli_option_help_t _cli_hsm_token_info_options[] = {
	{ "--provider <name>", "hsm_providers entry (required)" },
	{ "--token <label>", "token label (required)" },
};

static const cli_option_help_t _cli_hsm_key_list_options[] = {
	{ "--provider <name>", "hsm_providers entry (required)" },
	{ "--token <label>", "token label (required)" },
	{ "--pin-source <path>", "file with the token user PIN; logs in" },
	{ "--pin-value <pin>", "token user PIN; visible in argv" },
};

static const cli_option_help_t _cli_hsm_fetch_uri_options[] = {
	{ "--provider <name>", "hsm_providers entry (required)" },
	{ "--token <label>", "token label (required)" },
	{ "--label <key-label>", "CKA_LABEL of the key (required)" },
	{ "--pin-source <path>", "add pin-source to the URI" },
	{ "--pin-value <pin>", "add pin-value to the URI" },
};

static const cli_option_help_t _cli_hsm_search_options[] = {
	{ "--in <path>", "DER or PEM certificate, request or public key "
	  "(required)" },
	{ "--provider <name>", "hsm_providers entry (required)" },
	{ "--token <label>", "token label (required)" },
	{ "--pin-source <path>", "file with the token user PIN; logs in" },
	{ "--pin-value <pin>", "token user PIN; visible in argv" },
};

static const cli_option_help_t _cli_hsm_key_options[] = {
	{ "--key-uri <uri>", "PKCS #11 key URI (required)" },
};

static const cli_option_help_t _cli_hsm_keygen_options[] = {
	{ "--key-uri <uri>", "PKCS #11 key URI; the key pair is created in "
	  "this token (required)" },
	{ "--key-type <rsa|ec|ml-dsa-44|ml-dsa-65|ml-dsa-87>",
	  "key type (default: rsa)" },
	{ "--rsa-bits <n>", "RSA modulus size, 2048..16384 (default: 3072)" },
	{ "--ec-curve <p256|p384|p521>", "EC curve (default: p384)" },
};

static const cli_option_help_t _cli_hsm_pin_set_options[] = {
	{ "--key-uri <uri>", "PKCS #11 key URI supplying provider, token and "
	  "old PIN (required)" },
	{ "--new-pin <pin>", "new token user PIN (required)" },
};

static const cli_group_t _cli_groups[] = {
	{ "ca", "Create and manage CA configurations." },
	{ "cert", "Issue, record, revoke and list certificates." },
	{ "crl", "Build and publish certificate revocation lists." },
	{ "hsm", "Inspect and manage HSM providers, tokens and keys." },
};

#define CLI_HELP_OPTION_COUNT(options) \
	(sizeof (options) / sizeof (options)[0])

static const cli_command_t _cli_commands[] = {
	{
		.group = "ca",
		.name = "create",
		.summary = "Create a self-signed CA and its OCSP signer.",
		.usage = "[options]",
		.options = _cli_ca_create_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_ca_create_options),
		.details = "The key pairs for --key-uri and --ocsp-key-uri are "
			   "created in their tokens; the object labels must not "
			   "already exist. The OCSP signing certificate is "
			   "generated and stored with the CA.",
		.run = cli_cmd_ca_create,
	},
	{
		.group = "ca",
		.name = "import",
		.summary = "Import an existing CA certificate and its keys.",
		.usage = "[options]",
		.options = _cli_ca_import_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_ca_import_options),
		.details = "The OCSP signing certificate is generated with the CA "
			   "key and recorded as an issued certificate of the CA. "
			   "The CA key and the OCSP signer key may use different "
			   "hsm_providers entries. Use this after 'cert issue' "
			   "to register a subordinate CA certificate.",
		.run = cli_cmd_ca_import,
	},
	{
		.group = "ca",
		.name = "list",
		.summary = "List CA configurations and store identities.",
		.options = nullptr,
		.option_count = 0,
		.details = "Shows the store id and key hash of each CA's current "
			   "identity, the HSM keys (never PINs), the OCSP signer "
			   "configuration, the responder endpoint and the "
			   "publication periods.",
		.run = cli_cmd_ca_list,
	},
	{
		.group = "ca",
		.name = "update",
		.summary = "Change one or more fields of a CA configuration.",
		.usage = "(--ca-name <name> | --ca-id <id>) [field options...]",
		.options = _cli_ca_update_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_ca_update_options),
		.details = "At least one field option is required. --ca-name or "
			   "--ca-id selects the CA. Run 'ca ocsp-renew' after "
			   "changing a key. A running anyca_server reloads the "
			   "store before its next OCSP response or CRL check.",
		.run = cli_cmd_ca_update,
	},
	{
		.group = "ca",
		.name = "delete",
		.summary = "Delete a CA configuration.",
		.usage = "(--ca-name <name> | --ca-id <id>)",
		.options = _cli_ca_selector_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_ca_selector_options),
		.details = "Certificate and revocation records in the store are "
			   "kept.",
		.run = cli_cmd_ca_delete,
	},
	{
		.group = "ca",
		.name = "publish-crl",
		.summary = "Build, sign and publish one CA's CRL.",
		.usage = "(--ca-name <name> | --ca-id <id>)",
		.options = _cli_ca_publish_crl_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_ca_publish_crl_options),
		.details = "Writes "
			   "<crl_publish_path>/<CA-name>/<CA-name>.crl (DER); "
			   "the CA key must be available in its token.",
		.run = cli_cmd_ca_publish_crl,
	},
	{
		.group = "ca",
		.name = "ocsp-renew",
		.summary = "Renew a CA's OCSP signing certificate.",
		.usage = "(--ca-name <name> | --ca-id <id>) [options]",
		.options = _cli_ca_ocsp_renew_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_ca_ocsp_renew_options),
		.details = "The CA key and the OCSP signer key are read from the "
			   "stored CA configuration; an existing OCSP signing "
			   "certificate is replaced. The certificate is stored "
			   "with the CA and recorded as an issued certificate. "
			   "A running anyca_server uses it on the next OCSP "
			   "response.",
		.run = cli_cmd_ca_ocsp_renew,
	},
	{
		.group = "cert",
		.name = "issue",
		.summary = "Issue a certificate by signing a PKCS #10 request.",
		.usage = "(--ca-name <name> | --ca-id <id>) --in <path> "
			 "(--basic | --enforce) [options]",
		.options = _cli_cert_issue_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_cert_issue_options),
		.details = "One of --ca-name and --ca-id is required. --basic "
			   "copies only the CSR subject and requires --is-ca and "
			   "--certificate-usage; keyUsage and basicConstraints "
			   "are critical. --enforce signs the CSR with its "
			   "requested extensions, forcing keyUsage and "
			   "basicConstraints to be critical. Both modes add "
			   "authorityKeyIdentifier; CA certificates also receive "
			   "subjectKeyIdentifier. The certificate is written to "
			   "--out and recorded under the issuing CA in the "
			   "store.",
		.run = cli_cmd_cert_issue,
	},
	{
		.group = "cert",
		.name = "new-root",
		.summary = "Generate a self-signed root certificate.",
		.usage = "[options]",
		.options = _cli_cert_new_root_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_cert_new_root_options),
		.details = "Self-signed: --key-uri names both the subject and "
			   "signing key. The certificate is written to --out and "
			   "is not registered as a CA; use 'ca create' to create "
			   "a managed self-signed CA. A usage containing "
			   "keyCertSign requires --is-ca true.",
		.run = cli_cmd_cert_new_root,
	},
	{
		.group = "cert",
		.name = "record",
		.summary = "Add or delete an issued-certificate record.",
		.usage = "(--add | --delete) [options]",
		.options = _cli_cert_record_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_cert_record_options),
		.details = "Exactly one of --add and --delete is required. "
			   "Without --in, one of --ca-name or --ca-id, and "
			   "--serial, are required. With --in, both are optional "
			   "and derived from the certificate; when also given, "
			   "they must match it. A revoked record cannot be "
			   "deleted; delete the revocation first.",
		.run = cli_cmd_cert_record,
	},
	{
		.group = "cert",
		.name = "revoke",
		.summary = "Add or delete a certificate revocation.",
		.usage = "(--add | --delete) [options]",
		.options = _cli_cert_revoke_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_cert_revoke_options),
		.details = "Exactly one of --add and --delete is required. "
			   "Without --in, one of --ca-name or --ca-id, and "
			   "--serial, are required. With --in, both are optional "
			   "and derived from the certificate; when also given, "
			   "they must match it. --add records a placeholder "
			   "certificate record when the certificate is not "
			   "recorded; --delete removes the revocation and makes "
			   "the certificate good again.",
		.run = cli_cmd_cert_revoke,
	},
	{
		.group = "cert",
		.name = "list",
		.summary = "List certificate or revocation records of one CA.",
		.usage = "(--ca-name <name> | --ca-id <id>) [--revocation] "
			 "[--n <count>]",
		.options = _cli_cert_list_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_cert_list_options),
		.details = "One of --ca-name and --ca-id is required. "
			   "Certificate records show their revocation status; "
			   "--revocation lists revocation records instead.",
		.run = cli_cmd_cert_list,
	},
	{
		.group = "crl",
		.name = "publish",
		.summary = "Build, sign and publish CRLs.",
		.usage = "--ca-name <name> | --ca-id <id> | --all",
		.options = _cli_crl_publish_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_crl_publish_options),
		.details = "One of --ca-name, --ca-id or --all is required. "
			   "Writes "
			   "<crl_publish_path>/<CA-name>/<CA-name>.crl (DER); the "
			   "CA keys must be available in their tokens.",
		.run = cli_cmd_crl_publish,
	},
	{
		.group = "hsm",
		.name = "list",
		.summary = "List configured HSM providers.",
		.options = nullptr,
		.option_count = 0,
		.details = "Prints each hsm_providers entry with its library, "
			   "model and serial.",
		.run = cli_cmd_hsm_list,
	},
	{
		.group = "hsm",
		.name = "token-info",
		.summary = "Show information about one HSM token.",
		.usage = "--provider <name> --token <label>",
		.options = _cli_hsm_token_info_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_token_info_options),
		.details = "Opens the provider's PKCS #11 module and the named "
			   "token without logging in, then prints module and "
			   "token information.",
		.run = cli_cmd_hsm_token_info,
	},
	{
		.group = "hsm",
		.name = "key-list",
		.summary = "List the keys in one HSM token.",
		.usage = "--provider <name> --token <label> "
			 "[--pin-source <path>|--pin-value <pin>]",
		.options = _cli_hsm_key_list_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_key_list_options),
		.details = "Prints one entry per private-key or public-key "
			   "object, with its label, algorithm, type and PKCS #11 "
			   "URI. Logging in with --pin-source or --pin-value "
			   "makes private-key objects visible.",
		.run = cli_cmd_hsm_key_list,
	},
	{
		.group = "hsm",
		.name = "key-info",
		.summary = "Show the public key of one HSM key pair.",
		.usage = "--key-uri <uri>",
		.options = _cli_hsm_key_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_key_options),
		.details = "Reads the public key with the URI's object label and "
			   "prints its type, size and curve.",
		.run = cli_cmd_hsm_key_info,
	},
	{
		.group = "hsm",
		.name = "fetch-uri",
		.summary = "Print the PKCS #11 URI of one key label.",
		.usage = "--provider <name> --token <label> --label <key-label> "
			 "[--pin-source <path>|--pin-value <pin>]",
		.options = _cli_hsm_fetch_uri_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_fetch_uri_options),
		.details = "Builds a percent-encoded key URI. When --pin-source "
			   "or --pin-value is given, the URI carries the same "
			   "credential and can be used directly as --key-uri.",
		.run = cli_cmd_hsm_fetch_uri,
	},
	{
		.group = "hsm",
		.name = "search-key",
		.summary = "Find keys matching a certificate, request or key.",
		.usage = "--in <path> --provider <name> --token <label> "
			 "[--pin-source <path>|--pin-value <pin>]",
		.options = _cli_hsm_search_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_search_options),
		.details = "Reads a DER or PEM certificate, PKCS #10 request or "
			   "public key and prints the token keys whose public key "
			   "matches. The output format is the same as key-list. "
			   "Without a PIN only public-key objects are searched.",
		.run = cli_cmd_hsm_search_key,
	},
	{
		.group = "hsm",
		.name = "keygen",
		.summary = "Generate an RSA or EC key pair in a token.",
		.usage = "[options]",
		.options = _cli_hsm_keygen_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_keygen_options),
		.details = "The key pair is created in the token named by "
			   "--key-uri; the object label must not already exist.",
		.run = cli_cmd_hsm_keygen,
	},
	{
		.group = "hsm",
		.name = "keydel",
		.summary = "Delete an HSM key pair.",
		.usage = "--key-uri <uri>",
		.options = _cli_hsm_key_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_key_options),
		.details = "Destroys the private and public key objects carrying "
			   "the URI's object label. Deleting an absent key pair "
			   "succeeds.",
		.run = cli_cmd_hsm_keydel,
	},
	{
		.group = "hsm",
		.name = "pin-set",
		.summary = "Change an HSM token's user PIN.",
		.usage = "--key-uri <uri> --new-pin <pin>",
		.options = _cli_hsm_pin_set_options,
		.option_count = CLI_HELP_OPTION_COUNT(_cli_hsm_pin_set_options),
		.details = "The old PIN is read from the key URI; the token must "
			   "be logged in. Prefer pin-source in the URI over "
			   "pin-value, and note that --new-pin is visible in the "
			   "process list.",
		.run = cli_cmd_hsm_pin_set,
	},
};

static const cli_command_t *_cli_find_command(const char *group,
					      const char *name)
{
	for (size_t i = 0; i < sizeof _cli_commands / sizeof _cli_commands[0];
	     i++) {
		if (strcmp(_cli_commands[i].group, group) == 0
		    && strcmp(_cli_commands[i].name, name) == 0)
			return &_cli_commands[i];
	}
	return nullptr;
}

static const cli_group_t *_cli_find_group(const char *name)
{
	for (size_t i = 0; i < sizeof _cli_groups / sizeof _cli_groups[0]; i++) {
		if (strcmp(_cli_groups[i].name, name) == 0)
			return &_cli_groups[i];
	}
	return nullptr;
}

static bool _cli_known_group(const char *command)
{
	return _cli_find_group(command) != nullptr;
}

static void _cli_print_indent(FILE *stream, size_t count)
{
	for (size_t i = 0; i < count; i++)
		fputc(' ', stream);
}

/*
 * Print length bytes of text, wrapping at CLI_HELP_WIDTH.  The cursor is
 * expected at column; continuation lines are indented by indent.
 */
static void _cli_print_wrapped(FILE *stream, const char *text, size_t length,
			       size_t column, size_t indent)
{
	size_t position = 0;
	bool first = true;

	while (position < length) {
		size_t start;
		size_t word_length;

		while (position < length && text[position] == ' ')
			position++;
		if (position >= length)
			break;
		start = position;
		while (position < length && text[position] != ' ')
			position++;
		word_length = position - start;

		if (!first && column + 1 + word_length > CLI_HELP_WIDTH) {
			fputc('\n', stream);
			_cli_print_indent(stream, indent);
			column = indent;
			first = true;
		}
		if (!first) {
			fputc(' ', stream);
			column++;
		}
		fwrite(text + start, 1, word_length, stream);
		column += word_length;
		first = false;
	}
	fputc('\n', stream);
}

static void _cli_print_options(FILE *stream,
			       const cli_option_help_t *options, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		size_t length = strlen(options[i].option);

		if (length + 4 > CLI_HELP_DESCRIPTION_COLUMN) {
			fprintf(stream, "  %s\n", options[i].option);
			_cli_print_indent(stream, CLI_HELP_DESCRIPTION_COLUMN);
		} else {
			fprintf(stream, "  %-*s",
				(int) (CLI_HELP_DESCRIPTION_COLUMN - 2),
				options[i].option);
		}
		_cli_print_wrapped(stream, options[i].description,
				   strlen(options[i].description),
				   CLI_HELP_DESCRIPTION_COLUMN,
				   CLI_HELP_DESCRIPTION_COLUMN);
	}
}

static void _cli_print_details(FILE *stream, const char *details)
{
	const char *line = details;

	for (;;) {
		const char *end = strchr(line, '\n');
		size_t length = end != nullptr ? (size_t) (end - line)
					       : strlen(line);

		if (length == 0) {
			fputc('\n', stream);
		} else {
			_cli_print_indent(stream, 2);
			_cli_print_wrapped(stream, line, length, 2, 2);
		}
		if (end == nullptr)
			break;
		line = end + 1;
	}
}

void cli_print_version(FILE *stream)
{
	fprintf(stream, "anyca_cli %s\n", core_version());
}

void cli_usage(FILE *stream)
{
	const char *group = nullptr;

	fprintf(stream,
		"Usage:\n"
		"  anyca_cli [global options] <command> <subcommand> [options]\n"
		"  anyca_cli <command> [<subcommand>] --help\n"
		"\n"
		"Commands:\n");
	for (size_t i = 0; i < sizeof _cli_commands / sizeof _cli_commands[0];
	     i++) {
		const cli_command_t *entry = &_cli_commands[i];

		if (group != nullptr && strcmp(group, entry->group) != 0)
			fputc('\n', stream);
		group = entry->group;
		fprintf(stream, "  %-*s  %-*s  %s\n",
			(int) CLI_HELP_GROUP_WIDTH, entry->group,
			(int) CLI_HELP_COMMAND_WIDTH, entry->name,
			entry->summary);
	}
	fprintf(stream, "\nGlobal options:\n");
	_cli_print_options(stream, _cli_global_options,
			   CLI_HELP_OPTION_COUNT(_cli_global_options));
	fprintf(stream,
		"\n"
		"Run 'anyca_cli <command> --help' for a command's subcommands, "
		"or\n"
		"'anyca_cli <command> <subcommand> --help' for a subcommand's "
		"options.\n"
		"\n"
		"HSM keys are identified by an RFC 7512 PKCS #11 URI:\n"
		"  pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]\n"
		"         token=<label>;object=<label>?pin-value=<pin>\n"
		"  provider is an AnyCA extension naming an hsm_providers entry;\n"
		"  without it, model and serial select exactly one matching "
		"entry.\n"
		"  token and object are CKA_LABEL values; pin-value and "
		"pin-source\n"
		"  (query attributes) are mutually exclusive.\n"
		"\n"
		"Publish directories are set by crl_publish_path and "
		"cacerts_publish_path.\n");
}

void cli_usage_group(FILE *stream, const char *group)
{
	const cli_group_t *info = _cli_find_group(group);

	if (info == nullptr) {
		cli_usage(stream);
		return;
	}

	fprintf(stream, "Usage: anyca_cli [global options] %s <subcommand> "
		"[options]\n\n", group);
	_cli_print_indent(stream, 2);
	_cli_print_wrapped(stream, info->summary, strlen(info->summary), 2, 2);

	fprintf(stream, "\nSubcommands:\n");
	for (size_t i = 0; i < sizeof _cli_commands / sizeof _cli_commands[0];
	     i++) {
		const cli_command_t *entry = &_cli_commands[i];

		if (strcmp(entry->group, group) != 0)
			continue;
		fprintf(stream, "  %-*s  %s\n",
			(int) CLI_HELP_COMMAND_WIDTH, entry->name,
			entry->summary);
	}
	fprintf(stream,
		"\nRun 'anyca_cli %s <subcommand> --help' for the options of a "
		"subcommand.\n", group);
}

static void _cli_print_usage_line(FILE *stream, const cli_command_t *entry)
{
	int column;

	column = fprintf(stream, "Usage: anyca_cli [global options] %s %s",
			 entry->group, entry->name);
	if (entry->usage == nullptr) {
		fputc('\n', stream);
		return;
	}
	fputc(' ', stream);
	column++;
	_cli_print_wrapped(stream, entry->usage, strlen(entry->usage),
			   (size_t) column, sizeof "Usage: " - 1);
}

void cli_usage_command(FILE *stream, const char *group, const char *name)
{
	const cli_command_t *entry = _cli_find_command(group, name);

	if (entry == nullptr) {
		cli_usage(stream);
		return;
	}

	_cli_print_usage_line(stream, entry);
	fputc('\n', stream);
	_cli_print_indent(stream, 2);
	_cli_print_wrapped(stream, entry->summary, strlen(entry->summary), 2, 2);

	if (entry->option_count > 0) {
		fprintf(stream, "\nOptions:\n");
		_cli_print_options(stream, entry->options, entry->option_count);
	}
	fprintf(stream, "\nGlobal options:\n");
	_cli_print_options(stream, _cli_global_options,
			   CLI_HELP_OPTION_COUNT(_cli_global_options));

	if (entry->details != nullptr) {
		fprintf(stream, "\nNotes:\n");
		_cli_print_details(stream, entry->details);
	}
}

void cli_usage_current(FILE *stream, const cli_global_options_t *global)
{
	if (global == nullptr || global->command == nullptr) {
		cli_usage(stream);
		return;
	}
	if (global->subcommand == nullptr) {
		cli_usage_group(stream, global->command);
		return;
	}
	cli_usage_command(stream, global->command, global->subcommand);
}

int main(int argc, char **argv)
{
	cli_global_options_t global = { .config_path = CONFIG_DEFAULT_PATH };
	const cli_command_t *entry;
	const char *command;
	const char *subcommand_name;
	int index = 1;
	int status;

	osal_log_set_level(OSAL_LOG_WARN);

	while (index < argc) {
		const char *argument = argv[index];

		switch (cli_parse_global_option(argc, argv, &index, argument,
						&global)) {
		case CLI_GLOBAL_OPTION_HELP:
			cli_usage(stdout);
			return EXIT_SUCCESS;
		case CLI_GLOBAL_OPTION_VERSION:
			cli_print_version(stdout);
			return EXIT_SUCCESS;
		case CLI_GLOBAL_OPTION_ERROR:
			cli_usage(stderr);
			return EXIT_FAILURE;
		case CLI_GLOBAL_OPTION_HANDLED:
			index++;
			continue;
		case CLI_GLOBAL_OPTION_NOT_MATCHED:
			break;
		}
		break;
	}

	if (index >= argc) {
		cli_usage(stderr);
		return EXIT_FAILURE;
	}
	command = argv[index++];
	if (!_cli_known_group(command)) {
		fprintf(stderr, "anyca_cli: unknown command: %s\n", command);
		cli_usage(stderr);
		return EXIT_FAILURE;
	}

	if (index >= argc) {
		cli_usage_group(stderr, command);
		return EXIT_FAILURE;
	}
	subcommand_name = argv[index++];
	if (strcmp(subcommand_name, "-h") == 0
	    || strcmp(subcommand_name, "--help") == 0) {
		cli_usage_group(stdout, command);
		return EXIT_SUCCESS;
	}

	entry = _cli_find_command(command, subcommand_name);
	if (entry == nullptr) {
		fprintf(stderr, "anyca_cli: unknown %s subcommand: %s\n",
			command, subcommand_name);
		cli_usage_group(stderr, command);
		return EXIT_FAILURE;
	}

	global.command = command;
	global.subcommand = subcommand_name;

	status = entry->run(&global, argc, argv, index);
	if (status == CLI_EXIT_USAGE) {
		cli_usage_command(stderr, command, subcommand_name);
		return EXIT_FAILURE;
	}
	return status;
}
