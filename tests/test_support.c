/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/x509v3.h>

#include <anyca/osal/file.h>

#include "test_support.h"

bool test_softhsm_available(void)
{
	if (access(TEST_SOFTHSM_MODULE, R_OK) != 0)
		return false;
	return system("command -v softhsm2-util >/dev/null 2>&1") == 0;
}

bool test_softhsm_init_token(char *directory, size_t directory_size,
			     char *conf_path, size_t conf_path_size)
{
	char tokens[PATH_MAX];
	char conf[PATH_MAX + 128];
	char command[PATH_MAX + 128];
	char *temp = test_temp_dir();
	int written;

	if (temp == NULL)
		return false;
	snprintf(directory, directory_size, "%s", temp);
	free(temp);

	snprintf(tokens, sizeof tokens, "%s/tokens", directory);
	if (!osal_file_make_dirs(tokens))
		return false;

	snprintf(conf, sizeof conf,
		 "directories.tokendir = %s\n"
		 "objectstore.backend = file\n"
		 "log.level = ERROR\n"
		 "slots.removable = false\n",
		 tokens);
	snprintf(conf_path, conf_path_size, "%s/softhsm2.conf", directory);
	if (!test_write_file(conf_path, conf, strlen(conf)))
		return false;
	if (setenv("SOFTHSM2_CONF", conf_path, 1) != 0)
		return false;

	written = snprintf(command, sizeof command,
			   "softhsm2-util --init-token --free --label %s "
			   "--so-pin 1234 --pin %s >/dev/null 2>&1",
			   TEST_SOFTHSM_TOKEN_LABEL, TEST_SOFTHSM_PIN);
	if (written < 0 || (size_t) written >= sizeof command)
		return false;
	return system(command) == 0;
}

bool test_softhsm_import_key(const char *pem_path, const char *label,
			     const char *id)
{
	char command[PATH_MAX * 2];
	int written;

	written = snprintf(command, sizeof command,
			   "softhsm2-util --import %s --token %s --label %s "
			   "--id %s --pin %s >/dev/null 2>&1",
			   pem_path, TEST_SOFTHSM_TOKEN_LABEL, label, id,
			   TEST_SOFTHSM_PIN);
	if (written < 0 || (size_t) written >= sizeof command)
		return false;
	return system(command) == 0;
}

EVP_PKEY *test_rsa_key(void)
{
	return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
}

EVP_PKEY *test_ec_key(void)
{
	return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
}

static bool add_extension(X509 *certificate, int nid, const char *value)
{
	X509_EXTENSION *extension =
		X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	bool ok = extension != NULL
		&& X509_add_ext(certificate, extension, -1) == 1;

	X509_EXTENSION_free(extension);
	return ok;
}

X509 *test_certificate(EVP_PKEY *subject_key, X509 *issuer,
		       EVP_PKEY *issuer_key, long serial, unsigned flags)
{
	X509 *certificate = X509_new();
	X509_NAME *name;
	bool ok;

	if (certificate == NULL)
		return NULL;

	ok = X509_set_version(certificate, 2) == 1
		&& ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial)
			   == 1
		&& X509_gmtime_adj(X509_getm_notBefore(certificate), -60)
			   != NULL
		&& X509_gmtime_adj(X509_getm_notAfter(certificate), 3600)
			   != NULL
		&& X509_set_pubkey(certificate, subject_key) == 1;

	name = X509_get_subject_name(certificate);
	ok = ok
		&& X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					      (const unsigned char *)
						      "AnyCA Test",
					      -1, -1, 0)
			   == 1
		&& X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
					      (const unsigned char *)
						      "AnyCA",
					      -1, -1, 0)
			   == 1
		&& X509_set_issuer_name(
			   certificate,
			   issuer != NULL ? X509_get_subject_name(issuer)
					  : name)
			   == 1;

	ok = ok
		&& add_extension(certificate, NID_basic_constraints,
				 (flags & TEST_CERT_CA) != 0
					 ? "critical,CA:TRUE"
					 : "critical,CA:FALSE");
	if ((flags & TEST_CERT_CA) != 0) {
		ok = ok
			&& add_extension(certificate, NID_key_usage,
					 "critical,keyCertSign,cRLSign");
	} else if ((flags & TEST_CERT_OCSP_SIGNER) != 0) {
		ok = ok
			&& add_extension(certificate, NID_key_usage,
					 "critical,digitalSignature")
			&& add_extension(certificate, NID_ext_key_usage,
					 "OCSPSigning");
	} else {
		ok = ok
			&& add_extension(certificate, NID_key_usage,
					 "critical,digitalSignature");
	}

	ok = ok
		&& X509_sign(certificate,
			     issuer != NULL ? issuer_key : subject_key,
			     EVP_sha256())
			   > 0;
	if (!ok) {
		X509_free(certificate);
		return NULL;
	}
	return certificate;
}

unsigned char *test_cert_der(X509 *certificate, size_t *length)
{
	unsigned char *der = NULL;
	int size = i2d_X509(certificate, &der);

	if (size <= 0)
		return NULL;
	*length = (size_t) size;
	return der;
}

unsigned char *test_spki_der(EVP_PKEY *key, size_t *length)
{
	unsigned char *der = NULL;
	int size = i2d_PUBKEY(key, &der);

	if (size <= 0)
		return NULL;
	*length = (size_t) size;
	return der;
}

bool test_sign(EVP_PKEY *key, const unsigned char *data, size_t length,
	       unsigned char **signature, size_t *signature_length)
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned char *buffer = NULL;
	size_t size = 0;
	bool ok = false;

	if (context == NULL)
		return false;
	if (EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key) != 1)
		goto done;
	if (EVP_DigestSign(context, NULL, &size, data, length) != 1)
		goto done;
	buffer = OPENSSL_malloc(size);
	if (buffer == NULL)
		goto done;
	if (EVP_DigestSign(context, buffer, &size, data, length) != 1)
		goto done;

	*signature = buffer;
	*signature_length = size;
	buffer = NULL;
	ok = true;

done:
	OPENSSL_free(buffer);
	EVP_MD_CTX_free(context);
	return ok;
}

char *test_temp_dir(void)
{
	char template[] = "/tmp/anyca_test_XXXXXX";
	char *dir = mkdtemp(template);

	return dir != NULL ? strdup(dir) : NULL;
}

void test_remove_tree(const char *path)
{
	struct stat status;

	if (lstat(path, &status) != 0)
		return;
	if (!S_ISDIR(status.st_mode)) {
		(void) unlink(path);
		return;
	}

	DIR *directory = opendir(path);
	if (directory != NULL) {
		struct dirent *entry;

		while ((entry = readdir(directory)) != NULL) {
			char *child;
			size_t length;

			if (strcmp(entry->d_name, ".") == 0
			    || strcmp(entry->d_name, "..") == 0)
				continue;
			length = strlen(path) + strlen(entry->d_name) + 2;
			child = malloc(length);
			if (child == NULL)
				continue;
			snprintf(child, length, "%s/%s", path,
				 entry->d_name);
			test_remove_tree(child);
			free(child);
		}
		closedir(directory);
	}
	(void) rmdir(path);
}

bool test_write_file(const char *path, const void *data, size_t length)
{
	FILE *file = fopen(path, "wb");
	bool ok;

	if (file == NULL)
		return false;
	ok = length == 0 || fwrite(data, 1, length, file) == length;
	ok = fclose(file) == 0 && ok;
	return ok;
}
