# AnyCA CLI

`anyca_cli` is the command-line tool for AnyCA. It manages CA configurations,
issued-certificate records and revocations in the AnyCA store, publishes DER
CRLs, issues DER certificates from PKCS #10 requests, and inspects and manages
HSM tokens and keys. The CLI only reads public keys and requests signatures
through the configured HSM provider.

For end-to-end deployment steps, including SoftHSM setup, importing an existing
CA and importing keys into SoftHSM, see [DEPLOY.md](DEPLOY.md).

## Overview

A typical deployment follows these steps:

1. Configure `store.path` and at least one `hsm_providers` entry in the YAML
   configuration (default: `config.yaml`, selected with `--config`).
2. Register a CA with `ca create`, which generates the CA and OCSP key pairs
   in their tokens, or with `ca import`, which uses existing keys. The CA
   certificate, key URIs, PINs, periods and OCSP endpoint are stored in
   SQLite.
3. Issue certificates by signing PKCS #10 requests with `cert issue`, or
   generate a standalone self-signed root certificate with `cert new-root`.
   Renew a CA's OCSP signing certificate with `ca ocsp-renew`. Issued
   certificates are recorded automatically; the CLI reads the subject public
   key and asks the HSM to sign, so private keys never leave the token.
4. Revoke certificates with `cert revoke --add`; remove revocations with
   `cert revoke --delete`. `cert record` adds or removes issued-certificate
   records manually, and `cert list` shows both kinds of record.
5. Publish DER CRLs with `ca publish-crl` or `crl publish`. The server
   publishes CA certificates and CRLs at start-up.
6. Run `anyca_server` to serve OCSP responses for the registered CAs.

Commands that change or read the store require `store.path`: every `ca` and
`crl` command, and every `cert` command except `cert new-root`. `cert new-root`
and the `hsm` commands only need the configuration. A running
`anyca_server` reloads the CA configuration when the store changes, so
configuration changes take effect on its next OCSP response or CRL check
without a restart.

## Synopsis

```text
anyca_cli [--config <path>] ca create [options]
anyca_cli [--config <path>] ca import [options]
anyca_cli [--config <path>] ca list
anyca_cli [--config <path>] ca update (--ca-name <name>|--ca-id <id>) [field options...]
anyca_cli [--config <path>] ca delete (--ca-name <name>|--ca-id <id>)
anyca_cli [--config <path>] ca publish-crl (--ca-name <name>|--ca-id <id>)
anyca_cli [--config <path>] ca ocsp-renew (--ca-name <name>|--ca-id <id>) [options]
anyca_cli [--config <path>] cert issue (--ca-name <name>|--ca-id <id>) --in <path> (--basic|--enforce) [options]
anyca_cli [--config <path>] cert new-root [options]
anyca_cli [--config <path>] cert record (--add|--delete) [options]
anyca_cli [--config <path>] cert revoke (--add|--delete) [options]
anyca_cli [--config <path>] cert list (--ca-name <name>|--ca-id <id>) [--revocation] [--n <count>]
anyca_cli [--config <path>] crl publish (--ca-name <name>|--ca-id <id>|--all)
anyca_cli [--config <path>] hsm list
anyca_cli [--config <path>] hsm token-info --provider <name> --token <label>
anyca_cli [--config <path>] hsm key-list --provider <name> --token <label> [--pin-source <path>|--pin-value <pin>]
anyca_cli [--config <path>] hsm key-info --key-uri <uri>
anyca_cli [--config <path>] hsm fetch-uri --provider <name> --token <label> --label <key-label> [--pin-source <path>|--pin-value <pin>]
anyca_cli [--config <path>] hsm search-key --in <path> --provider <name> --token <label> [--pin-source <path>|--pin-value <pin>]
anyca_cli [--config <path>] hsm keygen [options]
anyca_cli [--config <path>] hsm keydel --key-uri <uri>
anyca_cli [--config <path>] hsm pin-set --key-uri <uri> --new-pin <pin>
```

Global options may appear before or after the command name.

## Global options

| Option | Description |
| --- | --- |
| `-c, --config <path>` | YAML configuration file. Default: `config.yaml`. |
| `-h, --help` | Print help and exit. |
| `-V, --version` | Print the version and exit. |

Long options accept both `--name value` and `--name=value`; a value may be
empty only where the option explicitly allows it. `anyca_cli --help` prints
the command overview,
`anyca_cli <command> --help` prints the subcommands of a command, and
`anyca_cli <command> <subcommand> --help` prints that subcommand's options.

Commands that take a file as input name it with `--in`; output files use
`--out`.

Relative paths are resolved against the process working directory, not the
configuration file directory or the executable directory. This applies to
`store.path`, `crl_publish_path`, `cacerts_publish_path` and command-line
paths such as `--in` and `--out`.

`anyca_server` uses the same default path and the same option forms
(`-c <path>`, `--config <path>`, `--config=<path>`), and prints the same
version with `-V`/`--version`.

## Configuration

The configuration file (see `docs/example/config.yaml`) supplies:

- `store.path` — SQLite database. Required by every `ca` and `crl` command and
  by the `cert` commands except `cert new-root`. The `hsm` commands read only
  the configuration and `hsm_providers`; they do not open the store.
- `crl_publish_path` — optional directory receiving CRLs as
  `<crl_publish_path>/<CA-name>/<CA-name>.crl`.
- `cacerts_publish_path` — optional directory receiving CA certificates as
  `<cacerts_publish_path>/<CA-name>.crt`. The server publishes them at
  start-up and when a reload finds a changed stored certificate.
- `hsm_providers` — names accepted in PKCS #11 URIs and `ca list`, each with
  the PKCS #11 module path (`library`). An entry may also declare the token
  `model` and `serial`, which let a URI select the entry without a `provider`
  attribute. Multiple providers may use different module libraries; one module
  instance is loaded per distinct library.
- `certificate_usages` — named keyUsage/enhancedKeyUsage profiles accepted by
  `--certificate-usage`.
- `certificate_templates` — named AIA and CRL distribution point profiles
  accepted by `--certificate-template` on `cert new-root` and `cert issue`.
  Each entry has an optional `aia` mapping with `issuer_uris`
  (id-ad-caIssuers) and `ocsp_uris` (id-ad-OCSP), plus `crl_uris` for
  cRLDistributionPoints. All URI lists are optional; a template with no URIs
  adds no extensions.
- `certificate_policies` — named certificate policy profiles accepted by
  `cert issue --basic --certificate-policy`. Each `cps` entry contributes a
  policy OID and an optional CPS URI qualifier.

CA keys, PINs and DER certificates are stored in the database by `ca import`
and `ca create`. A running server reloads that configuration whenever the
database changes, so `ca import`, `ca create`, `ca update`, `ca delete` and
`ca ocsp-renew` apply without a restart; certificate and revocation records
are read for every request. A database written by an incompatible schema
version is rejected; create a new database.

Both publish directories are optional. When a directory is unset, the
corresponding publication is disabled. The server publishes CA certificates
and CRLs at start-up and publishes a CRL on the scheduler tick once the CA's
`--crl-publish-period-min` has elapsed.

## PKCS #11 URIs

Every HSM key is identified by an RFC 7512-style PKCS #11 URI. The path
component holds `;`-separated attributes; the optional query component after
`?` holds `&`-separated attributes:

```text
pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]token=<label>;object=<label>[;type=private][?pin-value=<pin>]
pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]token=<label>;object=<label>?pin-source=<file>
```

- `token` is the PKCS #11 token label.
- `object` is the key's `CKA_LABEL`. The same label identifies the private key
  and its public key.
- `model` and `serial` are the standard RFC 7512 token attributes. Without
  `provider`, they select an `hsm_providers` entry: an entry that declares
  every attribute present in the URI and matches them takes precedence over an
  entry that leaves some of them unset. The selection must be unique.
- `provider` is an AnyCA extension naming an entry in `hsm_providers`. When
  given, `model` and `serial` are optional consistency checks against that
  entry's configured values.
- `manufacturer` is accepted for RFC 7512 compatibility and is not used for
  provider matching.
- `type=private` is accepted; only private keys are supported.
- `pin-value` supplies the token PIN directly. `pin-source` reads it from a
  file, stripping trailing CR/LF. Exactly one of the two is required. The
  `pin-source` file must be a regular file (symbolic links are rejected),
  owned by the invoking user or root, and must not grant any group or other
  permission bits; otherwise the PIN is refused. RFC 7512 defines both as
  query attributes; AnyCA also accepts them in the path component for
  compatibility with older URIs.
- Values may contain `%XX` escapes. A literal `;`, `&`, `?` or `=` in a value
  must be percent-encoded.

`provider` is not defined by RFC 7512 (the standard selects a module with the
`module-path` or `module-name` query attributes); it is a vendor-specific
attribute that names an `hsm_providers` entry. Prefer standard matching with
`model` and `serial`, which requires the values in the configuration:

```yaml
hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    serial: "3dfe48398b2b6b63"   # optional; unique per token
    library: "/usr/lib/softhsm/libsofthsm2.so"
```

Quote the URI in a shell because `;`, `?` and `&` are shell metacharacters:

```sh
--key-uri 'pkcs11:model=SoftHSM%20v2;serial=3dfe48398b2b6b63;token=AnyCA;object=root-key?pin-value=1234'
```

Opening the same token again in one process shares its login state and session
pool. Tokens with the same label in different modules remain separate.

## Value formats

- **Distinguished name** (`--subject`): comma-separated attributes
  (`CN=Example,O=AnyCA,C=CN`) or `/`-separated attributes (`/CN=Example/O=AnyCA`).
  RFC 2253 backslash escapes are accepted.
- **Serial** (`--serial`): hexadecimal, optionally prefixed with `0x`, with or
  without leading zeros. At most 20 bytes; a 20-byte value must not have the
  high bit set. Serial numbers printed by the CLI use uppercase hex.
- **Times** (`--not-after`, `--revoked-at`): Unix time in seconds.
- **CA selection** (`--ca-name`, `--ca-id`): `--ca-name` selects a CA by its
  configuration name; `--ca-id` selects it by the numeric id printed by
  `ca list`. The two options are mutually exclusive. An id is accepted only
  when its key hash matches the CA's current certificate, so a stale id left
  over from re-keying is rejected with a request to use `--ca-name`.
- **Boolean** (`--is-ca`): `true`/`yes`/`1` or `false`/`no`/`0`, case-insensitive.
- **Hash algorithm** (certificates: `--digest`; CAs:
  `--ocsp-signer-hash-algorithm`): `sha1`, `sha256`, `sha384` or `sha512`,
  case-insensitive. Default: `sha384`.
- **Certificate files**: all certificate inputs and outputs are DER-encoded.
  `cert issue` also accepts a PEM or DER PKCS #10 request.

## CA commands

CA commands manage the CA configurations in the store. Each configuration
holds the CA key URI, the OCSP signer key URI, both DER certificates, the CRL
period, the OCSP nextUpdate period and the responder endpoint. A running
server reloads this configuration whenever the store changes.

### `ca create`

Create a new self-signed CA: generate both key pairs in their tokens, build the
CA certificate, generate the OCSP signing certificate, and store everything.
This is the only command that creates and registers a new self-signed CA;
`ca import` registers a CA that already exists.

| Option | Description |
| --- | --- |
| `--name <name>` | CA name. Required. |
| `--key-uri <uri>` | URI whose `object` names the new CA key pair. Required. |
| `--ocsp-key-uri <uri>` | URI whose `object` names the new OCSP signer key pair. Required. |
| `--ocsp-responder-endpoint <name>` | HTTP endpoint name; must not contain `/`. Required. |
| `--subject <dn>` | CA subject. Default: `CN=<name>`, with DN special characters escaped. |
| `--certificate-usage <name>` | CA `certificate_usages` entry. Default: `ca`. |
| `--key-type <rsa\|ec\|ml-dsa-44\|ml-dsa-65\|ml-dsa-87>` | Generated key type. Default: `rsa`. |
| `--rsa-bits <n>` | RSA modulus size, `2048`–`16384`. Default: `3072`. RSA only. |
| `--ec-curve <p256\|p384\|p521>` | EC curve. Default: `p384`. EC only. |
| `--ocsp-signer-hash-algorithm <sha1\|sha256\|sha384\|sha512>` | Hash algorithm for the CA and OCSP signing certificates. Default: `sha384`. |
| `--crl-publish-period-min <n>` | CRL nextUpdate period in minutes. Default: `10080` (7 days); `0` disables periodic publication. |
| `--ocsp-update-period-min <n>` | OCSP nextUpdate period in minutes. Default: `10`; `0` omits nextUpdate. |

A `crl_publish_period_min` of `0` disables periodic republication: the CA is
published once at server start and on `crl publish`, but the scheduler never
renews it automatically. Every published CRL still carries nextUpdate; with a
period of `0` it uses the default 7-day period.

The token must not already contain a private key with either URI's `object`
label; key generation is rejected rather than creating ambiguous labels. Use a
unique label for every generated key pair. A duplicate CA name or OCSP
responder endpoint is rejected before key generation. If a later step fails,
the key pairs created by this invocation are deleted; if deletion fails, the
CLI prints a warning with the labels that require manual cleanup. The two URIs
may name different `hsm_providers`: each key pair is created in the module
named by its own URI. ML-DSA needs a PKCS #11 3.2 provider that implements
`CKM_ML_DSA_KEY_PAIR_GEN` and `CKM_ML_DSA`; SoftHSM 2.6 does not.
`--ocsp-signer-hash-algorithm` has no effect on ML-DSA certificates, which sign
the TBS directly.

Example:

```sh
anyca_cli ca create --name root-ca \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-key?pin-value=1234' \
  --ocsp-key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=ocsp-key?pin-value=1234' \
  --ocsp-responder-endpoint root-ca \
  --key-type ec --ec-curve p384 \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

### `ca import`

Import an existing CA certificate and register its keys. The DER certificate is
stored in the database and is used by every later operation. Use this to
register a subordinate CA after `cert issue` has signed its CSR with the
parent CA.

| Option | Description |
| --- | --- |
| `--name <name>` | CA name. Required. |
| `--key-uri <uri>` | PKCS #11 URI of the CA private key. Required. |
| `--in <path>` | DER CA certificate. Required. It must match the CA key. |
| `--ocsp-key-uri <uri>` | PKCS #11 URI of the OCSP signer key. Required. |
| `--ocsp-responder-endpoint <name>` | HTTP endpoint name; must not contain `/`. Required. |
| `--ocsp-signer-hash-algorithm <sha1\|sha256\|sha384\|sha512>` | Hash algorithm for the generated OCSP signing certificate, stored with the CA. Default: `sha384`. |
| `--crl-publish-period-min <n>` | CRL nextUpdate period in minutes. Default: `10080` (7 days); `0` disables periodic publication. |
| `--ocsp-update-period-min <n>` | OCSP nextUpdate period in minutes. Default: `10`; `0` omits nextUpdate. |

A `crl_publish_period_min` of `0` disables periodic republication: the CA is
published once at server start and on `crl publish`, but the scheduler never
renews it automatically. Every published CRL still carries nextUpdate; with a
period of `0` it uses the default 7-day period.

The CLI generates an OCSP signing certificate with the CA key: the subject
defaults to `CN=<CA name> OCSP Signer`, the validity defaults to 3650 days, and
the `--ocsp-signer-hash-algorithm` value is used. The certificate has fixed
extensions: critical keyUsage `digitalSignature`, critical basicConstraints
with `cA=false`, and the OCSPSigning extendedKeyUsage.
`--ocsp-signer-hash-algorithm` is also stored
for later renewals and for `ca ocsp-renew`. The generated certificate is added
to the CA's issued-certificate records, so it appears in `cert list`.

The CLI reads the CA certificate as DER. It verifies that it is a CA
certificate (`X509_check_ca`), that the generated OCSP signing certificate is
authorized for this CA, and that the HSM keys selected by `--key-uri` and
`--ocsp-key-uri` match their respective certificates. Matching is checked by
signing a fixed challenge with the HSM key and verifying the signature with the
certificate public key. A duplicate CA name or OCSP responder endpoint is
rejected before the CA is registered. The two URIs may name different
`hsm_providers`, so the CA key and the OCSP signer key can live in different
PKCS #11 modules. All checks must pass for the import to succeed; on failure
the CA record is rolled back, and the CLI warns if that rollback fails.

Example:

```sh
anyca_cli ca import --name root-ca \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-key?pin-value=1234' \
  --in root.der \
  --ocsp-key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=ocsp-key?pin-value=1234' \
  --ocsp-responder-endpoint root-ca \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

### `ca list`

List stored CA configurations together with their current store identity,
HSM keys, OCSP signer configuration, responder endpoint and publication
periods. PINs are never printed. The store id shown for each CA can be used
with `--ca-id`.

```text
CA root-ca (id 1)
  key: softhsm/AnyCA/root-key
  OCSP signer: softhsm/AnyCA/ocsp-key
  OCSP digest: sha384
  endpoint: root-ca
  periods: CRL 60 min, OCSP 10 min, CRL number 1794905864
  key hash: 19683FFEEE3393923FE039F112B51ACF88EC6D44F7300BCB3F90C07944C1F296
```

The key hash is the SHA-256 of the CA certificate's DER SubjectPublicKeyInfo.
A CA whose certificate has not been registered yet is shown with
`(not registered)` instead of an id. `CRL number` is the last reserved CRL
number; it is `0` before the first publication, and the first reservation is
seeded from the current Unix time.

```sh
anyca_cli ca list
```

### `ca update`

Change one or more fields of a stored CA configuration. One of `--ca-name` and
`--ca-id` is required; any number of the following field options may be given
in the same invocation:

- `--key-uri <uri>` — replace the CA provider, token, PIN and key label.
- `--in <path>` — replace the stored DER CA certificate.
- `--ocsp-key-uri <uri>` — replace the OCSP signer provider, token, PIN and key
  label.
- `--ocsp-signer-hash-algorithm <name>` — change the stored OCSP signing hash
  algorithm.
- `--crl-publish-period-min <n>`, `--ocsp-update-period-min <n>`.
- `--ocsp-responder-endpoint <name>`.

When `--key-uri`, `--in` or `--ocsp-key-uri` is given, the resulting identity is
validated before anything is written:

- The CA key must match the CA certificate.
- The OCSP signer key must match a signer certificate that the CA issued
  directly and that carries the OCSPSigning EKU.

`--ocsp-key-uri` always reissues the OCSP signing certificate, because the old
certificate cannot match the new key. `--key-uri` and `--in` reissue it only
when the stored certificate is no longer usable with the new CA key or
certificate. A reissued certificate is recorded as an issued certificate of the
CA. If validation or reissue fails, the command exits non-zero and does not
change the stored CA configuration.

Use `--in` only to renew the certificate of the same CA identity (same subject
and key). Replacing the subject or key changes the issuer identity: old
certificates then receive OCSP `unknown` and cannot use the newly published
CRL. The rotation procedure is described in `DEPLOY.md`. After a key change the
old `--ca-id` no longer matches the CA; select it with `--ca-name`.

A running server reloads the changed configuration on its next OCSP response or
CRL check.

```sh
anyca_cli ca update --ca-name root-ca \
  --crl-publish-period-min 30 --ocsp-update-period-min 10
```

### `ca delete`

Delete a CA configuration. Certificate and revocation records in the store are
kept, and the HSM key objects are not deleted:

```sh
anyca_cli ca delete --ca-name root-ca
```

To remove the keys, use `hsm keydel` or a PKCS #11 vendor tool. Creating a new
CA with the same key labels while the old objects still exist fails with
`HSM_ERR_DUPLICATE`; delete the old key objects first or choose new labels.
Published CRL and CA certificate files are also left in place.

### `ca publish-crl`

Build, sign and publish one CA's CRL on demand. This command opens the
configured token, checks that the CA key matches its certificate, and writes
`<crl_publish_path>/<CA-name>/<CA-name>.crl` in DER. Select the CA with
`--ca-name` or `--ca-id`.

```sh
anyca_cli ca publish-crl --ca-name root-ca
```

`crl publish` performs the same operation and can additionally publish every
CA with `--all`.

### `ca ocsp-renew`

Create or renew the OCSP signing certificate of a stored CA, save it to the
database and record it as an issued certificate of that CA.

| Option | Description |
| --- | --- |
| `--ca-name <name>` | CA from the store. One of `--ca-name`, `--ca-id` is required. |
| `--ca-id <id>` | CA by store id from `ca list`. Mutually exclusive with `--ca-name`. |
| `--subject <dn>` | Subject. Default: `CN=<CA name> OCSP Signer`. |
| `--days <n>` | Validity in days, `1`–`365000`. Default: `3650`. |
| `--ocsp-signer-hash-algorithm <sha1\|sha256\|sha384\|sha512>` | Signature hash algorithm. Default: the CA's stored OCSP signing hash algorithm (`sha384` when unset). |
| `--serial <hex>` | Serial, at most 20 bytes. Default: random. |
| `--out <path>` | Also write the DER certificate. |

The CA key and the OCSP signer key are read from the stored CA configuration.
An existing OCSP signing certificate is replaced regardless of its expiry. The
new certificate is also recorded under the CA's issued certificates, so it
appears in `cert list`. The signing hash algorithm comes from the CA's stored
value unless `--ocsp-signer-hash-algorithm` is given; a command-line value
overrides it for this certificate only and does not change the stored value.
The certificate has fixed extensions: critical keyUsage `digitalSignature`,
critical basicConstraints with `cA=false`, and the OCSPSigning extendedKeyUsage.
notBefore is backdated by one hour so the certificate is immediately usable.
The new certificate is recorded under the CA's issued certificates before
`--out` is written. `--out` is published atomically (a temporary file in the
same directory, then a rename); if that write fails, the command exits
non-zero, no success message is printed, and the CA's stored OCSP signer is
left unchanged (the issued-certificate record remains).

```sh
anyca_cli ca ocsp-renew --ca-name root-ca --days 30 \
  --ocsp-signer-hash-algorithm sha512 --out ocsp-signer.der
```

## Certificate commands

`cert issue` signs a PKCS #10 request with a stored CA and records the result
under that CA. `cert new-root` generates a standalone self-signed root
certificate. `cert record`, `cert revoke` and `cert list` manage the
certificate inventory in SQLite.

### `cert issue`

Sign a PKCS #10 request with a stored CA. The request may be DER or PEM
encoded, and its self-signature is verified before signing. Select the issuing
CA with `--ca-name` or `--ca-id`, choose exactly one mode with `--basic` or
`--enforce`, and write the DER certificate to `--out`. The certificate is also
recorded as an issued certificate of the CA; when its serial is already
recorded, the existing record's notAfter is updated. The command fails if the
record cannot be written. The certificate is recorded before `--out` is
written, and `--out` is published atomically (a temporary file in the same
directory, then a rename); the success message is printed only after both
steps succeed.

Use `--is-ca true` and a CA usage to issue a subordinate CA certificate, then
register it with `ca import`.

| Option | Description |
| --- | --- |
| `--ca-name <name>` | Issuing CA from the store. One of `--ca-name`, `--ca-id` is required. |
| `--ca-id <id>` | Issuing CA by store id from `ca list`. Mutually exclusive with `--ca-name`. |
| `--in <path>` | PKCS #10 request, DER or PEM. Required. |
| `--basic` | Copy only the request subject and build extensions from profiles. Exactly one of `--basic`, `--enforce` is required. |
| `--enforce` | Sign the request and copy its requested extensions. |
| `--is-ca <true\|false>` | basicConstraints cA. Required with `--basic`. |
| `--path-length <n\|none>` | basicConstraints pathLenConstraint. Default: `none`. Requires `--is-ca true`. |
| `--certificate-usage <name>` | `certificate_usages` entry. Required with `--basic`. |
| `--certificate-template <name>` | Optional `certificate_templates` entry; adds authorityInfoAccess and cRLDistributionPoints. |
| `--certificate-policy <name>` | Optional `certificate_policies` entry; adds certificatePolicies. |
| `--days <n>` | Validity in days, `1`–`365000`. Default: `3650`. |
| `--digest <sha1\|sha256\|sha384\|sha512>` | Signature digest. Default: `sha384`. |
| `--serial <hex>` | Serial, at most 20 bytes. Default: random. |
| `--out <path>` | Output DER certificate. Required. |
| `--no-aki` | Do not add authorityKeyIdentifier. |
| `--no-ski` | Do not add subjectKeyIdentifier. |

Basic mode copies only the subject and public key from the request and ignores
its requested extensions. It always adds critical basicConstraints and
keyUsage, and adds non-critical extendedKeyUsage when the usage profile has
`enhanced_usage_oids`. `--certificate-template` adds authorityInfoAccess
(issuer and OCSP URIs) and cRLDistributionPoints; `--certificate-policy` adds
certificatePolicies, including CPS URI qualifiers.

Enforce mode signs the request as submitted: every requested extension is
copied except subjectKeyIdentifier and authorityKeyIdentifier. keyUsage and
basicConstraints remain critical even when the request marks them
non-critical. Usage, template and policy options are rejected in this mode.
Because all requested extensions are accepted unchanged, a CSR can request CA
basicConstraints or arbitrary keyUsage; the CLI prints a warning for this mode
so the request should be reviewed before issuing.

Both modes add authorityKeyIdentifier by default. CA certificates also receive
a computed subjectKeyIdentifier; in enforce mode a non-CA certificate keeps a
subjectKeyIdentifier requested by the CSR. `--no-aki` and `--no-ski` suppress
the corresponding extension. Enforce mode takes the cA value from the requested
basicConstraints extension; a request without that extension is treated as a
non-CA certificate.

```sh
# Basic: subject from the request, extensions from the configured profiles.
anyca_cli cert issue --ca-name root-ca --in leaf.csr \
  --basic --is-ca false --certificate-usage code-signing \
  --certificate-template default --certificate-policy code-signing \
  --out leaf.der

# Enforce: sign the requested extensions as submitted.
anyca_cli cert issue --ca-name root-ca --in leaf.csr --enforce \
  --out leaf.der

# Subordinate CA: issue the CA certificate, then register it with ca import.
anyca_cli cert issue --ca-name root-ca --in sub-ca.csr \
  --basic --is-ca true --path-length 0 --certificate-usage ca \
  --out sub-ca.der
anyca_cli ca import --name sub-ca --in sub-ca.der \
  --key-uri 'pkcs11:...;object=sub-ca-key?pin-source=token.pin' \
  --ocsp-key-uri 'pkcs11:...;object=sub-ca-ocsp-key?pin-source=token.pin' \
  --ocsp-responder-endpoint sub-ca
```

### `cert new-root`

Generate a self-signed certificate. The issuer and subject key are the same HSM
key. The certificate is written to `--out` and is not registered as a CA; use
`ca create` to create a managed self-signed CA.

| Option | Description |
| --- | --- |
| `--subject <dn>` | Subject distinguished name. Required. |
| `--key-uri <uri>` | PKCS #11 URI of the key used as subject and signer. Required. |
| `--certificate-usage <name>` | `certificate_usages` entry. Required. |
| `--certificate-template <name>` | `certificate_templates` entry supplying AIA and CRL distribution point URIs. Optional. |
| `--is-ca <true\|false>` | basicConstraints cA. Default: `true`. |
| `--path-length <n\|none>` | basicConstraints pathLenConstraint. Default: `none`. Requires `--is-ca true`. |
| `--days <n>` | Validity in days, `1`–`365000`. Default: `3650`. |
| `--digest <sha1\|sha256\|sha384\|sha512>` | Signature digest. Default: `sha384`. |
| `--serial <hex>` | Serial, at most 20 bytes. Default: random. |
| `--out <path>` | Output DER certificate. Required. |

The usage profile supplies the keyUsage bits; a profile containing
`keyCertSign` requires `--is-ca true`. Self-signed certificates do not carry an
EKU extension. subjectKeyIdentifier and basicConstraints/keyUsage are always
added. When `--certificate-template` is given, the template adds
authorityInfoAccess and cRLDistributionPoints.

```sh
anyca_cli cert new-root --subject "CN=AnyCA Root,O=AnyCA,C=CN" \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-key?pin-value=1234' \
  --certificate-usage ca --is-ca true --path-length 1 --days 7300 --out root.der
```

### `cert record`

Add or delete an issued-certificate record in the store.

| Option | Description |
| --- | --- |
| `--add` | Add the certificate record. Exactly one of `--add`, `--delete` is required. |
| `--delete` | Delete the certificate record. A still-revoked record cannot be deleted; delete the revocation first. |
| `--in <path>` | DER certificate from which to read the CA, serial and notAfter. |
| `--ca-name <name>` | Issuing CA in the store. One of `--ca-name`, `--ca-id` is required without `--in`. |
| `--ca-id <id>` | Issuing CA by store id from `ca list`. Mutually exclusive with `--ca-name`. |
| `--serial <hex>` | Certificate serial. Required without `--in`; when used with `--in`, must match it. |
| `--not-after <time>` | notAfter as Unix time, `--add` only. Default with `--in`: taken from the certificate; otherwise `0`. |

With `--in`, the CLI identifies the issuing CA by verifying the certificate
against each configured CA. If several CAs match, `--ca-name` or `--ca-id` is
required.

```sh
anyca_cli cert record --add --in leaf.der --ca-name root-ca
anyca_cli cert record --delete --in leaf.der
anyca_cli cert record --delete --ca-name root-ca --serial 6619A5CE9DF9B325DB30BC4EF45C3D29
```

### `cert revoke`

Add or delete a certificate revocation in the store.

| Option | Description |
| --- | --- |
| `--add` | Record the revocation. Exactly one of `--add`, `--delete` is required. |
| `--delete` | Delete the revocation record, making the certificate good again. |
| `--in <path>` | DER certificate to read the CA and serial from. |
| `--ca-name <name>` | Issuing CA from the store. One of `--ca-name`, `--ca-id` is required without `--in`. |
| `--ca-id <id>` | Issuing CA by store id from `ca list`. Mutually exclusive with `--ca-name`. |
| `--serial <hex>` | Certificate serial. Required without `--in`; when used with `--in`, must match it. |
| `--revoked-at <time>` | Revocation time as Unix time, `--add` only. Default: now. |
| `--reason <n>` | RFC 5280 reasonCode, `0`–`10` except `7`, `--add` only. Default: `0`. |

With `--add`, if the certificate is not recorded yet, the CLI records a
placeholder entry and then adds the revocation, printing a warning. Revoking an
already revoked certificate is an error. With `--delete`, an unrevoked
certificate is an error; the certificate record is left untouched.

RFC 5280 reasonCode values: `0` unspecified, `1` keyCompromise, `2` cACompromise,
`3` affiliationChanged, `4` superseded, `5` cessationOfOperation,
`6` certificateHold, `8` removeFromCRL, `9` privilegeWithdrawn,
`10` aACompromise. Value `7` is unused.

```sh
anyca_cli cert revoke --add --in leaf.der --reason 1
anyca_cli cert revoke --delete --in leaf.der
```

### `cert list`

List certificate or revocation records for one CA.

| Option | Description |
| --- | --- |
| `--ca-name <name>` | CA from the store. Exactly one of `--ca-name`, `--ca-id` is required. |
| `--ca-id <id>` | CA by store id from `ca list`. Mutually exclusive with `--ca-name`. |
| `--revocation` | List revocation records instead of certificate records. |
| `--n <count>` | List the most recent `<count>` records. |

Certificate records show the serial, notAfter and, when revoked, the revocation
time and reason. Revocation records show the serial, revokedAt and reason. All
times are Unix time.

```sh
anyca_cli cert list --ca-name root-ca
anyca_cli cert list --ca-name root-ca --revocation --n 20
```

## CRL commands

### `crl publish`

Build, sign and publish one or every CA's CRL on demand. This command opens the
configured tokens, checks that each CA key matches its certificate, and writes
`<crl_publish_path>/<CA-name>/<CA-name>.crl` in DER. `--ca-name`/`--ca-id` and
`--all` are mutually exclusive; one of the three is required.

```sh
anyca_cli crl publish --ca-name root-ca
anyca_cli crl publish --all
```

## HSM commands

HSM commands inspect and manage the `hsm_providers` entries and their tokens.
`key-list`, `fetch-uri` and `search-key` select a provider and token directly;
the other key commands use a PKCS #11 URI. When a PIN is needed,
`--pin-source <path>` reads it from a file (stripping trailing CR/LF), while
`--pin-value <pin>` supplies it on the command line; the two are mutually
exclusive. `hsm list` and `hsm token-info` only read the configuration and never
log in.

### `hsm list`

List every `hsm_providers` entry with its library, model and serial.

```sh
anyca_cli hsm list
```

### `hsm token-info`

Open a provider's PKCS #11 module and the named token without logging in, then
print module and token information.

| Option | Description |
| --- | --- |
| `--provider <name>` | `hsm_providers` entry. Required. |
| `--token <label>` | PKCS #11 token label. Required. |

```sh
anyca_cli hsm token-info --provider softhsm --token AnyCA
```

### `hsm key-list`

List the RSA, EC and ML-DSA key objects in one token. Private-key and public-key
objects are separate entries with the same label. Each entry shows the label,
algorithm (`RSA2048`, `ECC-P384`, `ML-DSA-65`), object type (`private` or
`public`) and a PKCS #11 URI without credentials.

| Option | Description |
| --- | --- |
| `--provider <name>` | `hsm_providers` entry. Required. |
| `--token <label>` | PKCS #11 token label. Required. |
| `--pin-source <path>` | Read the token PIN from a file and log in. |
| `--pin-value <pin>` | Token PIN on the command line and log in. |

Without a PIN, the token is opened without logging in; many tokens then expose
only public-key objects. With `--pin-source` or `--pin-value`, the token is
opened with a login and private-key objects are listed too. If no keys are
visible, the command prints `No keys found in token <label>.`

```text
Key: ca-key
  algorithm: RSA2048
  type: private
  uri: pkcs11:provider=softhsm;token=AnyCA;object=ca-key

Key: ca-key
  algorithm: RSA2048
  type: public
  uri: pkcs11:provider=softhsm;token=AnyCA;object=ca-key
```

```sh
anyca_cli hsm key-list --provider softhsm --token AnyCA \
  --pin-source token.pin
```

### `hsm key-info`

Read the public key identified by the URI's `object` label and print its type
and size. RSA keys report their modulus size; EC keys report the named curve and
encoded point size; ML-DSA keys report the parameter set and raw public-key size.

| Option | Description |
| --- | --- |
| `--key-uri <uri>` | PKCS #11 key URI. Required. |

```sh
anyca_cli hsm key-info \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-key?pin-source=token.pin'
```

### `hsm fetch-uri`

Build a PKCS #11 key URI from a provider, token and key label. Values are
percent-encoded. When `--pin-source` or `--pin-value` is supplied, the URI
carries the same credential and can be used directly as `--key-uri` for CA and
certificate commands.

| Option | Description |
| --- | --- |
| `--provider <name>` | `hsm_providers` entry. Required. |
| `--token <label>` | PKCS #11 token label. Required. |
| `--label <key-label>` | Key `CKA_LABEL`. Required. |
| `--pin-source <path>` | Add `pin-source` to the URI. |
| `--pin-value <pin>` | Add `pin-value` to the URI. |

This command reads the configuration to validate the provider name but does not
open the token, so it does not verify that the label exists.

```sh
anyca_cli hsm fetch-uri --provider softhsm --token AnyCA \
  --label root-ca-key --pin-source /opt/anyca/pins/token.pin
```

```text
pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=%2Fopt%2Fanyca%2Fpins%2Ftoken.pin
```

Without `--pin-source` and `--pin-value` the output has no query component;
append `?pin-source=<path>` or `?pin-value=<pin>` before using it.

### `hsm search-key`

Find token keys whose public key matches a certificate, PKCS #10 request or
public key. The output format is the same as `key-list`, but only matching
labels are printed. A matching label produces both private-key and public-key
entries when both are visible.

| Option | Description |
| --- | --- |
| `--in <path>` | DER or PEM certificate, PKCS #10 request or public key. Required. |
| `--provider <name>` | `hsm_providers` entry. Required. |
| `--token <label>` | PKCS #11 token label. Required. |
| `--pin-source <path>` | Read the token PIN from a file and log in. |
| `--pin-value <pin>` | Token PIN on the command line and log in. |

`--in` accepts a DER or PEM X.509 certificate, a DER or PEM PKCS #10 request,
or a DER or PEM SubjectPublicKeyInfo public key. The command extracts the
public key and compares it with the token keys; signatures in the input are not
verified. Without a PIN, public-key objects can still be matched; logging in
also reports matching private-key objects. When no PIN is supplied, the command
prints a note that matching private keys were not searched. If nothing matches,
the command prints `No matching key found.` and exits successfully. An input
that cannot be parsed is an error.

```sh
anyca_cli hsm search-key --in leaf.der --provider softhsm --token AnyCA \
  --pin-source token.pin
```

```text
Key: leaf-key
  algorithm: ECC-P384
  type: private
  uri: pkcs11:provider=softhsm;token=AnyCA;object=leaf-key

Key: leaf-key
  algorithm: ECC-P384
  type: public
  uri: pkcs11:provider=softhsm;token=AnyCA;object=leaf-key
```

### `hsm keygen`

Generate an RSA, EC or ML-DSA key pair in the token named by the URI. The key
pair receives the URI's `object` label, which must not already exist.

| Option | Description |
| --- | --- |
| `--key-uri <uri>` | PKCS #11 key URI naming the new key pair. Required. |
| `--key-type <rsa\|ec\|ml-dsa-44\|ml-dsa-65\|ml-dsa-87>` | Key type. Default: `rsa`. |
| `--rsa-bits <n>` | RSA modulus size, `2048`–`16384`. Default: `3072`. RSA only. |
| `--ec-curve <p256\|p384\|p521>` | EC curve. Default: `p384`. EC only. |

ML-DSA requires a PKCS #11 3.2 provider that implements
`CKM_ML_DSA_KEY_PAIR_GEN` and `CKM_ML_DSA` (for example a vendor module or a
recent HSM); SoftHSM 2.6 does not. The generated key can be used for
certificates, CRLs and OCSP responses the same way as RSA and EC keys. Always
authenticate (`CKA_ALWAYS_AUTHENTICATE`) keys need a PIN for each signature;
the CLI and server supply it from the stored key URI.

```sh
anyca_cli hsm keygen \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=leaf-key?pin-source=token.pin' \
  --key-type ec --ec-curve p384
```

### `hsm keydel`

Destroy the private and public key objects carrying the URI's `object` label.
Deleting an absent key pair succeeds.

| Option | Description |
| --- | --- |
| `--key-uri <uri>` | PKCS #11 key URI. Required. |

```sh
anyca_cli hsm keydel \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=leaf-key?pin-source=token.pin'
```

### `hsm pin-set`

Change an HSM token's user PIN. The old PIN is read from the key URI; the token
must be logged in.

| Option | Description |
| --- | --- |
| `--key-uri <uri>` | PKCS #11 key URI supplying the provider, token and old PIN. Required. |
| `--new-pin <pin>` | New token user PIN. Required. |

```sh
anyca_cli hsm pin-set \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-key?pin-source=token.pin' \
  --new-pin 5678
```

`--new-pin` is visible in the process list and shell history. Run this command
from a protected environment and update the `pin-source` file (and any stored
CA PIN, with `ca update`) afterwards.

## Example workflow

```sh
# 1. Create a self-signed CA and its OCSP signer key and certificate.
anyca_cli ca create --name root-ca \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-key?pin-value=1234' \
  --ocsp-key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=ocsp-key?pin-value=1234' \
  --ocsp-responder-endpoint root-ca --crl-publish-period-min 60

# 2. Inspect the stored configuration.
anyca_cli ca list

# 3. Issue a leaf certificate from a PKCS #10 request.
openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key \
  -subj "/CN=leaf.example" -outform DER -out leaf.csr
anyca_cli cert issue --ca-name root-ca --in leaf.csr \
  --basic --is-ca false --certificate-usage code-signing \
  --certificate-template default --out leaf.der

# 4. The issued certificate is already recorded; revoke it later and publish
#    an updated CRL.
anyca_cli cert revoke --add --in leaf.der --reason 1
anyca_cli crl publish --ca-name root-ca

# 5. Inspect the store; --delete reverses a revocation or record.
anyca_cli cert list --ca-name root-ca
anyca_cli cert list --ca-name root-ca --revocation

# 6. Renew the OCSP signing certificate.
anyca_cli ca ocsp-renew --ca-name root-ca --days 30

# 7. Start the server; it publishes the CA certificate and CRLs at start-up.
anyca_server
```

To import a CA that already exists, replace step 1 with `ca import` and provide
`--in` plus the two key URIs. To create a subordinate CA, issue its certificate
with `cert issue --basic --is-ca true --certificate-usage ca`, then register it
with `ca import`.

## SoftHSM helper scripts

The scripts under [scripts/](../scripts/) wrap `softhsm2-util` and `pkcs11-tool`
for local token setup and inspection. They use
`/usr/lib/softhsm/libsofthsm2.so` by default; set `PKCS11_MODULE` to select a
different module. Run them from the repository root:

```sh
scripts/softhsm-init-token.sh <token-label> <user-pin> <so-pin>
scripts/softhsm-gen-key.sh <token-label> <user-pin> <algorithm> <key-label>
scripts/softhsm-import-key.sh <token-label> <user-pin> <key-label> <key-file>
scripts/softhsm-list-tokens.sh
scripts/softhsm-list-keys.sh <token-label> <user-pin>
```

A PIN in the command line is visible in shell history and the process list.
The scripts also accept it through the environment, without the PIN argument:

```sh
PKCS11_PIN=<user-pin> SOFTHSM_SO_PIN=<so-pin> scripts/softhsm-init-token.sh <token-label>
PKCS11_PIN=<user-pin> scripts/softhsm-gen-key.sh <token-label> <algorithm> <key-label>
PKCS11_PIN=<user-pin> scripts/softhsm-import-key.sh <token-label> <key-label> <key-file>
PKCS11_PIN=<user-pin> scripts/softhsm-list-keys.sh <token-label>
```

`softhsm2-util` and `pkcs11-tool` still receive the PIN as an argument, so it is
briefly visible in the process list.

`softhsm-list-tokens.sh` prints the label, serial number and PKCS #11 URI of
every initialized token. `softhsm-list-keys.sh` prints one
`<label><TAB><URI>` line per private key. The key URIs contain no PIN; append
`?pin-value=<pin>` or `?pin-source=<file>` before passing one to AnyCA.

## Exit status

`0` on success and a non-zero status on failure. Usage errors print the
reference of the command being run to stderr. Diagnostics are written to
stderr; command results are written to stdout.

## Security note

`pin-value` places the PIN on the command line, where it may be visible in
process listings and shell history. Prefer `pin-source=<file>` with a
permission-restricted file, and use a dedicated token PIN. `--new-pin` in
`hsm pin-set` has the same exposure. `--pin-value` on `hsm key-list`,
`hsm fetch-uri` and `hsm search-key` is exposed in the same way, and
`hsm fetch-uri --pin-value` also writes the PIN into the URI it prints.
