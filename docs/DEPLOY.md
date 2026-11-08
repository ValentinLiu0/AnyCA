# Deployment guide

This guide takes you from an empty Linux host to a running AnyCA OCSP
responder. It covers two deployments:

- **New CA**: AnyCA generates the CA key pair, a self-signed CA certificate,
  the OCSP signer key pair and the OCSP signing certificate.
- **Existing CA**: the CA certificate and private key already exist. The CA key
  is imported into SoftHSM, an OCSP signer key is generated (or imported), and
  both keys are registered with `ca import`.

It also includes a standalone section on
[importing existing private keys into SoftHSM](#4-importing-private-keys-into-softhsm).

For all command-line options, see [CLI.md](CLI.md). The annotated configuration
example is [example/config.yaml](example/config.yaml). All shell examples use
Bash and a dedicated `anyca` service account with the installation prefix
`/opt/anyca`; adjust names and paths to your environment.

Relative paths in `config.yaml` (including `store.path`,
`crl_publish_path` and `cacerts_publish_path`) and relative paths given on the
command line are resolved against the **current working directory of the
process**, not the directory containing the configuration file. Use absolute
paths in a production configuration.

## 1. Prepare the host

### 1.1 Dependencies

Build requirements:

- CMake 4.3 or newer
- a C23 compiler (GCC or Clang)
- OpenSSL 3 development files
- SQLite3 development files
- libwebsockets development files
- libyaml development files

The PKCS #11 3.2 header is a public-domain copy from
latchset/pkcs11-headers in `third_party/pkcs11/`, so p11-kit is not needed.

Runtime and HSM tooling:

- SoftHSM2 (only when SoftHSM is the PKCS #11 module)
- OpenSC (`pkcs11-tool`) for token administration
- the `openssl` command-line tool for key and certificate conversion

Debian/Ubuntu:

```sh
sudo apt install build-essential cmake \
  libssl-dev libsqlite3-dev libwebsockets-dev libyaml-dev \
  softhsm2 opensc openssl
```

Fedora:

```sh
sudo dnf install gcc make cmake \
  openssl-devel sqlite-devel libwebsockets-devel libyaml-devel \
  softhsm opensc openssl
```

If the distribution provides CMake older than 4.3, install a newer CMake from
<https://cmake.org/download/> or through a separate toolchain. Check with:

```sh
cmake --version
```

### 1.2 Build

From the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The build produces:

- `build/anyca_cli`
- `build/anyca_server`
- `build/libanyca_core.so` (runtime dependency of both programs)

There are no install targets. Run the binaries from `build/`, or copy them to
a fixed prefix as shown below. The executables find `libanyca_core.so` through
the build-tree run path; when they are copied elsewhere, set
`LD_LIBRARY_PATH` to the directory containing the library.

### 1.3 Service account and layout

Create an unprivileged account and a self-contained prefix:

```sh
sudo useradd --system --user-group --home-dir /opt/anyca \
  --shell /usr/sbin/nologin anyca
sudo install -d -o anyca -g anyca -m 0750 /opt/anyca
sudo install -d -o anyca -g anyca -m 0750 \
  /opt/anyca/bin /opt/anyca/lib /opt/anyca/crl /opt/anyca/cacerts
sudo install -d -o anyca -g anyca -m 0700 /opt/anyca/pins
sudo install -o anyca -g anyca -m 0755 \
  build/anyca_cli build/anyca_server /opt/anyca/bin/
sudo install -o anyca -g anyca -m 0755 \
  build/libanyca_core.so /opt/anyca/lib/
```

A possible layout after completing the guide:

```text
/opt/anyca/
├── bin/                 anyca_cli, anyca_server
├── lib/                 libanyca_core.so
├── config.yaml          AnyCA configuration
├── softhsm2.conf        SoftHSM configuration
├── store.db             CA configurations, certificates, revocations
├── pins/                PIN files referenced by pin-source (mode 0700)
├── tokens/              SoftHSM token store (mode 0700)
├── crl/                 published CRLs
└── cacerts/             published CA certificates
```

Start a shell as the service account for the remaining commands in this
guide:

```sh
sudo -u anyca -H /bin/bash
cd /opt/anyca
export PATH=/opt/anyca/bin:$PATH
export LD_LIBRARY_PATH=/opt/anyca/lib
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
```

### 1.4 Configure and initialize SoftHSM

Set `SOFTHSM2_CONF` explicitly for every SoftHSM command and the server
process. This avoids depending on the distribution default or on
`$HOME/.config/softhsm2/softhsm2.conf`, and ensures that the CLI and server use
the same token store.

Create the SoftHSM configuration and token directory:

```sh
cat > /opt/anyca/softhsm2.conf <<'EOF'
directories.tokendir = /opt/anyca/tokens
objectstore.backend = file
log.level = ERROR
EOF
install -d -m 0700 /opt/anyca/tokens
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
```

Initialize a token. The SO PIN is used only for token administration; the user
PIN is the PIN that AnyCA uses. Store the SO PIN offline and use a strong user
PIN:

```sh
read -rsp 'New SO PIN: ' SO_PIN; echo
read -rsp 'New user PIN: ' TOKEN_PIN; echo
softhsm2-util --init-token --free --label AnyCA \
  --so-pin "$SO_PIN" --pin "$TOKEN_PIN"
unset SO_PIN
```

Keep the user PIN in a root/service-account-only file for `pin-source`. The
file may end with a newline; the CLI strips trailing CR/LF.

```sh
printf '%s' "$TOKEN_PIN" > /opt/anyca/pins/token.pin
chmod 600 /opt/anyca/pins/token.pin
unset TOKEN_PIN
```

Verify the token and record its label and serial:

```sh
softhsm2-util --show-slots
```

AnyCA stores the token PIN it reads from the URI in `store.db`. The PIN is
therefore present in the database in plaintext as well as in the PIN file.
Restrict access to both. See [Security notes](#7-security-and-operations).

### 1.5 Configure AnyCA

Copy the example and edit the paths. The example uses relative paths; replace
them with absolute paths so the server behaves the same regardless of its
working directory.

```sh
cp /path/to/anyca/docs/example/config.yaml /opt/anyca/config.yaml
chmod 600 /opt/anyca/config.yaml
```

A minimal configuration for this guide:

```yaml
store:
  path: "/opt/anyca/store.db"

http:
  address: "127.0.0.1"
  port: 8080
  max_connections: 1024
  requests_per_second: 1000
  request_burst: 2000

crl_publish_path: "/opt/anyca/crl"
cacerts_publish_path: "/opt/anyca/cacerts"

hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    library: "/usr/lib/softhsm/libsofthsm2.so"

certificate_usages:
  - name: "ca"
    basic_usages:
      - "digitalSignature"
      - "keyCertSign"
      - "cRLSign"
    enhanced_usage_oids: []
  - name: "code-signing"
    basic_usages:
      - "digitalSignature"
    enhanced_usage_oids:
      - "1.3.6.1.5.5.7.3.3"
```

Notes:

- `store.path` is the SQLite database. The schema is created on first use.
- `hsm_providers[].name` is what `provider=<name>` in a PKCS #11 URI selects.
  `model` and `serial` are used only when a URI omits `provider=`.
- `http.address` `127.0.0.1` is suitable behind a TLS reverse proxy. Use
  `0.0.0.0` (with a firewall) only when clients connect directly.
- `http.max_connections` caps libwebsockets file descriptors;
  `requests_per_second` and `request_burst` configure a per-client token
  bucket (keyed by peer address).
  Omitted or zero values use the defaults shown above. The service's
  `LimitNOFILE` must be larger than `max_connections`.
- `crl_publish_path` and `cacerts_publish_path` are optional, but are needed
  for `crl publish`, the server's CA-certificate publication at start-up and
  the server's periodic CRL publication.
- `certificate_usages` must contain the profiles named on the command line.
  `ca` is required by `ca create`'s default, and `code-signing` is used by the
  examples below.

If clients are expected to discover OCSP and CRL locations from issued
certificates, add a template with public URLs. These URIs are embedded in
every certificate that uses the template, so they must be correct before
issuance:

```yaml
certificate_templates:
  - name: "default"
    aia:
      issuer_uris:
        - "https://pki.example.com/cacerts/root-ca.crt"
      ocsp_uris:
        - "https://ocsp.example.com/ocsp/root-ca"
    crl_uris:
      - "https://pki.example.com/crl/root-ca/root-ca.crl"
```

The file names and directory layout above are produced by
`cacerts_publish_path` and `crl_publish_path`; see
[section 2.3](#23-publish-the-crl) and
[section 2.5](#25-start-the-server).

## 2. Deploy a new CA

### 2.1 Create the CA

`ca create` generates the CA key pair and the OCSP signer key pair in the
token, creates a self-signed CA certificate and an OCSP signing certificate,
and stores both certificates and both key URIs in the database.

```sh
anyca_cli -c /opt/anyca/config.yaml ca create \
  --name root-ca \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/opt/anyca/pins/token.pin' \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-ocsp-key?pin-source=/opt/anyca/pins/token.pin' \
  --ocsp-responder-endpoint root-ca \
  --subject 'CN=Example Root CA,O=Example,C=US' \
  --key-type ec --ec-curve p384 \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

Expected output:

```text
Created CA: root-ca
```

The CA and OCSP key labels must not already exist in the token. The CLI
rejects a duplicate CA name or a duplicate OCSP responder endpoint before it
generates any key. If a later step fails after key generation, the key pairs
created by that invocation are deleted; a warning is printed if cleanup fails,
in which case remove the keys manually.

Verify the registration:

```sh
anyca_cli -c /opt/anyca/config.yaml ca list
```

### 2.2 Inspect the generated keys

```sh
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login --list-objects
```

The CA key and OCSP signer key each have a private-key object and a
public-key object with the same label. AnyCA discovers the public-key object
by label, so both objects must be present.

### 2.3 Publish the CRL

```sh
anyca_cli -c /opt/anyca/config.yaml crl publish --all
```

`crl publish` opens the token and signs a CRL with the CA key. It writes:

```text
/opt/anyca/crl/root-ca/root-ca.crl
```

The CA certificate is published by the server at start-up (section 2.5), which
writes `/opt/anyca/cacerts/root-ca.crt` from the database. Both files are DER
encoded. Serve these directories with a static web server, or copy the files to
your distribution infrastructure.

### 2.4 Issue a test certificate

This step is optional, but it exercises the CA key, the store and the OCSP
responder end to end.

Generate a leaf key and a PKCS #10 request. This smoke test keeps the leaf key
on the local filesystem; production certificates normally use a CSR produced
with the subject's own PKCS #11 tooling.

```sh
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /opt/anyca/leaf.key \
  -subj '/CN=leaf.example' \
  -outform DER -out /opt/anyca/leaf.csr
openssl req -in /opt/anyca/leaf.csr -inform DER -noout -verify
```

Issue a certificate:

```sh
anyca_cli -c /opt/anyca/config.yaml cert issue \
  --ca-name root-ca \
  --in /opt/anyca/leaf.csr \
  --basic --is-ca false \
  --certificate-usage code-signing \
  --out /opt/anyca/leaf.der
```

Add `--certificate-template default` if you configured a template with public
AIA and CRL URLs. Certificates are DER encoded and are recorded automatically;
the issued certificate appears in `cert list` and its revocation can be
reported by OCSP without a separate `cert record --add` step.

To issue a subordinate CA certificate, use `cert issue --basic --is-ca true
--path-length 0 --certificate-usage ca`, then register the result with
`ca import`.

### 2.5 Start the server

```sh
anyca_server -c /opt/anyca/config.yaml
```

The server runs in the foreground, logs to stderr, and stops cleanly on
SIGINT/SIGTERM. At start-up it publishes the CA certificate to
`/opt/anyca/cacerts/root-ca.crt` and publishes the initial CRLs. It then
checks the store once per minute and publishes each CA's CRL when its
`crl_publish_period_min` has elapsed. For a service, see
[section 6](#6-run-as-a-systemd-service).

From another terminal, query OCSP. Convert the DER certificates to PEM for the
`openssl ocsp` client:

```sh
openssl x509 -inform DER -in /opt/anyca/cacerts/root-ca.crt -out /tmp/root-ca.pem
openssl x509 -inform DER -in /opt/anyca/leaf.der -out /tmp/leaf.pem

openssl ocsp \
  -issuer /tmp/root-ca.pem \
  -cert /tmp/leaf.pem \
  -url http://127.0.0.1:8080/ocsp/root-ca \
  -no_nonce -noverify -resp_text
```

A healthy response contains:

```text
Cert Status: good
```

`-noverify` disables response-signature verification in this smoke test.
Production clients verify the OCSP response against the OCSP signer and the
CA. GET and POST OCSP requests are supported under `/ocsp/<endpoint>`.

### 2.6 Revoke a certificate

```sh
anyca_cli -c /opt/anyca/config.yaml cert revoke --add \
  --in /opt/anyca/leaf.der --reason 1

anyca_cli -c /opt/anyca/config.yaml crl publish --ca-name root-ca
```

The server reads the store for each OCSP request, so the next request for that
certificate reports `revoked` without a restart. The CRL is updated when you
run `crl publish` or when the server's periodic CRL timer fires (60 minutes in
the `ca create` example).

## 3. Deploy an existing CA

Use this path when the CA certificate and private key already exist and you
want AnyCA to continue using that CA. The CA key must end up in a PKCS #11
token; AnyCA never reads a private key from a file.

### 3.1 Check the existing material

The CA certificate must:

- be an X.509 CA certificate: `X509_check_ca()` must accept it, which normally
  means BasicConstraints `CA:TRUE` and a key usage permitting certificate
  signing;
- be within its validity period; check the dates with `openssl x509 -dates`
  before deployment and monitor them afterwards;
- correspond to the private key (same public key).

The private key may be RSA (2048 bits or stronger) or EC (P-256/P-384/P-521).
SoftHSM supports importing PKCS #8 RSA and EC keys. ML-DSA keys need a
PKCS #11 3.2 provider that implements `CKM_ML_DSA`; SoftHSM 2.6 does not, so
use the HSM vendor's import procedure for those keys.

Inspect the certificate:

```sh
openssl x509 -in existing-ca.pem -noout -subject -issuer -dates
openssl x509 -in existing-ca.pem -noout -text | \
  grep -A2 -E 'Basic Constraints|Key Usage'
```

Check that the key matches the certificate:

```sh
openssl pkey -in existing-ca.key -pubout -out /tmp/existing-ca-key.pub
openssl x509 -in existing-ca.pem -pubkey -noout > /tmp/existing-ca-cert.pub
cmp /tmp/existing-ca-key.pub /tmp/existing-ca-cert.pub
```

`cmp` prints nothing and exits 0 when the keys match. Convert the certificate
to DER for `ca import`:

```sh
openssl x509 -in existing-ca.pem -outform DER -out /opt/anyca/existing-ca.der
```

### 3.2 Import the CA key into SoftHSM

Follow [section 4](#4-importing-private-keys-into-softhsm). Use a unique label,
for example `existing-ca-key`, and verify that both the private-key and
public-key objects exist. Remember the label for the PKCS #11 URI.

### 3.3 Prepare the OCSP signer key

The OCSP signer key must also be in a token. Generate a signer key pair;
AnyCA creates the OCSP signing certificate with the CA key during `ca import`:

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login \
  --keypairgen --key-type EC:secp384r1 \
  --label existing-ca-ocsp-key --usage-sign
```

The generated certificate is signed by the CA, has subject
`CN=<CA name> OCSP Signer`, is valid for 3650 days, and is added to the CA's
issued-certificate records. Its extensions are fixed: critical keyUsage
`digitalSignature`, critical basicConstraints with `cA=false`, and the
OCSPSigning extendedKeyUsage.

### 3.4 Register the CA

```sh
anyca_cli -c /opt/anyca/config.yaml ca import \
  --name existing-ca \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-key?pin-source=/opt/anyca/pins/token.pin' \
  --in /opt/anyca/existing-ca.der \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-ocsp-key?pin-source=/opt/anyca/pins/token.pin' \
  --ocsp-responder-endpoint existing-ca \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

Expected output:

```text
Imported CA: existing-ca
```

Before the CA is registered, the CLI checks:

| Check | Failure behavior |
| --- | --- |
| CA certificate parses as DER | Import fails; nothing is registered. |
| CA certificate is a CA certificate (`X509_check_ca`) | Import fails; nothing is registered. |
| CA key matches the CA certificate | Import fails; nothing is registered. |
| OCSP signer key matches the generated OCSP signing certificate | Import fails; nothing is registered. |
| Generated OCSP signing certificate is authorized for this CA (directly issued, OCSPSigning EKU) | Import fails; nothing is registered. |
| CA name and OCSP responder endpoint are unused | Rejected before a CA record is added. |

Key/certificate matching is checked by signing a fixed challenge with the HSM
key and verifying the signature with the certificate's public key. The CA
configuration is kept only if every check passes; a failed import rolls it
back, and the CLI warns if the rollback itself fails.

The CA certificate is read from the database on later operations. Keep the
original file as a backup, but AnyCA does not need it after import.

### 3.5 Publish and run

```sh
anyca_cli -c /opt/anyca/config.yaml ca list
anyca_cli -c /opt/anyca/config.yaml crl publish --all
anyca_server -c /opt/anyca/config.yaml
```

Use the same smoke test as [section 2.5](#25-start-the-server), replacing
`root-ca` with `existing-ca` in the OCSP URL. The server publishes
`/opt/anyca/cacerts/existing-ca.crt` at start-up. To issue a certificate with
the imported CA, use `cert issue` with `--ca-name existing-ca`.

At start-up the server applies the same validation: it opens the CA and OCSP
signer tokens, checks the CA certificate, the OCSP signer authorization, and
both key/certificate pairs. A CA that fails is logged and skipped; other CAs
continue to start. A running server repeats this validation when it reloads a
changed CA configuration from the store, so fixing the stored settings applies
without a restart. If the CA still fails, the server keeps its previous
configuration.

## 4. Importing private keys into SoftHSM

This section applies to an existing CA key, an existing OCSP signer key, or any
other key that must be used through AnyCA. The recommended command is
`softhsm2-util --import`, because it imports a **key pair** (private key and
public key) with one label. AnyCA needs the public-key object to read the
public key and to verify key/certificate consistency.

### 4.1 Convert the key to PKCS #8

`softhsm2-util --import` requires a PKCS #8 file. If the key is in PKCS #1
(`BEGIN RSA PRIVATE KEY`), traditional EC form, or an encrypted container,
convert it first:

```sh
# Unencrypted PKCS #8.  The output file contains the raw private key.
openssl pkcs8 -topk8 -nocrypt -in existing-ca.key -out existing-ca.p8
chmod 600 existing-ca.p8
```

If the input key is encrypted, the same command prompts for its pass phrase;
`-nocrypt` keeps the output unencrypted. Perform this on a trusted host, keep
the temporary file on a filesystem with restrictive permissions, and remove it
after the import according to your key-handling policy.

Check the key type and size before importing:

```sh
openssl pkey -in existing-ca.key -text -noout | head
```

Use RSA keys of at least 2048 bits, or EC keys on P-256, P-384 or P-521.

### 4.2 Initialize the token

If the token does not exist yet:

```sh
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
read -rsp 'New SO PIN: ' SO_PIN; echo
read -rsp 'New user PIN: ' TOKEN_PIN; echo
softhsm2-util --init-token --free --label AnyCA \
  --so-pin "$SO_PIN" --pin "$TOKEN_PIN"
unset SO_PIN
printf '%s' "$TOKEN_PIN" > /opt/anyca/pins/token.pin
chmod 600 /opt/anyca/pins/token.pin
```

Verify the token label:

```sh
softhsm2-util --show-slots
```

### 4.3 Import the key pair

```sh
softhsm2-util --import /secure/existing-ca.p8 \
  --token AnyCA --pin "$TOKEN_PIN" \
  --label existing-ca-key --id 01
```

- `--token` is the token label, not the slot number. `--slot` and `--serial`
  are alternatives.
- `--label` is the label AnyCA uses in the PKCS #11 URI's `object=`.
- `--id` is required by SoftHSM even though AnyCA selects keys by label. Use a
  unique hexadecimal ID per key (for example `01`, `02`, ...). If the ID
  already exists, SoftHSM refuses the import; choose another ID. Do not use
  `--force` unless you intend to allow duplicate IDs.
- Do not pass `--no-public-key`: AnyCA requires the public-key object.

The command prompts for the user PIN when `--pin` is omitted. Passing the PIN
with `--pin` exposes it in the process list and shell history; use a protected
temporary shell or the interactive prompt on a multi-user host.

Expected output:

```text
The key pair has been imported.
```

### 4.4 Verify the pair

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login --list-objects --type privkey
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login --list-objects --type pubkey
```

Both listings must contain an object with the same label and ID. The private
key should have `sign` usage and the public key should have `verify` usage.
SoftHSM stores both objects under the label you passed to `softhsm2-util`.

Build the URI for AnyCA:

```text
pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-key?pin-source=/opt/anyca/pins/token.pin
```

`provider=softhsm` must match the `name` in `hsm_providers`. If the URI omits
`provider=`, AnyCA matches the standard `model` and `serial` attributes
against the provider entries instead. Percent-encode spaces and other reserved
characters in token or object labels (`%20` for a space). Quote the URI in the
shell because `;`, `?` and `&` are shell metacharacters.

Use this URI as `--key-uri` for `ca import`, `ca update`, `cert new-root` or
`hsm key-info`. For the OCSP signer, use the label of the signer key as
`object=` and pass the URI as `--ocsp-key-uri`.

### 4.5 Import an OCSP signer key

The same procedure applies:

```sh
softhsm2-util --import /secure/existing-ocsp.p8 \
  --token AnyCA --pin "$TOKEN_PIN" \
  --label existing-ca-ocsp-key --id 02
```

If you do not already have an OCSP signer key, generate one in the token
instead:

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login \
  --keypairgen --key-type EC:secp384r1 \
  --label existing-ca-ocsp-key --usage-sign
```

### 4.6 Other import methods

- `pkcs11-tool --keypairgen` generates a new key pair in the token and is the
  right tool for new keys.
- `pkcs11-tool --write-object --type privkey` writes only a private-key object.
  AnyCA also needs a public-key object for the same label, so this alone is not
  sufficient. Import the matching public key separately, or prefer
  `softhsm2-util --import`.
- The helper script [../scripts/softhsm-import-key.sh](../scripts/softhsm-import-key.sh)
  uses `pkcs11-tool --write-object --type privkey` and therefore has the same
  limitation. It is not the recommended way to import a CA key for AnyCA.
- Hardware PKCS #11 modules are imported with the vendor's tooling. AnyCA only
  needs the resulting token label, object label and PIN.

### 4.7 Clean up temporary key material

After verifying that the token contains the key pair and that your backup or
escrow policy is satisfied, remove the unencrypted PKCS #8 file:

```sh
shred -u existing-ca.p8
```

Never delete the only copy of a CA key. SoftHSM tokens are ordinary files under
`directories.tokendir`; protect backups of the token directory as key material.

## 5. URL layout and reverse proxy

AnyCA serves OCSP only over plain HTTP. A typical public deployment puts a TLS
reverse proxy in front of it and serves published files as static content.

- OCSP: `http://127.0.0.1:8080/ocsp/<endpoint>` -> public
  `https://ocsp.example.com/ocsp/<endpoint>`
- CA certificates: `/opt/anyca/cacerts/<CA-name>.crt` -> public
  `https://pki.example.com/cacerts/<CA-name>.crt`
- CRLs: `/opt/anyca/crl/<CA-name>/<CA-name>.crl` -> public
  `https://pki.example.com/crl/<CA-name>/<CA-name>.crl`

A minimal nginx location for OCSP:

```nginx
# Per-client limit at the proxy; AnyCA sees only 127.0.0.1 behind it.
limit_req_zone $binary_remote_addr zone=ocsp:10m rate=100r/s;

location /ocsp/ {
    limit_req zone=ocsp burst=200 nodelay;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 15s;
}
```

AnyCA applies its rate limit by peer address. Behind a reverse proxy every
request appears to come from `127.0.0.1`, so
`http.requests_per_second`/`http.request_burst` collapse into one global bucket
shared by all clients. Enforce the per-client limit at the proxy (as above) and
raise the AnyCA limits to cover the proxy's aggregate traffic, or expose the
OCSP listener directly under firewall rules. AnyCA does not trust
`X-Forwarded-For`, so the forwarded header cannot restore per-client buckets.

Keep the AnyCA listener on `127.0.0.1` when a reverse proxy is used. If clients
connect directly, set `http.address` to a specific interface and enforce access
with a firewall; there is no built-in TLS.

The publish directories are inside `/opt/anyca`, which is mode `0750`. If a
different user (for example `www-data`) serves the files, grant that user read
and traverse access to `/opt/anyca/crl` and `/opt/anyca/cacerts` through group
membership or an ACL. Do not grant it access to `tokens/`, `pins/` or
`store.db`.

## 6. Run as a systemd service

Create `/etc/systemd/system/anyca.service`:

```ini
[Unit]
Description=AnyCA OCSP responder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=anyca
Group=anyca
WorkingDirectory=/opt/anyca
Environment=SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
Environment=LD_LIBRARY_PATH=/opt/anyca/lib
ExecStart=/opt/anyca/bin/anyca_server -c /opt/anyca/config.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=4096
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/anyca

[Install]
WantedBy=multi-user.target
```

Enable and start it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now anyca
sudo systemctl status anyca
sudo journalctl -u anyca -f
```

The service must use the same `SOFTHSM2_CONF` as the SoftHSM commands used to
initialize and import keys. `LimitNOFILE` must exceed `http.max_connections`;
`4096` covers the default `max_connections` of 1024 with room for other
descriptors. If you raise the connection limit, raise `LimitNOFILE` too.

Run `anyca_cli` as the `anyca` user (or with a umask and permissions that keep
the store writable by the service). A CLI run as root can create root-owned
files that the service cannot update.

A running server reloads the CA configuration from the store before each OCSP
response and on each CRL scheduler tick, so `ca update` and `ca delete` take
effect without a restart. Restart the service only after editing `config.yaml`
(for example, to add an `hsm_providers` entry):

```sh
sudo systemctl restart anyca
```

## 7. Security and operations

### 7.1 Protect secrets

- `store.db` contains CA key URIs and token PINs in plaintext. AnyCA creates a
  new database with mode `0600`; verify it (and any database created
  elsewhere) with `stat` and keep the database on a filesystem with restricted
  access or encryption at rest. Keep `/opt/anyca` and its private
  subdirectories non-world-readable as well. WAL mode also creates
  `store.db-wal` and `store.db-shm`, which contain the same sensitive data and
  inherit the database file mode.
- `pins/*.pin` must be readable only by the service account. The CLI enforces
  this for `pin-source`: the file must be a regular file (no symbolic links),
  owned by the invoking user or root, with no group or other permission bits.
  `pin-source` keeps the PIN out of `argv`, shell history and process
  listings, but it does not remove the PIN from `store.db`.
- SoftHSM is a software HSM, not a tamper-resistant device. For higher
  assurance, use a hardware PKCS #11 module and the vendor's key-import
  procedure; AnyCA only needs a provider entry and a PKCS #11 URI.
- Consider separate tokens for the CA key and the OCSP signer key, with
  different PINs and access rules. The two URIs may select different
  `hsm_providers`.
- Restrict who can run `anyca_cli` and who can read the token directory.
- Back up `/opt/anyca/tokens`, `store.db`, `config.yaml` and the PIN files while
  the service is stopped. A backup contains private keys and PINs; encrypt it.

### 7.2 Availability

- `http.max_connections` limits libwebsockets file descriptors. Set the
  systemd `LimitNOFILE` higher than this value.
- `http.requests_per_second` and `http.request_burst` apply a per-client token
  bucket (keyed by peer address) and return HTTP 503 for excess requests.
  Tune them for the expected OCSP load and the reverse proxy's own limits.
- The responder serves requests on one libwebsockets thread and serializes
  core and store access with a session lock, so a CRL publication briefly
  delays an OCSP response. HSM token sessions are shared inside the process;
  run multiple instances only if they share the same store safely and the HSM
  supports the concurrent sessions.
- Serve CRLs and CA certificates from a reliable static server or CDN. Clients
  may cache them.
- Keep the host clock synchronized (for example with chrony or systemd-timesyncd).
  Certificate validity, CRL times and OCSP `thisUpdate`/`nextUpdate` all depend
  on it.
- Monitor CA and OCSP signing certificate expiry. An expired OCSP signing
  certificate is rejected when the CA is loaded and causes that CA to be
  skipped at start-up.

### 7.3 CA certificate and key rotation

OCSP responses and CRLs are tied to the issuer identity: an OCSP CertID contains
hashes of the issuer name and public key, and a CRL is verified with the
issuer's public key. Replacing the stored CA certificate or key in place with
`ca update --in` or `ca update --key-uri` therefore affects every certificate
the old CA issued:

- Certificates issued under the old identity no longer match the responder's
  issuer name and key hashes. The responder answers `unknown` for them, even
  though their serial numbers are still in the store.
- `<crl_publish_path>/<CA-name>/<CA-name>.crl` is overwritten with a CRL signed
  by the new key. Clients that still hold an old certificate cannot verify that
  CRL against the issuer named in the certificate, and the previous CRL number
  sequence and content are lost.
- `<cacerts_publish_path>/<CA-name>.crt` is overwritten with the new
  certificate. Anything that pins or caches the old file must be updated.

Renewing only the CA certificate while keeping the same subject and key is less
disruptive: existing CertIDs still match and CRLs remain verifiable, because
both depend on the issuer name and key rather than on the CA certificate
serial. The published CA file still changes, and the old certificate must not
remain trusted if it was compromised.

To rotate a CA safely:

1. Create a new CA configuration with a new name (`ca create` or `ca import`)
   and a distinct OCSP endpoint (`--ocsp-responder-endpoint`). The new name
   automatically gets its own `<CA-name>` subdirectory under the configured
   `crl_publish_path` and `cacerts_publish_path`. Never reuse a CA name, OCSP
   endpoint or published URL path for a different identity.
2. Keep the old CA configuration, its keys and its published files in service
   until every certificate issued by the old CA has expired or been revoked.
   Keep the old OCSP endpoint and the old CRL path reachable, and do not
   republish a different CRL there.
3. Issue new certificates from the new CA and distribute the new CA
   certificate to trust stores. During the transition, clients can trust both
   the old and the new CA certificate.
4. Retire the old CA only after its last certificate has expired. Archive its
   CRL and CA certificate at stable paths if clients may still reference them,
   then remove the configuration with `ca delete` and the keys with
   `hsm keydel`.

`ca update --in` and `ca update --key-uri` validate the new key and certificate
and reissue the OCSP signing certificate when needed, but they cannot repair
the OCSP or CRL state of certificates issued under the previous identity. Use
them only for a certificate renewal that keeps the same subject and key, not
for a CA rotation.

### 7.4 Routine commands

| Task | Command |
| --- | --- |
| List CAs | `anyca_cli -c /opt/anyca/config.yaml ca list` |
| List certificates of a CA | `anyca_cli -c /opt/anyca/config.yaml cert list --ca-name root-ca` |
| List revocations | `anyca_cli -c /opt/anyca/config.yaml cert list --revocation --ca-name root-ca` |
| Revoke by certificate | `anyca_cli -c /opt/anyca/config.yaml cert revoke --add --in leaf.der --reason 1` |
| Delete a revocation | `anyca_cli -c /opt/anyca/config.yaml cert revoke --delete --in leaf.der` |
| Republish CRL | `anyca_cli -c /opt/anyca/config.yaml crl publish --ca-name root-ca` |
| Change periods or endpoint | `anyca_cli -c /opt/anyca/config.yaml ca update --ca-name root-ca --crl-publish-period-min 30` |
| Renew an OCSP signing certificate | `anyca_cli -c /opt/anyca/config.yaml ca ocsp-renew --ca-name root-ca --days 30` |
| Renew the CA certificate (same subject and key) | `anyca_cli -c /opt/anyca/config.yaml ca update --ca-name root-ca --in new-ca.der` |
| Delete a CA configuration | `anyca_cli -c /opt/anyca/config.yaml ca delete --ca-name root-ca` |

CA certificates are published at start-up and again whenever a reload detects
a changed stored certificate, so `ca update --in` refreshes
`cacerts/<CA-name>.crt` without a restart. See section 7.3 before replacing a
CA certificate or key: an in-place identity change breaks OCSP and CRL for the
certificates the old CA issued.

`ca delete` removes the CA configuration and key URIs from the store but keeps
the certificate and revocation records. It does not delete keys from the token;
remove the SoftHSM objects separately with your PKCS #11 administration tool if
they are no longer needed.

## 8. Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `config_load: Could not open file` | The `-c` path is wrong, or the process working directory differs from what you expect. Use an absolute `-c` path. |
| CA appears to be missing after `ca import` | The CLI and server may be using different `store.db` files. Check `store.path`; relative paths resolve against each process's working directory. |
| `Cannot open HSM token ...` or `CKR_TOKEN_NOT_PRESENT` | Token label mismatch, wrong `SOFTHSM2_CONF`, or the token directory is not readable by the service account. Compare `softhsm2-util --show-slots` run with the same environment. |
| `CKR_PIN_INCORRECT` | The PIN in the URI no longer matches the token. Update the PIN file and re-register the URI with `ca update --key-uri`/`--ocsp-key-uri`, or re-import the CA. |
| `the HSM key does not match the certificate for CA ...` | The URI selects the wrong key label, or the certificate does not belong to that key. Verify the public-key object and compare public keys with `openssl pkey -pubout`. |
| `Certificate for CA ... is not a CA certificate` | The certificate lacks CA BasicConstraints/key usage, or a non-CA certificate was passed to `ca import`. Import the correct CA certificate. |
| `OCSP signing certificate is not authorized for CA ...` | The signer certificate is expired, was not issued directly by this CA, or lacks the OCSPSigning EKU. Renew it with `ca ocsp-renew --ca-name <name>`. |
| `CA name or OCSP responder endpoint is already in use` | Choose another `--name`/`--ocsp-responder-endpoint`, or delete the existing CA first. |
| `softhsm2-util --import` reports a format error | The key is not PKCS #8. Convert it with `openssl pkcs8 -topk8 -nocrypt`. |
| `ca import` cannot find the public key | The key was imported as a private-key-only object. Use `softhsm2-util --import` without `--no-public-key`, or import the matching public-key object. |
| HTTP 503 from the responder | The per-client rate limit or burst limit was exceeded. Raise `http.requests_per_second`/`http.request_burst`, or add capacity and rate limiting at the proxy. Check the server log for rate-limit warnings. |
| The server starts but skips a CA | Read the preceding `LOGE` line. Common causes are token access, an expired signer certificate, a signer not issued by the CA, or a key/certificate mismatch. |
| OCSP still reports `good` after revocation | The certificate is not recorded under the CA that the server loaded, or the CLI and server use different stores. Check `cert list --revocation --ca-name ...` and `store.path`. |
| CRL is not updated | Run `crl publish` or wait for the CA's `--crl-publish-period-min` period. The server publishes CRLs at start-up and whenever the scheduler finds the period elapsed. |
| `ca create` fails after key generation | The CLI removes the key pairs created by that invocation. If cleanup also fails, the error includes a warning; delete the labels with `pkcs11-tool --delete-object` or the vendor tool. |

## 9. Deployment checklist

- [ ] OpenSSL, SQLite, libwebsockets and libyaml dependencies match the build,
      and `third_party/pkcs11/pkcs11.h` is present.
- [ ] `SOFTHSM2_CONF` and the token directory are identical for `anyca_cli`,
      `anyca_server` and all SoftHSM commands.
- [ ] `config.yaml` uses absolute paths for the store and publish directories.
- [ ] `hsm_providers` contains the module path; `provider=` values in URIs match
      its `name`.
- [ ] The CA and OCSP signer keys have both private-key and public-key objects.
- [ ] `ca list` shows the expected CA, endpoint and key hash.
- [ ] `crl publish --all` produces the expected DER CRL, and the server writes
      the expected DER CA certificate at start-up.
- [ ] An OCSP smoke test returns `good`, and a revoked certificate returns
      `revoked`.
- [ ] `store.db`, the PIN files and the token directory are readable only by the
      service account.
- [ ] systemd `LimitNOFILE` is above `http.max_connections`.
- [ ] Backups of the store, token directory, configuration and PIN files are
      tested, encrypted and access-controlled.
- [ ] The host clock is synchronized.
- [ ] CA and OCSP signer expiry dates are monitored.
