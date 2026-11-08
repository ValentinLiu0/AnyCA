# AnyCA

AnyCA is a C23 CA and OCSP responder. It issues X.509 v3 certificates with
private keys held in a PKCS #11 HSM, stores CA configurations and
certificate/revocation records in SQLite, and serves OCSP responses over HTTP.

- Create a self-signed root CA with generated HSM keys, or import an existing
  CA certificate and key.
- Generate RSA, ECDSA and ML-DSA certificates (RSA and ECDSA support
  SHA-1/256/384/512, with SHA-384 as the default; ML-DSA signs the message
  directly), or sign PKCS #10 requests with a stored CA. ML-DSA requires a
  PKCS #11 3.2 provider.
- Generate OCSP signing certificates automatically; they are stored with the
  CA and registered in its issued-certificate records.
- Keep CA configurations, issued certificates and revocations in SQLite.
- Use multiple PKCS #11 modules in one process and select keys with PKCS #11
  URIs.
- List token keys, build key URIs and find the key matching a certificate,
  request or public key.
- Publish DER CRLs and CA certificates to configured directories.
- Serve OCSP responses under `/ocsp/<endpoint>`; private keys never leave
  the HSM.
- Reload CA configuration from the store when the CLI changes it, so changes
  made by `ca create`, `ca update`, `ca delete`, `ca ocsp-renew`, `cert record`
  and `cert revoke` take effect without restarting the server.

The package provides `anyca_cli` for administration and certificate
generation, and `anyca_server` for the OCSP responder.

## Documentation

- [docs/DEPLOY.md](docs/DEPLOY.md) — deployment guide: build, SoftHSM setup,
  a new CA, an existing CA, importing keys into SoftHSM, systemd, backups and
  troubleshooting
- [docs/DEPLOY.zh-cn.md](docs/DEPLOY.zh-cn.md) — Chinese deployment guide
- [docs/CLI.md](docs/CLI.md) — complete CLI usage, options and examples
- [docs/CLI.zh-cn.md](docs/CLI.zh-cn.md) — Chinese CLI reference
- [docs/example/config.yaml](docs/example/config.yaml) — annotated example
  configuration
- [scripts/](scripts/) — SoftHSM helper scripts

## Build

Build dependencies include OpenSSL 3, SQLite3, libwebsockets, libyaml and
CMake 4.3+.  The PKCS #11 3.2 header is a public-domain copy from
[latchset/pkcs11-headers](https://github.com/latchset/pkcs11-headers) in
[third_party/pkcs11/](third_party/pkcs11/), so p11-kit is not needed.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The build produces `build/anyca_cli`, `build/anyca_server` and the shared
library `build/libanyca_core.so`, which the executables link at run time. There
are no install targets. Run the binaries from `build/`, or follow
[docs/DEPLOY.md](docs/DEPLOY.md#13-service-account-and-layout) for a fixed
prefix, service account and systemd unit.

## Quick start

This is a local smoke test; use [docs/DEPLOY.md](docs/DEPLOY.md) for a
production deployment. It assumes that SoftHSM is already configured and that a
token labelled `AnyCA` is initialized with PIN `1234` (see
[docs/DEPLOY.md](docs/DEPLOY.md#14-configure-and-initialize-softhsm)).

```sh
export PATH="$PWD/build:$PATH"
cp docs/example/config.yaml config.yaml
# Edit store.path, hsm_providers, crl_publish_path and cacerts_publish_path.

printf '%s' '1234' > token.pin
chmod 600 token.pin

anyca_cli ca create --name root-ca \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-ca-key?pin-source=token.pin' \
  --ocsp-key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-ca-ocsp-key?pin-source=token.pin' \
  --ocsp-responder-endpoint root-ca \
  --key-type ec --ec-curve p384 \
  --crl-publish-period-min 60 --ocsp-update-period-min 10

anyca_cli crl publish --all

anyca_server
```

The server listens on the address and port from `config.yaml` and serves OCSP
under `/ocsp/root-ca`. Complete workflows for issuing a test certificate,
verifying OCSP, revoking a certificate and running the service are in
[docs/DEPLOY.md](docs/DEPLOY.md).

## HSM key URIs

HSM keys are selected with RFC 7512-style PKCS #11 URIs:

```text
pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]token=<label>;object=<key-label>[?pin-value=<pin>|?pin-source=<file>]
```

`provider` is an AnyCA extension that names an `hsm_providers` entry. When it is
omitted, the standard `model` and `serial` attributes select the entry, so
declare those attributes in `config.yaml`:

```yaml
hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    library: "/usr/lib/softhsm/libsofthsm2.so"
```

Use `pin-source=<file>` instead of `pin-value` to keep the PIN out of the
command line, shell history and process list. The file's trailing CR/LF is
stripped. AnyCA stores the resolved PIN in the store database, so protect
`store.db` as well. Quote the URI in the shell because `;`, `?` and `&` are
shell metacharacters. The CA key URI and the OCSP signer key URI may select
different providers, so the two keys can live in separate PKCS #11 modules.

## SoftHSM helper scripts

The scripts in [scripts/](scripts/) wrap `softhsm2-util` and `pkcs11-tool`.
They all default to `/usr/lib/softhsm/libsofthsm2.so`; set `PKCS11_MODULE` to
use another module.

| Script | Purpose |
| --- | --- |
| [scripts/softhsm-init-token.sh](scripts/softhsm-init-token.sh) | Initialize a token: `<token-label> <user-pin> <so-pin>`. |
| [scripts/softhsm-gen-key.sh](scripts/softhsm-gen-key.sh) | Generate a key pair: `<token-label> <user-pin> <algorithm> <key-label>`. |
| [scripts/softhsm-import-key.sh](scripts/softhsm-import-key.sh) | Write a private-key object: `<token-label> <user-pin> <key-label> <private-key-file>`. |
| [scripts/softhsm-list-tokens.sh](scripts/softhsm-list-tokens.sh) | List initialized tokens with label, serial and PKCS #11 URI. |
| [scripts/softhsm-list-keys.sh](scripts/softhsm-list-keys.sh) | List private keys: `<token-label> <user-pin>`; prints label and PKCS #11 URI. |

`softhsm-import-key.sh` writes only a private-key object. AnyCA also needs a
public-key object with the same label, so use `softhsm2-util --import` to
import an existing CA key pair, as described in
[docs/DEPLOY.md](docs/DEPLOY.md#4-importing-private-keys-into-softhsm). The
key URI printed by `softhsm-list-keys.sh` has no PIN; add
`?pin-value=<pin>` or `?pin-source=<file>` before passing it to `anyca_cli`.

A PIN on the command line is visible in shell history and the process list.
Every script also accepts the PIN through the environment, which keeps it out
of the script's arguments:

```sh
PKCS11_PIN=<user-pin> SOFTHSM_SO_PIN=<so-pin> scripts/softhsm-init-token.sh <token-label>
PKCS11_PIN=<user-pin> scripts/softhsm-gen-key.sh <token-label> <algorithm> <key-label>
PKCS11_PIN=<user-pin> scripts/softhsm-import-key.sh <token-label> <key-label> <private-key-file>
PKCS11_PIN=<user-pin> scripts/softhsm-list-keys.sh <token-label>
```

`softhsm2-util` and `pkcs11-tool` still receive the PIN as an argument, so it
is briefly visible in the process list; only `softhsm-list-tokens.sh` needs no
PIN.

## Runtime validation and reload

At start-up, the server loads each CA from the store and verifies that the CA
certificate is a CA certificate, that the OCSP signer certificate is currently
valid and is either the CA certificate itself or was issued directly by that CA
with the OCSPSigning EKU, and that both HSM keys match their certificates. A CA
that fails validation is logged and skipped while the remaining CAs continue to
start.
`ca import` performs the same checks and rejects the import instead of leaving
an invalid configuration.

A running server also reloads the CA configuration whenever a CLI command
changes the store: before each OCSP response and on each CRL scheduler tick.
New, changed and deleted CAs therefore take effect without a restart. A CA
whose changed settings fail validation retains its previous configuration.

## External libraries

License names are short identifiers (SPDX where applicable).

| Library                              | License       |
|--------------------------------------|---------------|
| OpenSSL                              | Apache-2.0    |
| SQLite                               | Public Domain |
| libwebsockets                        | LGPL-2.1      |
| PKCS #11 3.2 headers (public domain) | Public Domain |
| libyaml                              | MIT           |

Build tooling: CMake (BSD-3-Clause).
