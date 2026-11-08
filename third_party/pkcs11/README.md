# PKCS #11 headers

`pkcs11.h` is vendored from the public-domain PKCS #11 3.2 headers in
[latchset/pkcs11-headers](https://github.com/latchset/pkcs11-headers),
`public-domain/3.2/pkcs11.h`:

<https://github.com/latchset/pkcs11-headers/blob/master/public-domain/3.2/pkcs11.h>

The file is in the public domain.  It is self-contained: it defines the
platform macros and the Windows structure packing itself.  It implements the
OASIS PKCS #11 3.2 API, including the ML-DSA mechanisms AnyCA uses.  Vendoring
it removes the build-time dependency on p11-kit; the project only needs the
declarations, not an extra library.

SHA-256 of the vendored file:

```
f700fb2b26363cd7ae77dfb94172f9baadc6d9798fb13563323451d8ac27b66f
```

To update the header, copy `public-domain/<version>/pkcs11.h` from a newer
latchset/pkcs11-headers revision and record the version and hash here.  Keep
the file byte-for-byte identical to upstream so that later updates remain
reviewable.
