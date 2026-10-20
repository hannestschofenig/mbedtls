# Jumbo / TLSLargeCiphertext – Tests

This branch contains an implementation of the IETF draft
`draft-ietf-tls-super-jumbo-record-limit-03` (Large Record Size Limit + `TLSLargeCiphertext`).
The tests primarily use the example applications `ssl_client2` and `ssl_server2`.

## Current behavior (implementation notes)

- If the Jumbo extension is negotiated, **all TLS 1.3 records protected with `application_traffic_secret` use `TLSLargeCiphertext`** (independent of the negotiated numeric limit).
  Records protected with `early_traffic_secret` or `handshake_traffic_secret` remain in the classic TLSCiphertext format (as per the draft: they are not subject to the large record size limit).
- The Jumbo record length field uses the draft-03 varuint format and is **strict**:
  only 1/2/4-byte encodings are accepted and decoding rejects non-minimal encodings.
- Record handling behavior (draft-03 alignment):
  invalid Jumbo extension values → `illegal_parameter`;
  receiving a Jumbo record larger than the advertised limit → fatal `record_overflow` alert (TLS);
  malformed Jumbo record header varuint length encoding → fatal `record_overflow` alert (TLS).

## Prerequisites

- Build (Make): `CCACHE_DISABLE=1 make -j4`
- Many E2E tests start local servers/clients and require TCP `bind()`/`listen()` on `127.0.0.1`.
  In this environment that can require approval / elevated sandbox permissions.
- `gnutls-cli`/`gnutls-serv` are optional. If they are missing, mbedTLS↔mbedTLS tests still run;
  gnutls-based tests are skipped.

## Existing Tests (Jumbo)

### 1) `tests/ssl-opt.sh` (E2E, mbedTLS ↔ mbedTLS)

These tests exercise Jumbo negotiation, varuint boundary cases, and TLS 1.3 resumption end-to-end:

- `JUMBO_RECORD_SIZE_LIMIT: extension exists`
- `JUMBO_RECORD_SIZE_LIMIT: negotiated`
- `JUMBO_RECORD_SIZE_LIMIT: min value accepted` (64, smallest varuint encoding)
- `JUMBO_RECORD_SIZE_LIMIT: 2-byte varuint (16383)` (upper bound of the 14-bit range)
- `JUMBO_RECORD_SIZE_LIMIT: 4-byte varuint (16384)` (lower bound of the 30-bit range, and enforces `TLSLargeCiphertext`)
- `JUMBO_RECORD_SIZE_LIMIT: 50k single record` (sends 50k Application Data via `raw_payload_size` and expects a single record/write fragment)
- `JUMBO_RECORD_SIZE_LIMIT: small record uses TLSLargeCiphertext` (ensures `TLSLargeCiphertext` is used even for small Application Data once negotiated)
- `JUMBO_RECORD_SIZE_LIMIT: max value accepted` (checks parsing/range; max is `2^30 - 256` = `1073741568`)
- `JUMBO_RECORD_SIZE_LIMIT: tls13 resumption (serialize/load)` (ticket-based resumption with `reco_mode=1`)

Run (Jumbo subset only):

```sh
CCACHE_DISABLE=1 tests/ssl-opt.sh -f JUMBO_RECORD_SIZE_LIMIT --min 1
```

### 2) `tests/compat.sh` (E2E, mbedTLS ↔ mbedTLS)

These are targeted mbedTLS↔mbedTLS TLS 1.3 Jumbo checks (similar to `ssl-opt.sh`, but using the compat harness):

- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: extension exists`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: negotiated`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: min value accepted`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: 2-byte varuint (16383)`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: 4-byte varuint (16384)`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: 50k single record`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: max value accepted`
- `m->m tls13,jumbo JUMBO_RECORD_SIZE_LIMIT: tls13 resumption (serialize/load)`

Run (Jumbo subset only):

```sh
CCACHE_DISABLE=1 tests/compat.sh -f JUMBO --min 1
```

### 3) Unit tests: `tests/test_suite_ssl` (session serialize/load)

There is also a unit test that ensures `jumbo_record_size_limit` is preserved across
`mbedtls_ssl_session_save()`/`mbedtls_ssl_session_load()` for TLS 1.3, and a small unit-test
set that checks strict varuint parsing rules for the Jumbo extension (minimum-size encoding,
invalid prefix/length).

Run:

```sh
CCACHE_DISABLE=1 make -j4 tests
./tests/test_suite_ssl tests/test_suite_ssl.datax
```

## Manual smoke tests using the example programs

You can also test Jumbo and TLS 1.3 resumption directly with `ssl_server2`/`ssl_client2`:

```sh
./programs/ssl/ssl_server2 force_version=tls13 tickets=1 jumbo_record_size_limit=16385
./programs/ssl/ssl_client2 force_version=tls13 tickets=1 jumbo_record_size_limit=16385 reconnect=1 reco_mode=1
```

50k demo (no huge stdout logging; sends exactly N bytes of app data):

```sh
./programs/ssl/ssl_server2 force_version=tls13 tickets=0 jumbo_record_size_limit=60000 raw_payload_size=50000 buffer_size=60000 data_print=0
./programs/ssl/ssl_client2 force_version=tls13 tickets=0 jumbo_record_size_limit=60000 raw_payload_size=50000
```

## Gaps vs. the draft

- **Section 4 (Limits on Key Usage)**: the draft’s AEAD key-usage limit reduction for record sizes > 16k is not implemented (and there is no draft-driven automatic key update behavior).
- **DTLS 1.3 parts**: the draft’s DTLS `unified_hdr` / “length present MUST use …” requirements are not implemented in this branch (the focus is TLS 1.3 over TCP).
The main reason is that there is no DTLS 1.3 implementation for DTLS 1.3 in Mbed TLS.
- **Interop coverage**: no third-party interop tests for Jumbo (e.g., GnuTLS does not implement the extension; if `gnutls-cli/gnutls-serv` are missing, related tests are skipped).


## Functionality and interoperability status

This is an experimental TLS 1.3 over TCP implementation targeting
[draft-ietf-tls-super-jumbo-record-limit-03](https://datatracker.ietf.org/doc/html/draft-ietf-tls-super-jumbo-record-limit-03).
Client and server roles support negotiation in ClientHello and
EncryptedExtensions using the implementation's extension code point 100.
The extension value is a four-byte network-order uint32. Each endpoint
advertises its own receive limit independently; it covers TLSInnerPlaintext,
including content type and padding, and excludes AEAD expansion.

The draft permits limits from 64 through 2^30 - 256 bytes. This protocol
range does not imply that the implementation can buffer records of every
such size. Build-time buffer limits also apply. In particular, wolfSSL's
WOLFSSL_MAX_RECORD_SIZE setting currently permits 128 through 65535 bytes.

After negotiation, application-traffic records use TLSLargeCiphertext with
canonical 1-, 2-, or 4-byte varuint lengths. Handshake and early-traffic
records retain their standard TLS framing. TLS oversized records and invalid
Jumbo length encodings require a fatal record_overflow alert.

Previously successful cross-library tests covered both client/server role
combinations with a 65535-byte advertised limit and 50000-byte application
transfers. These tests do not establish full draft conformance. DTLS,
cross-library resumption, 0-RTT, and KeyUpdate are outside the verified
interoperability coverage. Mbed TLS additionally has local Jumbo test cases
for small records, length boundaries, and session resumption; their presence
does not establish cross-library support.

### Record overflow regression tests

After building both libraries with the interoperability script, run from the
parent `super_jumbo` directory:

```sh
python3 run_jumbo_overflow_tests.py
```

`WOLF_BUILD` and `MBED_BUILD` select the CMake build directories (defaults:
`/tmp/wolfssl_jumbo_build` and `/tmp/mbedtls_jumbo_build`). The tests require a
C compiler and localhost TCP sockets. Logs are retained in a temporary directory
printed by the runner. `JUMBO_TEST_PORT` overrides the default port 44550.

For both servers, the tests check an exact-limit valid record, an authenticated
record one byte over the limit, the reserved length prefix, non-minimal two- and
four-byte lengths, and oversized header-only records. The peer verifies a fatal
`record_overflow` alert (22); header-only cases also check that the receiver does
not wait for the payload. Different advertised limits exercise the direction of
the receive limit.
