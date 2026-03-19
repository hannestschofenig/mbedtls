# EKU (Extended Key Update) Summary

This document describes the TLS 1.3 Extended Key Update (EKU) integration, the tests that exercise it, and the public CLI/API surface for `ssl_client2` and `ssl_server2`. It focuses on the post‑handshake ExtendedKeyUpdate message flow, how it interleaves with application data and NewSessionTicket, and how to validate the behavior with the provided tests.

## EKU protocol flow (TLS 1.3)

Extended Key Update replaces the standard TLS 1.3 KeyUpdate mechanism. When EKU is negotiated, the classic `KeyUpdate` MUST NOT be used.

The protocol uses the `ExtendedKeyUpdate` handshake message with three subtypes:
1) **ExtendedKeyUpdate(key_update_request)** (initiator → responder)  
2) **ExtendedKeyUpdate(key_update_response)** (responder → initiator)  
3) **ExtendedKeyUpdate(new_key_update)** (initiator → responder)

Each request/response carries a `KeyShareEntry`, performing a fresh (EC)DHE exchange within the established session.

Key update ordering is important:
- The **initiator** updates its **receive** keys after receiving `key_update_response`, then sends `new_key_update`, and only then updates its **send** keys.
- The **responder** updates its **send** keys after sending `key_update_response`, and updates its **receive** keys upon receiving `new_key_update`.

While an EKU exchange is in progress, neither peer may initiate another Extended Key Update. If the peers independently initiate and requests cross, the request with the lower lexicographic order of the `key_exchange` in `KeyShareEntry` is ignored (tie‑break rule).

## TLS 1.3 EKU tests (`tests/ssl-opt.sh`)

Each test below focuses on a specific EKU interaction pattern and validates that the request/response/NKU sequence and key update ordering are handled correctly.

- **TLS 1.3 EKU: client initiates**  
  Client triggers one ExtendedKeyUpdate immediately after handshake (`eku_updates=1`). Validates the `key_update_request` → `key_update_response` → `new_key_update` sequence and the send/receive key update order defined by the draft.

- **TLS 1.3 EKU: both sides initiate**  
  Both peers start Extended Key Update concurrently (`eku_updates=1` on both sides). Exercises the tie‑break rule for crossed `key_update_request` messages and ensures the losing request is ignored without deadlock or state corruption.

- **TLS 1.3 EKU: client initiates (tickets disabled)**  
  Same as client‑initiated, but server runs with `tickets=0`. Confirms Extended Key Update works without NewSessionTicket interleaving and that classic KeyUpdate is rejected while EKU is enabled.

- **TLS 1.3 EKU: client initiates twice**  
  Client performs two sequential Extended Key Updates (`eku_updates=2`). Checks that EKU state machine variables and buffers are reset between exchanges and that repeated key derivations remain consistent.

- **TLS 1.3 EKU: server initiates (after exchange)**  
  Server triggers Extended Key Update after one application‑data exchange (`eku_after=1`). Ensures EKU can be injected mid‑flow without disrupting app‑data and that the client responds with `key_update_response` + `new_key_update` in the correct order.

- **TLS 1.3 EKU: timed appdata exchanges**  
  App‑data is exchanged for a fixed duration (`appdata_seconds=1`, `exchanges=0`) while EKU is injected periodically (`eku_after=1`). Validates mixed traffic where EKU, application data, and potential post‑handshake messages interleave in a time‑driven loop.

### Build and run the EKU tests

```
cmake -S . -B build-noccache -DENABLE_TESTING=Off -DCMAKE_C_COMPILER=/usr/bin/cc
cmake --build build-noccache -j$(nproc)
```

```
P_QUERY=./build/programs/test/query_compile_time_config \
P_SRV=./build/programs/ssl/ssl_server2 \
P_CLI=./build/programs/ssl/ssl_client2 \
P_PXY=./build/programs/test/udp_proxy \
./tests/ssl-opt.sh --filter 'TLS 1.3 EKU' --preserve-logs
```


## File Changes (Highlights)

### EKU protocol integration (TLS 1.3)
- `include/mbedtls/ssl.h`: new EKU handshake type, new state machine states, new config API, new public API, and config flag `tls13_extended_key_update`.
- `library/ssl_tls.c`: EKU config setter, EKU public API, and KeyUpdate disabled when EKU is enabled.
- `library/ssl_msg.c`: post‑handshake dispatch handles EKU; KeyUpdate rejected when EKU is enabled.
- `library/ssl_tls13_generic.c`: EKU parsing/derivation/state machine; ignores interleaved NewSessionTicket while waiting for EKU response.
- `library/ssl_tls13_keys.c`: helper for setting application keys; stores EKU salt during handshake.
- `library/ssl_tls13_client.c` / `library/ssl_tls13_server.c`: EKU states wired into TLS 1.3 handshake step.
- `library/ssl_misc.h`: internal EKU constants and handshake fields.

## State machine and post‑handshake handling

- EKU is handled as a TLS 1.3 post‑handshake message and routed through the generic post‑handshake dispatcher.  
- When EKU is in progress, the implementation tolerates interleaved NewSessionTicket and continues waiting for the EKU response to complete the exchange.  
- The EKU state machine explicitly tracks whether the local endpoint is acting as initiator or responder and enforces the correct key‑update ordering for each role.

### Program updates
- `programs/ssl/ssl_client2.c`: CLI options for EKU (`eku`, `eku_updates`, `eku_after`) and time‑based application data exchange (`appdata_seconds`).
- `programs/ssl/ssl_server2.c`: same EKU options plus time‑based application data exchange.

### Test updates
- `tests/ssl-opt.sh`: EKU functional testcases for `ssl_client2`/`ssl_server2`, including timed app‑data exchange and concurrent initiation.
- `tests/compat.sh`: EKU mbedTLS↔mbedTLS interop sanity test in the compat test framework (client‑initiated EKU).
- `tests/eku-interop.sh`: EKU interop matrix for mbedTLS (server) ↔ Rustls (client).

## Using EKU in `ssl_client2` and `ssl_server2`

### Enable EKU

Use `eku=1` on both client and server to enable Extended Key Update. When EKU is enabled, classic TLS 1.3 KeyUpdate is disabled and must not be used.

### Trigger EKU exchanges

- `eku_updates=N`  
  Run `N` EKU exchanges.  
  If `eku_after=0` (default), EKU runs immediately after the handshake.

- `eku_after=N`  
  Run EKU **every N application data exchanges**.  
  Example: `eku_after=1` triggers EKU after each app‑data exchange.

### Time‑based application data exchange

- `appdata_seconds=N`  
  Exchange application data for `N` seconds (instead of a fixed number of exchanges).
  Requires `MBEDTLS_TIMING_C`; otherwise the program reports an error.

### Notes on interleaving

- For server‑initiated EKU after an exchange, the EKU is triggered before sending the server’s application response to avoid overlapping with client‑initiated post‑handshake traffic.  
- In time‑based loops, EKU is scheduled based on completed exchanges rather than on elapsed time, so EKU frequency scales with throughput.

### Examples

Client‑initiated EKU immediately after handshake:
```
ssl_server2 force_version=tls13 eku=1
ssl_client2 force_version=tls13 eku=1 eku_updates=1
```

Server‑initiated EKU after each exchange:
```
ssl_server2 force_version=tls13 exchanges=2 eku=1 eku_updates=1 eku_after=1
ssl_client2 force_version=tls13 exchanges=2 eku=1
```

Timed app‑data exchange with periodic EKU:
```
ssl_server2 force_version=tls13 exchanges=0 appdata_seconds=5 eku=1 eku_updates=1 eku_after=1
ssl_client2 force_version=tls13 exchanges=0 appdata_seconds=5 eku=1 eku_after=1
```

## Interop testing with Rustls (`tests/eku-interop.sh`)

`tests/eku-interop.sh` exercises EKU interoperability between:
- `ssl_server2` from this mbedTLS tree
- the `eku_client` example binary from a sibling Rustls checkout

The script covers the same high-level EKU scenarios as the local `ssl-opt.sh`
tests, but across implementations:

1. Client-initiated EKU
2. Both sides initiate EKU
3. Client-initiated EKU with tickets disabled
4. Client-initiated EKU twice
5. Server-initiated EKU after one app-data exchange
6. Timed app-data exchange with periodic EKU

The script starts an mbedTLS server, runs the Rustls client against it, and
verifies each scenario end-to-end.

### Layout expected by the script

The script assumes a workspace layout like this:

```
workspace/
  mbedtls/
  rustls/
```

The Rustls tree is expected to provide:
- `Cargo.toml`
- `test-ca/rsa-2048/ca.cert`
- `test-ca/rsa-2048/end.fullchain`
- `test-ca/rsa-2048/end.key`
- the `rustls-examples --bin eku_client` example binary

### Running the Rustls interop tests

From the `mbedtls/` directory:

```
./tests/eku-interop.sh
```

Optionally, set `RUSTLS_DIR` if the Rustls checkout is not in `../rustls`:

```
RUSTLS_DIR=/path/to/rustls ./tests/eku-interop.sh
```
