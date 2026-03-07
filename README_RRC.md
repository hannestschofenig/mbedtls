# Return Routability Check (RRC)

## Introduction

Return Routability Check (RRC) is a DTLS mechanism to validate a peer's new
network address after endpoint changes (for example due to NAT rebinding).
Its purpose is to reduce amplification risk when Connection ID (CID) is in use.

In short, the endpoint that detects an address change sends a `path_challenge`,
and the peer proves reachability by returning a matching `path_response`.

For the normative specification and security considerations, see RFC 9853.

This document describes a test for the **DTLS Return Routability Check (RRC)** feature based on the test setup shown in the next sub-section.

## Test Setup

```text
+-----------+      DTLS/CoAP       +---------+      forwarded traffic      +-----------+
|  Client   | -------------------> |   NAT   | --------------------------> |  Server   |
| (cf-      |                      | (cf-nat)|                             | (cf-      |
| plugtest- | <------------------- |         | <-------------------------- | plugtest- |
| or dtls-  |   responses / RRC    |         |   responses / challenge     | server)   |
| rrc)      |                      |         |                             |           |
+-----------+                      +---------+                             +-----------+
                                        |                                       |
                                        | listen :6684                          | DTLS :5684
```

## Repositories and Branches

This test setup uses the following repositories and branches:

- `californium`:
  - repository: `https://github.com/eclipse-californium/californium.git`
  - branch: `feature/rrc`
  - contains Achim Kraus' RRC implementation in Scandium
- `dtls-rrc`:
  - repository: `https://github.com/thomas-fossati/dtls-rrc.git`
  - branch: `master`
  - contains Thomas Fossati's DTLS RRC implementation used as alternative client
- `mbedtls`:
  - repository: `https://github.com/hannestschofenig/mbedtls.git`
  - branch: `rrc`
  - contains the Mbed TLS client-side RRC implementation used in this repo

## Goal

Demonstrate that an RRC flow is executed when an IP endpoint change occurs (simulated via NAT/spoof):

- `Path Challenge` is sent
- `Path Response` is received
- The response is confirmed as matching

## Prerequisites

- Branch: `feature/rrc`
- Java 17+ in `PATH`
- Maven in `PATH`
- Go 1.22+ in `PATH` (only for Thomas Fossati client in `dtls-rrc`)
- CMake 3.20+ and C compiler (for Mbed TLS client in `mbedtls`)
- Start all commands from the workspace root (the directory containing `californium`, `dtls-rrc`, `mbedtls`)

## Relevant Components

- **Server**: Achim Kraus' `cf-plugtest-server` (CoAP/DTLS server, Scandium-based stack)
- **NAT**: `cf-nat` (NAT/endpoint-change simulator)
- **Client**: `cf-plugtest-client` (test client with DTLS CID)
- **Alternative Client**: Thomas Fossati's `dtls-rrc` implementation (`examples/dial/californium-rrc`)
- **Alternative Client**: Mbed TLS RRC client (`programs/ssl/dtls_rrc_client`)

## Build

From the project root:

```bash
cd californium
mvn -pl demo-apps/cf-plugtest-server,cf-utils/cf-nat,demo-apps/cf-plugtest-client -am package -DskipTests
```

For the client from Thomas Fossati:

```bash
cd dtls-rrc
go list ./...
```

For the Mbed TLS client:

```bash
cd mbedtls
cmake -S . -B build-rrc -DCMAKE_BUILD_TYPE=Debug
cmake --build build-rrc -j
```

Required Mbed TLS config macros for RRC:

- `MBEDTLS_SSL_DTLS_CONNECTION_ID`
- `MBEDTLS_SSL_DTLS_CONNECTION_ID_RRC`

`MBEDTLS_SSL_DTLS_CONNECTION_ID_RRC` depends on `MBEDTLS_SSL_DTLS_CONNECTION_ID`.

## Optional Server Log Configuration (recommended)

Create `/tmp/logback-rrc-test.xml`:

```xml
<configuration>
  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <encoder>
      <pattern>%date %-5level [%logger{48}]: %msg%n</pattern>
    </encoder>
  </appender>

  <logger name="org.eclipse.californium.scandium.DTLSConnector" level="INFO"/>
  <logger name="org.eclipse.californium.scandium.dtls" level="INFO"/>
  <root level="INFO">
    <appender-ref ref="STDOUT"/>
  </root>
</configuration>
```

This logging makes RRC events (`Path Challenge` / `Path Response`) visible.

## Startup Order

### 1) Start the Plugtest Server

```bash
java -Dlogback.configurationFile=/tmp/logback-rrc-test.xml \
  -jar californium/demo-apps/cf-plugtest-server/target/cf-plugtest-server-4.0.0-SNAPSHOT.jar \
  --dtls-only --no-external --no-tcp --no-oscore \
  2>&1 | tee /tmp/rrc_server.log
```

Parameters:

- `--dtls-only`: use DTLS endpoints only
- `--no-external`: do not publish external interfaces
- `--no-tcp`: disable CoAP/TCP
- `--no-oscore`: disable OSCORE

### 2) Start NAT

```bash
java -jar californium/cf-utils/cf-nat/target/cf-nat-4.0.0-SNAPSHOT.jar \
  :6684 localhost:5684 -tnat=5000 \
  2>&1 | tee /tmp/rrc_nat.log
```

Parameters:

- `:6684`: NAT listens locally on UDP port 6684
- `localhost:5684`: forward traffic to the local Plugtest server
- `-tnat=5000`: NAT entry timeout is 5000 ms

NAT console commands:

- `spoof`: send the next packet with a new ephemeral source address (simulated address change)
- `reassign`: reassign NAT mappings
- `info` or empty line: print status

### 3) Start the Plugtest Client

```bash
timeout 240s java -jar californium/demo-apps/cf-plugtest-client/target/cf-plugtest-client-4.0.0-SNAPSHOT.jar \
  -C /tmp/CaliforniumPlugtest3-client.properties \
  -v --no-ping --no-oscore --cid-length=4 \
  -i Client_identity -s secretPSK \
  coaps://localhost:6684 \
  2>&1 | tee /tmp/rrc_client.log
```

Parameters:

- `-C /tmp/...properties`: separate client config file (prevents overwriting server config)
- `-v`: verbose output
- `--no-ping`: disable initial ping
- `--no-oscore`: disable OSCORE
- `--cid-length=4`: DTLS Connection ID length = 4 bytes (RRC-relevant)
- `-i Client_identity`: PSK identity
- `-s secretPSK`: PSK secret
- `coaps://localhost:6684`: target is NAT, not the server directly

### 3b) Start Thomas Fossati's DTLS-RRC Client (Cross-Interop)

This uses the additional example at:
`dtls-rrc/examples/dial/californium-rrc/main.go`

```bash
cd dtls-rrc
go run ./examples/dial/californium-rrc \
  -host 127.0.0.1 \
  -port 6684 \
  -psk-id Client_identity \
  -psk-secret secretPSK \
  -cid-length 4 \
  -wait 7s \
  -timeout 8s
```

Parameters:

- `-host 127.0.0.1`: connect locally (NAT side)
- `-port 6684`: connect to NAT, not directly to server
- `-psk-id Client_identity`: PSK identity accepted by `cf-plugtest-server`
- `-psk-secret secretPSK`: matching PSK secret
- `-cid-length 4`: request DTLS CID support
- `-wait 7s`: wait long enough for NAT timeout (`-tnat=5000`) before second request
- `-timeout 8s`: response timeout per request

Expected client output:

- `connected to 127.0.0.1:6684`
- three `response #n` lines
- `response #n code: 2.05` for each request

### 3c) Start Mbed TLS DTLS-RRC Client (Cross-Interop)

This uses:
`mbedtls/programs/ssl/dtls_rrc_client.c`

Run:

```bash
cd mbedtls
./build-rrc/programs/ssl/dtls_rrc_client
```

What this client does:

- DTLS 1.2 PSK handshake to `127.0.0.1:6684` (NAT)
- CID enabled with length 4
- sends 3 CoAP `GET /rrc` requests
- waits 7 seconds between request #1 and #2 (to force NAT mapping timeout)
- auto-responds to incoming RRC `path_challenge` with `path_response` (client-side RRC implementation)

Expected output (example pattern):

- `. Performing DTLS handshake...`
- `< req1 recv ...`
- `. Waiting 7s to expire NAT mapping...`
- `< req2 recv ...`
- `< req3 recv ...`

## Trigger RRC Explicitly (while client is running)

In the NAT terminal:

```text
spoof
```

This triggers an endpoint change. Subsequent traffic should trigger RRC.

## Logfile Analysis

### Server side (`/tmp/rrc_server.log`)

Look for:

- `Sent Return Routability Check: Path Challenge`
- `Received Return Routability Check: Path Response`
- `Received matching Path Response`

Example:

```bash
rg -n "Path Challenge|Path Response|Received matching" /tmp/rrc_server.log
```

For the Thomas Fossati client run, you should also observe the peer port change between request #1 and #2, for example:

- first request from `127.0.0.1:34823`
- second request from `127.0.0.1:51481`
- plus RRC lines (`Path Challenge` / `Path Response`)

For the Mbed TLS client run, you should observe the same pattern:

- request #1 from one client UDP source port
- request #2/#3 from a different source port after the 7-second wait
- and the RRC lines:
  - `Sent Return Routability Check: Path Challenge`
  - `Received Return Routability Check: Path Response`
  - `Received matching Path Response`

### Client side (`/tmp/rrc_client.log`)

Look for:

- `Received Return Routability Check: Path Challenge`
- `Sent Return Routability Check: Path Response`

```bash
rg -n "Path Challenge|Path Response" /tmp/rrc_client.log
```

## Typical Failure Patterns

- Handshake timeout:
  - check whether server listens on `5684` and NAT on `6684`
- `go run` cannot write build cache:
  - set `GOCACHE=/tmp/go-build` and rerun
- `cmake` build fails due to missing tools:
  - ensure `cmake --version` works and a C compiler is installed
- Server in wrong DTLS role mode:
  - avoid shared config files; always start the client with a separate `-C` file
- No RRC log lines:
  - set `org.eclipse.californium.scandium.DTLSConnector` log level to `INFO`/`DEBUG`
  - ensure endpoint change actually occurs (`spoof`, or enough NAT timeout plus pause)

## Cleanup

Stop running processes:

```bash
pkill -f cf-plugtest-client || true
pkill -f cf-nat || true
pkill -f cf-plugtest-server || true
```

Check ports:

```bash
ss -lunp | rg "(:5684|:6684)" || true
```
