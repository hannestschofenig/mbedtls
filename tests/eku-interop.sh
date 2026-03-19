#!/usr/bin/env bash
set -euo pipefail

# mbedTLS repo root (script lives in tests/)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
RUSTLS_DIR="${RUSTLS_DIR:-${WORKSPACE_ROOT}/rustls}"

# Prefer a built server binary if available, otherwise fall back to source tree.
if [[ -x "${ROOT_DIR}/build/programs/ssl/ssl_server2" ]]; then
    server_bin="${ROOT_DIR}/build/programs/ssl/ssl_server2"
else
    server_bin="${ROOT_DIR}/programs/ssl/ssl_server2"
fi
# Rustls EKU client (built/run via cargo).
client_cmd=(cargo run --manifest-path "${RUSTLS_DIR}/Cargo.toml" -p rustls-examples --bin eku_client --)

host="127.0.0.1"
port="4433"
next_port="${EKU_INTEROP_BASE_PORT:-4433}"
ca_cert="${RUSTLS_DIR}/test-ca/rsa-2048/ca.cert"
server_cert="${RUSTLS_DIR}/test-ca/rsa-2048/end.fullchain"
server_key="${RUSTLS_DIR}/test-ca/rsa-2048/end.key"
server_name="testserver.com"
debug_level="${DEBUG_LEVEL:-}"

if [[ ! -f "${RUSTLS_DIR}/Cargo.toml" ]]; then
    echo "rustls checkout not found at ${RUSTLS_DIR}" >&2
    exit 1
fi

# Start the mbedTLS server with TLS 1.3 forced and provided key/cert.
run_server() {
    local debug_arg=()
    if [[ -n "${debug_level}" ]]; then
        debug_arg=("debug_level=${debug_level}")
    fi
    "${server_bin}" force_version=tls13 server_port="${port}" exchanges=1 "${debug_arg[@]}" "$@" \
        crt_file="${server_cert}" \
        key_file="${server_key}"
}

# Run the rustls EKU client with provided arguments.
run_client() {
    "${client_cmd[@]}" "$@"
}

# Helper to label and execute a test function.
run_test() {
    local name="$1"
    shift

    echo "==> ${name}"
    "$@"
    echo "==> OK: ${name}"
    echo
}

set_test_port() {
    port="${next_port}"
    next_port=$((next_port + 1))
}

# Wait for the server process to reach its accept loop without consuming a
# connection slot.
wait_for_server() {
    local server_pid="$1"
    local tries=100
    while kill -0 "${server_pid}" 2>/dev/null; do
        if [[ -f /tmp/eku_server.log ]] &&
           grep -q "Waiting for a remote connection" /tmp/eku_server.log; then
            return 0
        fi

        tries=$((tries - 1))
        if [[ ${tries} -le 0 ]]; then
            echo "Server did not become ready on ${host}:${port}" >&2
            return 1
        fi
        sleep 0.1
    done

    echo "Server exited before becoming ready on ${host}:${port}" >&2
    return 1
}

# Client initiates one EKU after handshake; server just responds.
test_client_initiated() {
    set_test_port
    run_server eku=1 exchanges=2 > /tmp/eku_server.log 2>&1 &
    local server_pid=$!
    trap 'kill "${server_pid}" 2>/dev/null || true' RETURN

    wait_for_server "${server_pid}"
    run_client "${host}" "${port}" "${ca_cert}" "${server_name}"

    kill "${server_pid}" 2>/dev/null || true
    trap - RETURN
}

# Both client and server initiate an EKU after handshake.
test_both_sides_initiate() {
    set_test_port
    run_server eku=1 eku_updates=1 exchanges=2 > /tmp/eku_server.log 2>&1 &
    local server_pid=$!
    trap 'kill "${server_pid}" 2>/dev/null || true' RETURN

    wait_for_server "${server_pid}"
    run_client "${host}" "${port}" "${ca_cert}" "${server_name}"

    kill "${server_pid}" 2>/dev/null || true
    trap - RETURN
}

# Client-initiated EKU with tickets disabled on the server.
test_client_initiated_no_tickets() {
    set_test_port
    run_server eku=1 tickets=0 exchanges=2 > /tmp/eku_server.log 2>&1 &
    local server_pid=$!
    trap 'kill "${server_pid}" 2>/dev/null || true' RETURN

    wait_for_server "${server_pid}"
    run_client "${host}" "${port}" "${ca_cert}" "${server_name}"

    kill "${server_pid}" 2>/dev/null || true
    trap - RETURN
}

# Client initiates two consecutive EKUs after handshake.
test_client_initiated_twice() {
    set_test_port
    run_server eku=1 exchanges=2 > /tmp/eku_server.log 2>&1 &
    local server_pid=$!
    trap 'kill "${server_pid}" 2>/dev/null || true' RETURN

    wait_for_server "${server_pid}"
    run_client --initiator-count 2 "${host}" "${port}" "${ca_cert}" "${server_name}"

    kill "${server_pid}" 2>/dev/null || true
    trap - RETURN
}

# Server initiates EKU after the first app-data exchange; client only responds.
test_server_initiated_after_exchange() {
    set_test_port
    run_server eku=1 eku_updates=1 eku_after=1 exchanges=2 > /tmp/eku_server.log 2>&1 &
    local server_pid=$!
    trap 'kill "${server_pid}" 2>/dev/null || true' RETURN

    wait_for_server "${server_pid}"
    run_client --no-initiator "${host}" "${port}" "${ca_cert}" "${server_name}"

    kill "${server_pid}" 2>/dev/null || true
    trap - RETURN
}

# Timed app-data exchanges; client triggers EKU after each exchange.
test_timed_appdata_exchanges() {
    set_test_port
    run_server eku=1 eku_updates=1 eku_after=1 exchanges=0 appdata_seconds=1 > /tmp/eku_server.log 2>&1 &
    local server_pid=$!
    trap 'kill "${server_pid}" 2>/dev/null || true' RETURN

    wait_for_server "${server_pid}"
    run_client --eku-after 1 --eku-updates 1 --appdata-seconds 1 "${host}" "${port}" "${ca_cert}" "${server_name}"

    kill "${server_pid}" 2>/dev/null || true
    trap - RETURN
}

cat <<'DOC'
EKU interop tests (mbedTLS server ↔ Rustls client)

1) Client-initiated EKU
   - mbedTLS server runs with EKU enabled and two app-data exchanges.
   - Rustls client enables EKU and initiates one EKU after handshake.

2) Both sides initiate EKU
   - mbedTLS server initiates one EKU right after handshake.
   - Rustls client also initiates one EKU after handshake.

3) Client-initiated EKU (tickets disabled)
   - mbedTLS server runs with EKU enabled, disables tickets.
   - Rustls client initiates one EKU after handshake.

4) Client-initiated EKU twice
   - Rustls client initiates two consecutive EKUs after handshake.

5) Server-initiated EKU (after exchange)
   - mbedTLS server triggers EKU after first app-data exchange.
   - Rustls client does not initiate EKU, only responds.

6) Timed appdata exchanges with EKU
   - Both sides exchange app-data for 1 second.
   - Rustls client initiates EKU every exchange; server responds.
DOC

echo
run_test "Client-initiated EKU" test_client_initiated
run_test "Both sides initiate EKU" test_both_sides_initiate
run_test "Client-initiated EKU (tickets disabled)" test_client_initiated_no_tickets
run_test "Client-initiated EKU twice" test_client_initiated_twice
run_test "Server-initiated EKU (after exchange)" test_server_initiated_after_exchange
run_test "Timed appdata exchanges with EKU" test_timed_appdata_exchanges
