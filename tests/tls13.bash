#!/bin/sh

# Test various options that are not covered by compat.sh
#
# Here the goal is not to cover every ciphersuite/version, but
# rather specific options (max fragment length, truncated hmac, etc)
# or procedures (session resumption from cache or ticket, renego, etc).
#
# Assumes a build with default options.
set -u

# Limit the size of each log to 10 GiB, in case of failures with this script
# where it may output seemingly unlimited length error logs.
ulimit -f 20971520

# default values, can be overriden by the environment
if [ -n "${OS:-}" ]; then
if [ "$OS" = "Windows_NT" ]; then
: ${P_SRV:=../visualc/VS2010/Debug/ssl_server2.exe}
: ${P_CLI:=../visualc/VS2010/Debug/ssl_client2.exe}
: ${P_PXY:=../visualc/VS2010/Debug/udp_proxy.exe}
else # OS other than Windows
: ${P_SRV:=../programs/ssl/ssl_server2}
: ${P_CLI:=../programs/ssl/ssl_client2}
: ${P_PXY:=../programs/test/udp_proxy}
fi
else # No OS set
: ${P_SRV:=../programs/ssl/ssl_server2}
: ${P_CLI:=../programs/ssl/ssl_client2}
: ${P_PXY:=../programs/test/udp_proxy}
fi

: ${OPENSSL_CMD:=openssl} # OPENSSL would conflict with the build system
: ${GNUTLS_CLI:=gnutls-cli}
: ${GNUTLS_SERV:=gnutls-serv}
: ${MBEDTLS_DEBUG_LEVEL:=debug_level=5}

O_SRV="$OPENSSL_CMD s_server -www -cert data_files/server5.crt -key data_files/server5.key"
O_CLI="echo 'GET / HTTP/1.0' | $OPENSSL_CMD s_client"
G_SRV="$GNUTLS_SERV --x509certfile data_files/server5.crt --x509keyfile data_files/server5.key"
G_CLI="echo 'GET / HTTP/1.0' | $GNUTLS_CLI --x509cafile data_files/test-ca_cat12.crt"



TESTS=0
FAILS=0
SKIPS=0

CONFIG_H='../include/mbedtls/config.h'

MEMCHECK=0
FILTER='.*'
EXCLUDE='^$'

print_usage() {
    echo "Usage: $0 [options]"
    printf "  -h|--help\tPrint this help.\n"
    printf "  -m|--memcheck\tCheck memory leaks and errors.\n"
    printf "  -f|--filter\tOnly matching tests are executed (default: '$FILTER')\n"
    printf "  -e|--exclude\tMatching tests are excluded (default: '$EXCLUDE')\n"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--filter)
                shift; FILTER=$1
                ;;
            -e|--exclude)
                shift; EXCLUDE=$1
                ;;
            -m|--memcheck)
                MEMCHECK=1
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown argument: '$1'"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

# skip next test if the flag is not enabled in config.h
requires_config_enabled() {
    if grep "^#define $1" $CONFIG_H > /dev/null; then :; else
        SKIP_NEXT="YES"
    fi
}

# skip next test if OpenSSL doesn't support FALLBACK_SCSV
requires_openssl_with_fallback_scsv() {
    if [ -z "${OPENSSL_HAS_FBSCSV:-}" ]; then
        if $OPENSSL_CMD s_client -help 2>&1 | grep fallback_scsv >/dev/null
        then
            OPENSSL_HAS_FBSCSV="YES"
        else
            OPENSSL_HAS_FBSCSV="NO"
        fi
    fi
    if [ "$OPENSSL_HAS_FBSCSV" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if GnuTLS isn't available
requires_gnutls() {
    if [ -z "${GNUTLS_AVAILABLE:-}" ]; then
        if ( which "$GNUTLS_CLI" && which "$GNUTLS_SERV" ) >/dev/null 2>&1; then
            GNUTLS_AVAILABLE="YES"
        else
            GNUTLS_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if IPv6 isn't available on this host
requires_ipv6() {
    if [ -z "${HAS_IPV6:-}" ]; then
        $P_SRV server_addr='::1' > $SRV_OUT 2>&1 &
        SRV_PID=$!
        sleep 1
        kill $SRV_PID >/dev/null 2>&1
        if grep "NET - Binding of the socket failed" $SRV_OUT >/dev/null; then
            HAS_IPV6="NO"
        else
            HAS_IPV6="YES"
        fi
        rm -r $SRV_OUT
    fi

    if [ "$HAS_IPV6" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip the next test if valgrind is in use
not_with_valgrind() {
    if [ "$MEMCHECK" -gt 0 ]; then
        SKIP_NEXT="YES"
    fi
}

# multiply the client timeout delay by the given factor for the next test
needs_more_time() {
    CLI_DELAY_FACTOR=$1
}

# print_name <name>
print_name() {
    printf "$1 "
    LEN=$(( 72 - `echo "$1" | wc -c` ))
    for i in `seq 1 $LEN`; do printf '.'; done
    printf ' '

    TESTS=$(( $TESTS + 1 ))
}

# fail <message>
fail() {
    echo "FAIL"
    echo "  ! $1"

    mv $SRV_OUT o-srv-${TESTS}.log
    mv $CLI_OUT o-cli-${TESTS}.log
    if [ -n "$PXY_CMD" ]; then
        mv $PXY_OUT o-pxy-${TESTS}.log
    fi
    echo "  ! outputs saved to o-XXX-${TESTS}.log"

    if [ "X${USER:-}" = Xbuildbot -o "X${LOGNAME:-}" = Xbuildbot ]; then
        echo "  ! server output:"
        cat o-srv-${TESTS}.log
        echo "  ! ========================================================"
        echo "  ! client output:"
        cat o-cli-${TESTS}.log
        if [ -n "$PXY_CMD" ]; then
            echo "  ! ========================================================"
            echo "  ! proxy output:"
            cat o-pxy-${TESTS}.log
        fi
        echo ""
    fi

    FAILS=$(( $FAILS + 1 ))
}

# is_polar <cmd_line>
is_polar() {
    echo "$1" | grep 'ssl_server2\|ssl_client2' > /dev/null
}

# openssl s_server doesn't have -www with DTLS
check_osrv_dtls() {
    if echo "$SRV_CMD" | grep 's_server.*-dtls' >/dev/null; then
        NEEDS_INPUT=1
        SRV_CMD="$( echo $SRV_CMD | sed s/-www// )"
    else
        NEEDS_INPUT=0
    fi
}

# provide input to commands that need it
provide_input() {
    if [ $NEEDS_INPUT -eq 0 ]; then
        return
    fi

    while true; do
        echo "HTTP/1.0 200 OK"
        sleep 1
    done
}

# has_mem_err <log_file_name>
has_mem_err() {
    if ( grep -F 'All heap blocks were freed -- no leaks are possible' "$1" &&
         grep -F 'ERROR SUMMARY: 0 errors from 0 contexts' "$1" ) > /dev/null
    then
        return 1 # false: does not have errors
    else
        return 0 # true: has errors
    fi
}

# wait for server to start: two versions depending on lsof availability
wait_server_start() {
    if which lsof >/dev/null 2>&1; then
        START_TIME=$( date +%s )
        DONE=0

        # make a tight loop, server usually takes less than 1 sec to start
        if [ "$DTLS" -eq 1 ]; then
            while [ $DONE -eq 0 ]; do
                if lsof -nbi UDP:"$SRV_PORT" 2>/dev/null | grep UDP >/dev/null
                then
                    DONE=1
                elif [ $(( $( date +%s ) - $START_TIME )) -gt $DOG_DELAY ]; then
                    echo "SERVERSTART TIMEOUT"
                    echo "SERVERSTART TIMEOUT" >> $SRV_OUT
                    DONE=1
                fi
            done
        else
            while [ $DONE -eq 0 ]; do
                if lsof -nbi TCP:"$SRV_PORT" 2>/dev/null | grep LISTEN >/dev/null
                then
                    DONE=1
                elif [ $(( $( date +%s ) - $START_TIME )) -gt $DOG_DELAY ]; then
                    echo "SERVERSTART TIMEOUT"
                    echo "SERVERSTART TIMEOUT" >> $SRV_OUT
                    DONE=1
                fi
            done
        fi
    else
        sleep "$START_DELAY"
    fi
}

# wait for client to terminate and set CLI_EXIT
# must be called right after starting the client
wait_client_done() {
    CLI_PID=$!

    CLI_DELAY=$(( $DOG_DELAY * $CLI_DELAY_FACTOR ))
    CLI_DELAY_FACTOR=1

    ( sleep $CLI_DELAY; echo "===CLIENT_TIMEOUT===" >> $CLI_OUT; kill $CLI_PID ) &
    DOG_PID=$!

    wait $CLI_PID
    CLI_EXIT=$?

    kill $DOG_PID >/dev/null 2>&1
    wait $DOG_PID

    echo "EXIT: $CLI_EXIT" >> $CLI_OUT
}

# check if the given command uses dtls and sets global variable DTLS
detect_dtls() {
    if echo "$1" | grep 'dtls=1\|-dtls1\|-u' >/dev/null; then
        DTLS=1
    else
        DTLS=0
    fi
}

# Usage: run_test name [-p proxy_cmd] srv_cmd cli_cmd cli_exit [option [...]]
# Options:  -s pattern  pattern that must be present in server output
#           -c pattern  pattern that must be present in client output
#           -S pattern  pattern that must be absent in server output
#           -C pattern  pattern that must be absent in client output
run_test() {
    NAME="$1"
    shift 1

    if echo "$NAME" | grep "$FILTER" | grep -v "$EXCLUDE" >/dev/null; then :
    else
        SKIP_NEXT="NO"
        return
    fi

    print_name "$NAME"

    # should we skip?
    if [ "X$SKIP_NEXT" = "XYES" ]; then
        SKIP_NEXT="NO"
        echo "SKIP"
        SKIPS=$(( $SKIPS + 1 ))
        return
    fi

    # does this test use a proxy?
    if [ "X$1" = "X-p" ]; then
        PXY_CMD="$2"
        shift 2
    else
        PXY_CMD=""
    fi

    # get commands and client output
    SRV_CMD="$1"
    CLI_CMD="$2"
    CLI_EXPECT="$3"
    shift 3

    # fix client port
    if [ -n "$PXY_CMD" ]; then
        CLI_CMD=$( echo "$CLI_CMD" | sed s/+SRV_PORT/$PXY_PORT/g )
    else
        CLI_CMD=$( echo "$CLI_CMD" | sed s/+SRV_PORT/$SRV_PORT/g )
    fi

    # update DTLS variable
    detect_dtls "$SRV_CMD"

    # prepend valgrind to our commands if active
    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SRV_CMD"; then
            SRV_CMD="valgrind --leak-check=full $SRV_CMD"
        fi
        if is_polar "$CLI_CMD"; then
            CLI_CMD="valgrind --leak-check=full $CLI_CMD"
        fi
    fi

    TIMES_LEFT=2
    while [ $TIMES_LEFT -gt 0 ]; do
        TIMES_LEFT=$(( $TIMES_LEFT - 1 ))

        # run the commands
        if [ -n "$PXY_CMD" ]; then
            echo "$PXY_CMD" > $PXY_OUT
            $PXY_CMD >> $PXY_OUT 2>&1 &
            PXY_PID=$!
            # assume proxy starts faster than server
        fi

        check_osrv_dtls
        echo "$SRV_CMD" > $SRV_OUT
        provide_input | $SRV_CMD >> $SRV_OUT 2>&1 &
        SRV_PID=$!
        wait_server_start

        echo "$CLI_CMD" > $CLI_OUT
        eval "$CLI_CMD" >> $CLI_OUT 2>&1 &
        wait_client_done

        # terminate the server (and the proxy)
        kill $SRV_PID
        wait $SRV_PID
        if [ -n "$PXY_CMD" ]; then
            kill $PXY_PID >/dev/null 2>&1
            wait $PXY_PID
        fi

        # retry only on timeouts
        if grep '===CLIENT_TIMEOUT===' $CLI_OUT >/dev/null; then
            printf "RETRY "
        else
            TIMES_LEFT=0
        fi
    done

    # check if the client and server went at least to the handshake stage
    # (useful to avoid tests with only negative assertions and non-zero
    # expected client exit to incorrectly succeed in case of catastrophic
    # failure)
    if is_polar "$SRV_CMD"; then
        if grep "Performing the SSL/TLS handshake" $SRV_OUT >/dev/null; then :;
        else
            fail "server or client failed to reach handshake stage"
            return
        fi
    fi
    if is_polar "$CLI_CMD"; then
        if grep "Performing the SSL/TLS handshake" $CLI_OUT >/dev/null; then :;
        else
            fail "server or client failed to reach handshake stage"
            return
        fi
    fi

    # check server exit code
    if [ $? != 0 ]; then
        fail "server fail"
        return
    fi

    # check client exit code
    if [ \( "$CLI_EXPECT" = 0 -a "$CLI_EXIT" != 0 \) -o \
         \( "$CLI_EXPECT" != 0 -a "$CLI_EXIT" = 0 \) ]
    then
        fail "bad client exit code (expected $CLI_EXPECT, got $CLI_EXIT)"
        return
    fi

    # check other assertions
    # lines beginning with == are added by valgrind, ignore them
    while [ $# -gt 0 ]
    do
        case $1 in
            "-s")
                if grep -v '^==' $SRV_OUT | grep "$2" >/dev/null; then :; else
                    fail "-s $2"
                    return
                fi
                ;;

            "-c")
                if grep -v '^==' $CLI_OUT | grep "$2" >/dev/null; then :; else
                    fail "-c $2"
                    return
                fi
                ;;

            "-S")
                if grep -v '^==' $SRV_OUT | grep "$2" >/dev/null; then
                    fail "-S $2"
                    return
                fi
                ;;

            "-C")
                if grep -v '^==' $CLI_OUT | grep "$2" >/dev/null; then
                    fail "-C $2"
                    return
                fi
                ;;

            *)
                echo "Unknown test: $1" >&2
                exit 1
        esac
        shift 2
    done

    # check valgrind's results
    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SRV_CMD" && has_mem_err $SRV_OUT; then
            fail "Server has memory errors"
            return
        fi
        if is_polar "$CLI_CMD" && has_mem_err $CLI_OUT; then
            fail "Client has memory errors"
            return
        fi
    fi

    # if we're here, everything is ok
    echo "PASS"
    rm -f $SRV_OUT $CLI_OUT $PXY_OUT
}

cleanup() {
    rm -f $CLI_OUT $SRV_OUT $PXY_OUT $SESSION
    test -n "${SRV_PID:-}" && kill $SRV_PID >/dev/null 2>&1
    test -n "${PXY_PID:-}" && kill $PXY_PID >/dev/null 2>&1
    test -n "${CLI_PID:-}" && kill $CLI_PID >/dev/null 2>&1
    test -n "${DOG_PID:-}" && kill $DOG_PID >/dev/null 2>&1
    exit 1
}

#
# MAIN
#

if cd $( dirname $0 ); then :; else
    echo "cd $( dirname $0 ) failed" >&2
    exit 1
fi

get_options "$@"

# sanity checks, avoid an avalanche of errors
if [ ! -x "$P_SRV" ]; then
    echo "Command '$P_SRV' is not an executable file"
    exit 1
fi
if [ ! -x "$P_CLI" ]; then
    echo "Command '$P_CLI' is not an executable file"
    exit 1
fi
if [ ! -x "$P_PXY" ]; then
    echo "Command '$P_PXY' is not an executable file"
    exit 1
fi
if which $OPENSSL_CMD >/dev/null 2>&1; then :; else
    echo "Command '$OPENSSL_CMD' not found"
    exit 1
fi

# used by watchdog
MAIN_PID="$$"

# be more patient with valgrind
if [ "$MEMCHECK" -gt 0 ]; then
    START_DELAY=3
    DOG_DELAY=30
else
    START_DELAY=1
    DOG_DELAY=10
fi
CLI_DELAY_FACTOR=1

# Pick a "unique" server port in the range 10000-19999, and a proxy port
PORT_BASE="0000$$"
PORT_BASE="$( printf $PORT_BASE | tail -c 4 )"
SRV_PORT="1$PORT_BASE"
PXY_PORT="2$PORT_BASE"
unset PORT_BASE

# fix commands to use this port, force IPv4 while at it
# +SRV_PORT will be replaced by either $SRV_PORT or $PXY_PORT later
P_SRV="$P_SRV server_addr=127.0.0.1 server_port=$SRV_PORT"
P_CLI="$P_CLI server_addr=127.0.0.1 server_port=+SRV_PORT"
P_PXY="$P_PXY server_addr=127.0.0.1 server_port=$SRV_PORT listen_addr=127.0.0.1 listen_port=$PXY_PORT"
O_SRV="$O_SRV -accept $SRV_PORT -dhparam data_files/dhparams.pem"
O_CLI="$O_CLI -connect localhost:+SRV_PORT"
G_SRV="$G_SRV -p $SRV_PORT"
G_CLI="$G_CLI -p +SRV_PORT localhost"

# Also pick a unique name for intermediate files
SRV_OUT="srv_out.$$"
CLI_OUT="cli_out.$$"
PXY_OUT="pxy_out.$$"
SESSION="session.$$"

SKIP_NEXT="NO"

trap cleanup INT TERM HUP


			
# ----------------------------------- Default Ciphersuite ----------------------------------

echo ""
echo "*** Default Ciphersuite (PSK)  *** "
echo ""

run_test    "PSK" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            0 \
            -s "Protocol is TLSv1.3"

echo ""
echo "*** Default Ciphersuite (Public Key)  *** "
echo ""

run_test    "ECDHE-ECDSA (server auth only)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3  key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Certificate verification was skipped" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
			-c "Verifying peer X.509 certificate... ok" 

# ----------------------------------- Plain PSK ----------------------------------

echo ""
echo "*** PSK *** "
echo ""

# - the PSK-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated 
run_test    "TLS_AES_128_CCM_SHA256 with PSK" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_CCM_SHA256 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_128_CCM_SHA256" 

# - the PSK-based ciphersuite exchange is executed
# - AES-128-GCM is negotiated 
run_test    "TLS_AES_128_GCM_SHA256 with PSK" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_GCM_SHA256 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_128_GCM_SHA256" 
			

# - the PSK-based ciphersuite exchange is executed
# - AES-128-CCM-8 is negotiated 
run_test    "TLS_AES_128_CCM_8_SHA256 with PSK" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_CCM_8_SHA256 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_128_CCM_8_SHA256" 

			
# - the PSK-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with PSK" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_256_GCM_SHA384 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_256_GCM_SHA384" 

# ----------------------------------- PSK-ECDHE ----------------------------------
echo ""
echo "*** PSK-ECDHE *** "
echo ""
			
# - the PSK-ECDHE-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated 
run_test    "TLS_AES_128_CCM_SHA256 with PSK-ECDHE" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_CCM_SHA256 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_128_CCM_SHA256" 
			
# - the PSK-ECDHE-based ciphersuite exchange is executed
# - AES-128-GCM is negotiated 
run_test    "TLS_AES_128_GCM_SHA256 with PSK-ECDHE" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_GCM_SHA256 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_128_GCM_SHA256" 
			
# - the PSK-ECDHE-based ciphersuite exchange is executed
# - AES-128-CCM-8 is negotiated 
run_test    "TLS_AES_128_CCM_8_SHA256 with PSK-ECDHE" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_CCM_8_SHA256 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_128_CCM_8_SHA256" 

# - the PSK-ECDHE-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with PSK-ECDHE" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_256_GCM_SHA384 psk=010203 psk_identity=0a0b0c key_exchange_modes=psk_dhe" \
            0 \
            -s "Protocol is TLSv1.3" \
            -s "Ciphersuite is TLS_AES_256_GCM_SHA384" 


# ----------------------------------- ECDHE-ECDSA ----------------------------------
# + with built-in test certificates
# + server-to-client authentication only
# + server_name extension

echo ""
echo "*** ECDHE-ECDSA, server auth only with built-in test certificates ***"
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated 
run_test    "TLS_AES_128_CCM_SHA256 with ECDHE-ECDSA (server auth only)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3  key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Certificate verification was skipped" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-GCM is negotiated 
run_test    "TLS_AES_128_GCM_SHA256 with ECDHE-ECDSA (server auth only)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_GCM_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Certificate verification was skipped" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_GCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 
			
# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM-8 is negotiated 
run_test    "TLS_AES_128_CCM_8_SHA256 with ECDHE-ECDSA (server auth only)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3  key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_8_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Certificate verification was skipped" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_8_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with ECDHE-ECDSA (server auth only)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_256_GCM_SHA384 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Certificate verification was skipped" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_256_GCM_SHA384" \
			-c "Verifying peer X.509 certificate... ok" 
			
# ----------------------------------- ECDHE-ECDSA ----------------------------------
# + with built-in test certificates
# + mutual authentication
# + server_name extension


echo ""
echo "*** ECDHE-ECDSA, mutual authentication with built-in test certificates *** "
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated 
run_test    "TLS_AES_128_CCM_SHA256 with ECDHE-ECDSA (mutual auth)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-GCM is negotiated 
run_test    "TLS_AES_128_GCM_SHA256 with ECDHE-ECDSA (mutual auth)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_GCM_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_GCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 
			
# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM-8 is negotiated 
run_test    "TLS_AES_128_CCM_8_SHA256 with ECDHE-ECDSA (mutual auth)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_8_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_8_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with ECDHE-ECDSA (mutual auth)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_256_GCM_SHA384 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_256_GCM_SHA384" \
			-c "Verifying peer X.509 certificate... ok" 


echo ""
echo "*** ECDHE-ECDSA, server-only auth. with client sending empty cert *** "
echo ""

# ----------------------------------- ECDHE-ECDSA ----------------------------------
# + server asks client for authentication with certificate request message 
# + client responds with empty certificate
			
# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-GCM is negotiated 
# - Client responds to certificate request with an empty certificate 
# - Server accepts the lack of client authentication 

run_test    "TLS_AES_128_GCM_SHA256 with ECDHE-ECDSA (empty client certificate)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=optional key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_GCM_SHA256 key_exchange_modes=ecdhe_ecdsa auth_mode=none" \
            0 \
			-s "client has no certificate" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_GCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "write empty client certificate"

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated 
# - Client responds to certificate request with an empty certificate 
# - Server does NOT accept the lack of client authentication 

run_test    "TLS_AES_128_CCM_SHA256 with ECDHE-ECDSA (empty client certificate)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=ecdhe_ecdsa" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_SHA256 key_exchange_modes=ecdhe_ecdsa auth_mode=none" \
            1 \
			-s "empty certificate message received" \
			-s "client has no certificate" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "write empty client certificate"
			
# ----------------------------------- ECDHE-ECDSA ----------------------------------
# + with external SHA384 certificates
# + server-only authentication
# + server_name extension


echo ""
echo "*** ECDHE-ECDSA, server auth only with SHA384 certificates *** "
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with ECDHE-ECDSA (server auth only)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 key_exchange_modes=ecdhe_ecdsa ca_file=certs/ca.crt crt_file=certs/server.crt key_file=certs/server.key" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_256_GCM_SHA384 key_exchange_modes=ecdhe_ecdsa ca_file=certs/ca.crt crt_file=none key_file=none" \
            0 \
			-s "Verifying peer X.509 certificate... failed" \
			-s "Certificate verification was skipped" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_256_GCM_SHA384" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "subject name      : C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=localhost" \
			-c "signed using      : ECDSA with SHA384" \
			-c "EC key size       : 384 bits" 


			

# ----------------------------------- Ticket Exchange ----------------------------------
#
echo ""
echo "*** Ticket Exchange (combination of ECDHE-ECDSA and PSK auth) *** "
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated 
run_test    "TLS_AES_128_CCM_SHA256 with ECDHE-ECDSA (mutual auth) with ticket" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=all tickets=1" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_SHA256 key_exchange_modes=ecdhe_ecdsa reconnect=1 tickets=1" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "got ticket" \
			-c "client hello, adding psk_key_exchange_modes extension" \
			-c "client hello, adding pre_shared_key extension" \
			-c "found pre_shared_key extension" \
			-s "<= write new session ticket" 

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-GCM is negotiated 
run_test    "TLS_AES_128_GCM_SHA256 with ECDHE-ECDSA (mutual auth) with ticket" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=all tickets=1" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_GCM_SHA256 key_exchange_modes=ecdhe_ecdsa reconnect=1 tickets=1" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_GCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "got ticket" \
			-c "client hello, adding psk_key_exchange_modes extension" \
			-c "client hello, adding pre_shared_key extension" \
			-c "found pre_shared_key extension" \
			-s "<= write new session ticket"
			
# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM-8 is negotiated 
run_test    "TLS_AES_128_CCM_8_SHA256 with ECDHE-ECDSA (mutual auth) with ticket" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=all tickets=1" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_8_SHA256 key_exchange_modes=ecdhe_ecdsa reconnect=1 tickets=1" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_8_SHA256" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "got ticket" \
			-c "client hello, adding psk_key_exchange_modes extension" \
			-c "client hello, adding pre_shared_key extension" \
			-c "found pre_shared_key extension" \
			-s "<= write new session ticket"

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with ECDHE-ECDSA (mutual auth) with ticket" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=all tickets=1" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_256_GCM_SHA384 key_exchange_modes=ecdhe_ecdsa reconnect=1 tickets=1" \
            0 \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_256_GCM_SHA384" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "got ticket" \
			-c "client hello, adding psk_key_exchange_modes extension" \
			-c "client hello, adding pre_shared_key extension" \
			-c "found pre_shared_key extension" \
			-s "<= write new session ticket" 



echo ""
echo "*** ECDHE-ECDSA, server auth only with SHA384 certificates with ticket *** "
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-256-GCM is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with ECDHE-ECDSA (server auth only) with ticket" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 key_exchange_modes=all tickets=1 ca_file=certs/ca.crt crt_file=certs/server.crt key_file=certs/server.key" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_256_GCM_SHA384 key_exchange_modes=ecdhe_ecdsa ca_file=certs/ca.crt crt_file=none key_file=none reconnect=1 tickets=1" \
            0 \
			-s "Verifying peer X.509 certificate... failed" \
			-s "Certificate verification was skipped" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_256_GCM_SHA384" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "subject name      : C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=localhost" \
			-c "signed using      : ECDSA with SHA384" \
			-c "EC key size       : 384 bits" \
			-c "got ticket" \
			-c "client hello, adding psk_key_exchange_modes extension" \
			-c "client hello, adding pre_shared_key extension" \
			-c "found pre_shared_key extension" \
			-s "<= write new session ticket" 
				


# ----------------------------------- Early Data ----------------------------------
#
echo ""
echo "*** Early Data *** "
echo ""

# - the PSK-based ciphersuite exchange is executed
# - AES-256-GCM with SHA384 is negotiated 
run_test    "TLS_AES_256_GCM_SHA384 with external PSK (+early data)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 early_data=enabled key_exchange_modes=psk psk=010203 psk_identity=0a0b0c" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_256_GCM_SHA384 key_exchange_modes=psk early_data=enabled psk=010203 psk_identity=0a0b0c" \
            0 \
			-s "found early_data extension" \
			-s "Derive Early Secret with 'ext binder'" \
			-c "client hello, adding early_data extension" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_256_GCM_SHA384" \
			-c "Derive Early Secret with 'ext binder'" \
			-c "<= write EndOfEarlyData" \
			-s "<= parse early data" \
			-s "<= parse end_of_early_data" \
			
# - the PSK-based ciphersuite exchange is executed
# - AES-128-CCM with SHA256 is negotiated 
run_test    "TLS_AES_128_CCM_SHA256 with external PSK (+early data)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 early_data=enabled key_exchange_modes=psk psk=010203 psk_identity=0a0b0c" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_CCM_SHA256 key_exchange_modes=psk early_data=enabled psk=010203 psk_identity=0a0b0c" \
            0 \
			-s "found early_data extension" \
			-s "Derive Early Secret with 'ext binder'" \
			-c "client hello, adding early_data extension" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_SHA256" \
			-c "Derive Early Secret with 'ext binder'" \
			-c "<= write EndOfEarlyData" \
			-s "<= parse early data" \
			-s "<= parse end_of_early_data" \

			
# - the PSK-based ciphersuite exchange is executed
# - AES-128-GCM with SHA256 is negotiated 
run_test    "TLS_AES_128_GCM_SHA256 with external PSK (+early data)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 early_data=enabled key_exchange_modes=psk psk=010203 psk_identity=0a0b0c" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_GCM_SHA256 key_exchange_modes=psk early_data=enabled psk=010203 psk_identity=0a0b0c" \
            0 \
			-s "found early_data extension" \
			-s "Derive Early Secret with 'ext binder'" \
			-c "client hello, adding early_data extension" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_GCM_SHA256" \
			-c "Derive Early Secret with 'ext binder'" \
			-c "<= write EndOfEarlyData" \
			-s "<= parse early data" \
			-s "<= parse end_of_early_data" \
			
# - the PSK-based ciphersuite exchange is executed
# - AES-128-CCM-8 with SHA256 is negotiated 
run_test    "TLS_AES_128_CCM_8_SHA256 with external PSK (+early data)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 early_data=enabled key_exchange_modes=psk psk=010203 psk_identity=0a0b0c" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 force_ciphersuite=TLS_AES_128_CCM_8_SHA256 key_exchange_modes=psk early_data=enabled psk=010203 psk_identity=0a0b0c" \
            0 \
			-s "found early_data extension" \
			-s "Derive Early Secret with 'ext binder'" \
			-c "client hello, adding early_data extension" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_8_SHA256" \
			-c "Derive Early Secret with 'ext binder'" \
			-c "<= write EndOfEarlyData" \
			-s "<= parse early data" \
			-s "<= parse end_of_early_data" \

			
# ----------------------------------- Cookie / HRR  ----------------------------------
#
echo ""
echo "*** Cookie / HRR *** "
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM-8 is negotiated 
# - HRR is initiated
run_test    "TLS_AES_128_CCM_8_SHA256 with ECDHE-ECDSA (mutual auth)" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 auth_mode=required key_exchange_modes=ecdhe_ecdsa tickets=0 cookies=2" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_8_SHA256 key_exchange_modes=ecdhe_ecdsa" \
            0 \
			-s "Cookie extension missing. Need to send a HRR." \
			-s "write hello retry request" \
			-c "received HelloRetryRequest message" \
			-s "Verifying peer X.509 certificate... ok" \
			-s "subject name      : C=NL, O=PolarSSL, CN=PolarSSL Test Client 2" \
			-c "subject name      : C=NL, O=PolarSSL, CN=localhost" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_8_SHA256" \
			-c "Verifying peer X.509 certificate... ok" 


# ----------------------------------- ECDHE-ECDSA with HRR ----------------------------------
# + with built-in test certificates
# + server-to-client authentication only
# + server_name extension
# + configure client to initially sent incorrect group, which will be corrected with HRR from the server

echo ""
echo "*** ECDHE-ECDSA, HRR - inacceptable key share ***"
echo ""

# - the ECDHE-ECDSA-based ciphersuite exchange is executed
# - AES-128-CCM is negotiated but HRR is used
run_test    "TLS_AES_128_CCM_SHA256 with ECDHE-ECDSA (server auth only) with HRR" \
            "$P_SRV $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 key_exchange_modes=ecdhe_ecdsa named_groups=secp256r1 cookies=1 tickets=0" \
            "$P_CLI $MBEDTLS_DEBUG_LEVEL force_version=tls1_3 server_name=localhost force_ciphersuite=TLS_AES_128_CCM_SHA256 key_exchange_modes=ecdhe_ecdsa named_groups=secp256r1,secp384r1 key_share_named_groups=secp384r1" \
            0 \
			-s "no matching curve for ECDHE" \
			-s "write hello retry request" \
			-s "NamedGroup in HRR: secp256r1" \
			-s "ECDH curve: secp256r1" \
			-c "received HelloRetryRequest message" \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS_AES_128_CCM_SHA256" \
			-c "Verifying peer X.509 certificate... ok" \
			-c "Key Exchange Mode is ECDHE-ECDSA"

			
# Final report
echo ""
echo "------------------------------------------------------------------------"

echo ""
echo "--- FINAL REPORT ---"
echo ""

if [ $FAILS = 0 ]; then
    printf "PASSED"
else
    printf "FAILED"
fi
PASSES=$(( $TESTS - $FAILS ))
echo " ($PASSES / $TESTS tests ($SKIPS skipped))"

exit $FAILS
