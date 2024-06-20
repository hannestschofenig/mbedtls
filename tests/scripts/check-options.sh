#!/usr/bin/env bash

print_usage() {
    echo "Usage: $0 [options]"
    printf "  -c|--check\tExit on error\n"
    printf "  -f|--full\ttest_all\n"
    printf "  -F|--fail\ttest unkown status test cases\n"
    printf "  -h|--help\tPrint this help.\n"
 }
pass_cases="9 13 5"
test_cases=""
fail_cases="3 1 2 6 7 10 11 14 15"
mbedtls_user_config="\\<test/check_options.h\\>"
while [ $# -gt 0 ]; do
        case "$1" in
            -c|--check)
                set -ex
                ;;
            -f|--full)
                test_cases="${fail_cases} ${pass_cases} ${test_cases}"
                ;;
            -F|--fail)
                test_cases="${fail_cases}"
                ;;
            -n|--number)
                shift ;test_cases="${test_cases} $1"
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
result=" "
config_1="|ENABLE|DISABLE|DISABLE|DISABLE|#238|"
config_2="|DISABLE|ENABLE|DISABLE|DISABLE|unkown|"
config_3="|ENABLE|ENABLE|DISABLE|DISABLE|#297|"
config_5="|ENABLE|DISABLE|ENABLE|DISABLE|pass|"
config_6="|DISABLE|ENABLE|ENABLE|DISABLE|#298|"
config_7="|ENABLE|ENABLE|ENABLE|DISABLE|unkown|"
config_9="|ENABLE|DISABLE|DISABLE|ENABLE|pass|"
config_10="|DISABLE|ENABLE|DISABLE|ENABLE|unkown|"
config_11="|ENABLE|ENABLE|DISABLE|ENABLE|unkown|"
config_13="|ENABLE|DISABLE|ENABLE|ENABLE|pass|"
config_14="|DISABLE|ENABLE|ENABLE|ENABLE|unkown|"
config_15="|ENABLE|ENABLE|ENABLE|ENABLE|unkown|"
title="|No.|MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL|MBEDTLS_SSL_PROTO_TLS1_2|MBEDTLS_DISABLE_BLOCK_IO|MBEDTLS_SSL_USE_MPS|comment|status|cmd|"
separated_line="|--------|--------|--------|--------|--------|--------|--------|-------|"






ret=0
fail_result=" "
pass_result=" "
test_cases=$(echo $test_cases | sort -u)
if [ -z "$test_cases" ]
then
    test_cases=$pass_cases
fi

echo $title
echo $separated_line

for i in ${test_cases}
do
    test_case=config_$i
    printf "|${i} ${!test_case}"
    make clean  && \
    make CFLAGS="-g -Werror -DMBEDTLS_TMP_TEST_CASE_${i} -I../tests/include -DMBEDTLS_USER_CONFIG_FILE=${mbedtls_user_config}" -j20 >/dev/null 2>&1 && \
    ./tests/ssl-opt.sh -s  >/dev/null 2>&1
    
    if [ $? != 0 ]; then
        printf "FAIL"
        ret=$i
    else
        printf "PASS"
    fi
    printf  "|%s|\n" "make clean  && make CFLAGS=\"-g -Werror -I../tests/include -DMBEDTLS_TMP_TEST_CASE_${i} -DMBEDTLS_USER_CONFIG_FILE=${mbedtls_user_config}\" -j20 && ./tests/ssl-opt.sh -s"
done

exit $ret

