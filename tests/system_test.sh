#!/usr/bin/env bash

SERVER="127.0.0.1"
PORT="6363"

FQDN="$1"
if [ -z "${FQDN}" ]; then
    FQDN="www.google.com"
fi

TOTAL_REQUESTS=50000
PARALLELISM=100

echo "Starting DNS stress test"
echo "Target: ${FQDN}"
echo "Requests: ${TOTAL_REQUESTS}"
echo "Parallelism: ${PARALLELISM}"
echo

run_query() {
    dig @"${SERVER}" -p "${PORT}" "${FQDN}" +short > /dev/null
}

export -f run_query
export SERVER PORT FQDN

seq 1 "${TOTAL_REQUESTS}" | \
    xargs -n1 -P "${PARALLELISM}" -I{} bash -c 'run_query'

echo
echo "Stress test completed"
