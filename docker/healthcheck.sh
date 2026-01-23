#!/bin/sh

BIND="${SOCKS_BIND:-0.0.0.0}"
PORT="${SOCKS_PORT:-1080}"

if [ "$BIND" = "0.0.0.0" ]; then
    TEST_HOST="127.0.0.1"
else
    TEST_HOST="$BIND"
fi

SOCKS_PROXY="${TEST_HOST}:${PORT}"

check_url() {
    curl --silent --fail \
        --connect-timeout 5 \
        --max-time 10 \
        --socks5 "$SOCKS_PROXY" \
        "$1" \
        -o /dev/null \
        -w "%{http_code}" 2>/dev/null
}

status=$(check_url "http://cp.cloudflare.com/")
if [ "$status" = "204" ]; then
    exit 0
fi

status=$(check_url "https://cloudflare.com/cdn-cgi/trace")
if [ "$status" = "200" ]; then
    exit 0
fi

exit 1
