#!/bin/sh

BIND="${SOCKS_BIND:-0.0.0.0}"
PORT="${SOCKS_PORT:-1080}"
USERNAME="${SOCKS_USER}"
PASSWORD="${SOCKS_PASS}"

if [ "$BIND" = "0.0.0.0" ]; then
    TEST_HOST="127.0.0.1"
else
    TEST_HOST="$BIND"
fi

SOCKS_PROXY="${TEST_HOST}:${PORT}"

check_url() {
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        curl --silent \
            --connect-timeout 5 \
            --max-time 10 \
            --socks5 "$SOCKS_PROXY" \
            --proxy-user "$USERNAME:$PASSWORD" \
            "$1" \
            -o /dev/null \
            -w "%{http_code}" 2>/dev/null
    else
        curl --silent \
            --connect-timeout 5 \
            --max-time 10 \
            --socks5 "$SOCKS_PROXY" \
            "$1" \
            -o /dev/null \
            -w "%{http_code}" 2>/dev/null
    fi
}

status=$(check_url "http://captive.apple.com/")
if [ -n "$status" ] && [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
    exit 0
fi

status=$(check_url "http://cp.cloudflare.com/")
if [ -n "$status" ] && [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
    exit 0
fi

exit 1
