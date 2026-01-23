#!/bin/sh
set -e

CONFIG_FILE="/app/config.json"

SOCKS_BIND="${SOCKS_BIND:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-1080}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found, starting auto-registration..."
    /usr/local/bin/usque-rs register --accept-tos -c "$CONFIG_FILE"

    if [ $? -eq 0 ]; then
        echo "Registration successful!"
    else
        echo "Registration failed!"
        exit 1
    fi
else
    echo "Configuration file exists: $CONFIG_FILE"
fi

if [ $# -gt 0 ]; then
    echo "Starting: usque-rs $@"
    exec /usr/local/bin/usque-rs "$@"
else
    echo "Starting SOCKS5 proxy on ${SOCKS_BIND}:${SOCKS_PORT}"

    SOCKS_CMD="/usr/local/bin/usque-rs socks -c $CONFIG_FILE -b $SOCKS_BIND -p $SOCKS_PORT"

    if [ -n "$SOCKS_USER" ] && [ -n "$SOCKS_PASS" ]; then
        echo "SOCKS5 authentication: Enabled"
        SOCKS_CMD="$SOCKS_CMD -u $SOCKS_USER -w $SOCKS_PASS"
    else
        echo "SOCKS5 authentication: Disabled"
    fi

    exec $SOCKS_CMD
fi
