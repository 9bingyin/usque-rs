#!/bin/sh
set -e

TUNNEL_MODE="${TUNNEL_MODE:-masque}"
SOCKS_BIND="${SOCKS_BIND:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1,1.0.0.1}"

if [ "$TUNNEL_MODE" = "wg" ] || [ "$TUNNEL_MODE" = "wireguard" ]; then
    CONFIG_FILE="/app/warp.conf"
    REGISTER_CMD="register wg"
    SOCKS_CMD_MODE="wg"
else
    CONFIG_FILE="/app/config.json"
    REGISTER_CMD="register masque"
    SOCKS_CMD_MODE="masque"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found, starting auto-registration ($TUNNEL_MODE mode)..."
    /usr/local/bin/usque-rs $REGISTER_CMD --accept-tos -c "$CONFIG_FILE"

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
    echo "Starting SOCKS5 proxy on ${SOCKS_BIND}:${SOCKS_PORT} ($TUNNEL_MODE mode)"

    SOCKS_CMD="/usr/local/bin/usque-rs socks $SOCKS_CMD_MODE -c $CONFIG_FILE -b $SOCKS_BIND -p $SOCKS_PORT"

    if [ -n "$SOCKS_USER" ] && [ -n "$SOCKS_PASS" ]; then
        echo "SOCKS5 authentication: Enabled"
        SOCKS_CMD="$SOCKS_CMD -u $SOCKS_USER -w $SOCKS_PASS"
    else
        echo "SOCKS5 authentication: Disabled"
    fi

    for dns in $(echo "$DNS_SERVERS" | tr ',' ' '); do
        SOCKS_CMD="$SOCKS_CMD --dns $dns"
    done
    echo "Using DNS servers: $DNS_SERVERS"

    exec $SOCKS_CMD
fi
