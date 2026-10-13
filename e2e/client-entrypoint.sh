#!/bin/sh
set -eu
# Install the rule before daemon startup. Docker DNS is on loopback, not eth0.
iptables -I OUTPUT 1 -o eth0 -p udp -j REJECT
ip6tables -I OUTPUT 1 -o eth0 -p udp -j REJECT
test -c /dev/net/tun
export SSL_CERT_FILE=/certs/ca.crt
exec tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --tun=tailscale0
