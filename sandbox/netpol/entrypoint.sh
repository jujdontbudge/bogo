#!/bin/sh
# Load the rules, prove they are in place, then drop every privilege for good.
# If any step fails the container exits, its healthcheck never passes, and the
# agent never starts.
set -eu
nft -c -f /etc/bogo/policy.nft
nft -f /etc/bogo/policy.nft
nft list table inet bogo >/dev/null
echo "netpol: rules loaded" >&2
touch /run/netpol/ready
exec setpriv --reuid=65534 --regid=65534 --clear-groups \
	--inh-caps=-all --bounding-set=-all --no-new-privs sleep infinity
