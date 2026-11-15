#!/bin/sh
# Runs the bypass suite inside the sandbox. The sandbox has no DNS, so the
# names it tries to reach directly are resolved here and passed in by address.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
BYPASS_TARGETS=$(python3 -I -c '
import socket
out = []
for name in ["api.stripe.com", "link.com", "api.link.com", "bogo.eilmer.si", "registry.npmjs.org", "example.com"]:
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})[:2]
    except OSError:
        ips = []
    if ips:
        out.append(name + "=" + ",".join(ips))
print(";".join(out))
')
export BYPASS_TARGETS
export BYPASS_RELAY_PORT="${BYPASS_RELAY_PORT:-8443}"
# A real approval signature from the audit log, if there is one, to replay.
log="${BOGO_HOME:-$HOME/.bogo}/log/audit.jsonl"
if [ -z "${BYPASS_REPLAY_SIG:-}" ] && [ -r "$log" ]; then
	BYPASS_REPLAY_SIG=$(python3 -I -c '
import json, sys
sig = ""
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "approval":
        # LogEvent::Approval records the signature as `proof` (hex).
        if isinstance(e.get("proof"), str):
            sig = e["proof"]
print(sig)
' "$log")
	export BYPASS_REPLAY_SIG
fi
exec docker compose --profile bypass run --rm bypass
