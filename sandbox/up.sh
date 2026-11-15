#!/bin/sh
# Starts the sandbox. The agent service starts only after netpol's rules load.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
[ -f .env ] || { echo "sandbox/.env is missing; copy .env.example and fill it in" >&2; exit 1; }
case "$(stat -f %Lp .env 2>/dev/null || stat -c %a .env)" in
	600|400) ;;
	*) echo "sandbox/.env must be mode 0600" >&2; exit 1 ;;
esac
docker compose up -d --wait gate model-gate netpol agent
docker compose ps
