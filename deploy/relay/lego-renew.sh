#!/bin/sh
set -eu
umask 077

# Run as root, via the BOGO-only systemd renewal unit. Never log credentials.
: "${BOGO_ACME_EMAIL:?set BOGO_ACME_EMAIL in /etc/bogo-relay/acme.env}"
: "${CF_DNS_API_TOKEN:?load /etc/bogo-relay/cloudflare.env}"
domain=bogo.eilmer.si
state=/var/lib/bogo-relay-acme
lego=/opt/bogo-relay/bin/lego

case "${1:-renew}" in
  --dry-run)
    # lego has no certbot-style dry-run flag. Exercise the same DNS-01
    # provider against Let's Encrypt staging, without installing that cert.
    if [ -f /var/lib/bogo-relay-acme-staging/certificates/bogo.eilmer.si.crt ]; then
      set -- renew --days 90
    else
      set -- run
    fi
    "$lego" --path /var/lib/bogo-relay-acme-staging \
      --server https://acme-staging-v02.api.letsencrypt.org/directory \
      --email "$BOGO_ACME_EMAIL" --accept-tos --domains "$domain" \
      --dns cloudflare --dns.resolvers 1.1.1.1:53 --dns.resolvers 8.8.8.8:53 "$@"
    exit 0
    ;;
  --issue) operation=run ;;
  renew) operation=renew ;;
  *) echo 'usage: lego-renew.sh [--issue|--dry-run]' >&2; exit 2 ;;
esac

if [ "$operation" = run ]; then
  "$lego" --path "$state" --email "$BOGO_ACME_EMAIL" --accept-tos \
    --domains "$domain" --dns cloudflare \
    --dns.resolvers 1.1.1.1:53 --dns.resolvers 8.8.8.8:53 run
else
  "$lego" --path "$state" --email "$BOGO_ACME_EMAIL" --accept-tos \
    --domains "$domain" --dns cloudflare \
    --dns.resolvers 1.1.1.1:53 --dns.resolvers 8.8.8.8:53 renew --days 30
fi

# Keep the Cloudflare credential and ACME account keys inaccessible to the
# relay. Copy only this relay's certificate/key; HUP reloads rustls in place.
changed=false
for ext in crt key; do
  src="$state/certificates/$domain.$ext"
  dst="/etc/bogo-relay/tls/$domain.$ext"
  if ! cmp -s "$src" "$dst"; then
    install -o root -g bogo-relay -m 0640 "$src" "$dst.new"
    mv -f "$dst.new" "$dst"
    changed=true
  fi
done
if [ "$changed" = true ] && systemctl is-active --quiet bogo-relay.service; then
  systemctl reload bogo-relay.service
fi
