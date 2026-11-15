# BOGO relay at bogo.eilmer.si

Endpoint: **https://bogo.eilmer.si:8443**. The authentication service identity
is `bogo.eilmer.si:8443` (without the scheme).

Target: Google Cloud `excerlock`, `us-central1-a`, VM `ab-relay`, public IPv4
`136.65.0.235`. Cloudflare A record `bogo`, DNS-only, TTL auto.

## Isolation

BOGO uses TCP 8443, system user/group `bogo-relay`, unit `bogo-relay.service`,
binary `/opt/bogo-relay/bin/bogo-relay`, and SQLite database
`/var/lib/bogo-relay/relay.sqlite`. Mailboxes hold at most 1,000 messages;
retention is explicitly 30 days, independent of approval expiry. SQLite uses
WAL and synchronous FULL. The service restarts on failure, is enabled for boot,
and has a 192 MiB memory limit and 50% of one CPU limit on this shared VM.

Apple Bridge's service, port 443, certificates, state, DNS and firewall rules
must not be changed. **Never reboot this VM for BOGO verification.** Restart
only `bogo-relay.service`; prove boot configuration with `systemctl is-enabled`.

## Certificates and renewal

The root renewal job owns:

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/etc/bogo-relay/cloudflare.env` | root:root 0600 | `CF_DNS_API_TOKEN`; never commit, print or copy to application state |
| `/etc/bogo-relay/acme.env` | root:root 0600 | `BOGO_ACME_EMAIL` |
| `/var/lib/bogo-relay-acme` | root:root 0700 | Production ACME account and certificate material |
| `/var/lib/bogo-relay-acme-staging` | root:root 0700 | Let's Encrypt staging verification, separate from production |
| `/etc/bogo-relay/tls` | root:bogo-relay 0750 | Only BOGO's installed cert/key, root:bogo-relay 0640 |

The Cloudflare token must have **Zone / DNS / Edit** and **Zone / Zone / Read**,
with resources **Include / Specific zone / eilmer.si** only. Zone Read lets
lego discover that zone; no other zone or account permissions are needed.
The token is loaded only by the root renewal job. The relay user cannot read
it or the ACME account keys.

`bogo-relay-renew.timer` checks daily with up to six hours of randomized delay
and catches missed runs. `lego-renew.sh` renews within 30 days of expiry, copies
only BOGO's certificate/key, then reloads **only BOGO** via SIGHUP. The relay
reloads rustls without restarting. The ACME client is pinned to lego **v4.35.2**;
verify the Linux amd64 archive against its published SHA-256 checksums.

## Installation

Build the existing relay with the checked-in lockfile for Linux x86-64. A
static build from an Apple Silicon Mac uses `cargo-zigbuild` plus Zig 0.14.1:

```sh
rustup target add x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p bogo-relay
```

Create the system user with `/usr/sbin/nologin`, the directories and ownership
above, and install the binary, pinned lego, and `lego-renew.sh` under
`/opt/bogo-relay/bin` as root-owned 0755 files. Install the three unit files
from this directory under `/etc/systemd/system` as root-owned 0644 files.
Enable only BOGO's service and renewal timer:

```sh
sudo systemctl daemon-reload
sudo systemctl enable bogo-relay.service bogo-relay-renew.timer
sudo systemctl start bogo-relay-renew.timer
```

The relay has a certificate-existence condition and is not started until its
certificate has been issued. The renewal unit skips runs until its credential
file exists. Install `acme.env` with the owner's ACME account email. Transfer
the new token directly into the VM's protected file without command arguments,
local files, screenshots or log output. Do not reuse Apple Bridge credentials.

Add a **new** `bogo-relay` network tag while retaining all existing VM tags.
The only firewall addition is this Google Cloud rule; no host firewall service
or nftables rules are installed:

```sh
gcloud compute instances add-tags ab-relay --zone=us-central1-a \
  --project=excerlock --tags=bogo-relay
gcloud compute firewall-rules create bogo-relay-allow-8443 \
  --project=excerlock --network=default --direction=INGRESS --priority=1000 \
  --allow=tcp:8443 --source-ranges=0.0.0.0/0 --target-tags=bogo-relay \
  --description='BOGO relay TLS; separate from Apple Bridge'
```

Issue the certificate using only BOGO's environment and ACME directories:

```sh
sudo systemd-run --wait --collect --unit=bogo-relay-issue \
  -p EnvironmentFile=/etc/bogo-relay/acme.env \
  -p EnvironmentFile=/etc/bogo-relay/cloudflare.env \
  /opt/bogo-relay/bin/lego-renew.sh --issue
sudo systemctl start bogo-relay.service
```

## Verification

Record Apple Bridge's status, PID/start time, served certificate fingerprint,
HTTP response and firewall list before and after. Compare the HTTP status/body
and stable headers; the Date header naturally advances. All existing firewall
objects must remain identical, with only `bogo-relay-allow-8443` added.

```sh
dig +short bogo.eilmer.si
openssl s_client -connect bogo.eilmer.si:8443 -servername bogo.eilmer.si \
  -verify_return_error </dev/null
systemctl is-enabled bogo-relay.service
sudo systemctl start bogo-relay-renew.service
sudo systemd-run --wait --collect --unit=bogo-relay-renew-dry-run \
  -p EnvironmentFile=/etc/bogo-relay/acme.env \
  -p EnvironmentFile=/etc/bogo-relay/cloudflare.env \
  /opt/bogo-relay/bin/lego-renew.sh --dry-run
sudo stat -c '%a %U:%G %n' /etc/bogo-relay/cloudflare.env
```

lego has no `--dry-run` flag. The script's `--dry-run` exercises Cloudflare
DNS-01 against Let's Encrypt **staging**, with separate state and no production
certificate replacement. Subsequent dry runs force staging renewal.

From this Mac, use the real protocol and HPKE crates:

```sh
cargo run --locked -p bogo-relay-proto --example live -- https://bogo.eilmer.si:8443
```

At its pause, run `sudo systemctl restart bogo-relay.service` on the VM, then
press Enter in the client. It verifies public TLS, both authenticated clients,
both sealed message directions, concurrent long polling, allowlist enforcement,
idempotency, rejected old sessions, held-message persistence and decryption,
durable allowlists, acknowledgments, and cleanup. Never restart Apple Bridge.
