# Live deployment evidence — 2026-11-15

Endpoint: **https://bogo.eilmer.si:8443**. Authentication service identity:
`bogo.eilmer.si:8443`. VM: `excerlock/us-central1-a/ab-relay`, IPv4
`136.65.0.235`. Deployment artifacts: commit `8de9636`.

## 1. Apple Bridge baseline

Before preparation, recorded `systemctl status ab-relay`, its unit hash,
served TLS certificate, HTTP response, and the complete GCP firewall list.
The same checks after deployment showed:

```text
MainPID=432553
ActiveEnterTimestamp=Sun 2026-11-08 23:19:57 UTC
Unit SHA256=899c511aac4110687e6f78d7b9c8768af9264b7a7d1d367215b8978d2dd99c0d
Port 443: ab-relay, PID 432553
Certificate CN=ab.lexaai.tech; issuer=Let's Encrypt YE1
serial=0574ED66FCE2240B98E8C61FD9D1C6E676C2
SHA256=91:C1:6B:AD:DC:FA:0E:0D:8D:DC:C9:CB:BE:5E:22:11:75:FA:31:77:3C:9C:70:36:BB:7E:54:00:DC:E3:E7:EF
notBefore=Oct 29 17:22:47 2026 GMT
notAfter=Jan 27 17:22:46 2027 GMT
```

`curl --resolve ab.lexaai.tech:443:136.65.0.235 https://ab.lexaai.tech/`
returned the same `HTTP/1.1 404 Not Found`, body `404 page not found\n`,
content type, length 19 and nosniff header. Only the Date header advanced.
Certificate fields, service PID/start time/command, and unit hash matched.
Memory/CPU counters naturally advanced. No Apple Bridge service, configuration,
state, certificate, record, firewall rule or Mac repository was modified.
No VM reboot occurred.

## 2. Cloudflare DNS

Created through the cua driver's typed browser tools in a dedicated Chrome tab:
A `bogo.eilmer.si` → `136.65.0.235`, DNS-only, TTL Auto.

```console
$ dig +short bogo.eilmer.si
136.65.0.235
```

A VM-side read-only API snapshot compared all existing record objects:

```text
All 35 existing Cloudflare records identical; only DNS-only bogo.eilmer.si A 136.65.0.235 added
```

ACME creates and cleans only `_acme-challenge.bogo.eilmer.si` TXT records.

## 3. Public TLS and renewal

From the Mac:

```console
$ openssl s_client -connect bogo.eilmer.si:8443 -servername bogo.eilmer.si \
    -verify_hostname bogo.eilmer.si -verify_return_error </dev/null
Verification: OK
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
```

```text
subject=CN=bogo.eilmer.si
issuer=C=US, O=Let's Encrypt, CN=YE2
SAN=DNS:bogo.eilmer.si
notBefore=Nov 15 15:10:44 2026 GMT
notAfter=Feb 13 15:10:43 2027 GMT
serial=05837425FB984B050A5B6BA83CE6568C32C8
SHA256=43:91:64:68:CD:A2:A3:C2:58:BC:91:00:24:40:4E:20:12:4C:C9:E9:8C:FF:66:5A:25:2D:AE:13:5C:44:FD:36
```

BOGO-only production issuance completed with exit status 0 (14.694 seconds).
`systemctl start bogo-relay-renew.service` succeeded; the fresh production
certificate was correctly retained. The timer is enabled and active, daily
with randomized delay and missed-run persistence. Its next scheduled run was
2026-11-16 05:14:06 UTC.

The documented `lego-renew.sh --dry-run` command completed staging DNS-01
validation and staging issuance with status 0 (18.378 seconds). Separate
staging state was used; the production certificate was never replaced.
A second invocation completed the staging renewal path with status 0
(6 minutes 766 ms, including lego's built-in randomized delay):

```text
acme: Trying renewal with 1535 hours remaining
acme: authorization already valid; skipping challenge
acme: Validations succeeded; requesting certificates
Server responded with a certificate.
Finished with result: success
Main processes terminated with: code=exited/status=0
```

The first staging run proved fresh DNS-01 validation; the renewal reused its
valid ACME authorization. After both runs, the same production certificate
serial/fingerprint still served with verification OK. A final Cloudflare
comparison again confirmed all 35 old records unchanged and only the DNS-only
BOGO A record added; no challenge TXT record remained.

## 4. Real clients and service persistence

Ran the repository's real client with `bogo-relay-proto` and `bogo-e2e`:

```console
$ cargo run --locked -p bogo-relay-proto --example live -- https://bogo.eilmer.si:8443
TLS validated; both mailbox identities authenticated; wrong service rejected
Mac -> phone: sealed bytes delivered and decrypted; resend deduplicated; unlisted sender rejected
Phone -> Mac: concurrent long-poll delivered and decrypted reply; ack succeeded
Held ciphertext remains unacknowledged. Restart ONLY bogo-relay, then press Enter.
```

At that pause, ran on the VM:

```console
$ sudo systemctl restart bogo-relay.service
$ systemctl is-enabled bogo-relay.service
enabled
$ systemctl is-active bogo-relay.service
active
```

Resumed the same client process; exit status 0:

```text
BOGO-only restart: old bearer rejected; held ciphertext and allowlist survived; decrypted exact request; mailboxes cleaned
```

`systemctl show bogo-relay -p Restart -p User`:

```text
Restart=on-failure
User=bogo-relay
```

Dedicated binary `/opt/bogo-relay/bin/bogo-relay`, state
`/var/lib/bogo-relay/relay.sqlite`, certificate `/etc/bogo-relay/tls`, and
service `bogo-relay.service` isolate BOGO. The listener was `0.0.0.0:8443`.
Boot configuration was verified as enabled; the VM was never rebooted.

## 5. Firewall and Apple Bridge continuity

Compared the complete firewall JSON objects before and after:

```text
All 7 prior firewall rules identical.
Only addition: bogo-relay-allow-8443
allowed=[{"IPProtocol":"tcp","ports":["8443"]}]
sourceRanges=["0.0.0.0/0"]; targetTags=["bogo-relay"]
```


| Rule | Allowed | Source | Target tags |
| --- | --- | --- | --- |
| ab-relay-allow-443 | tcp:443 | 0.0.0.0/0 | ab-relay |
| ab-selfhost-test-allow | tcp:443, tcp:53, udp:53 | 0.0.0.0/0 | ab-selfhost-test |
| bogo-relay-allow-8443 | tcp:8443 | 0.0.0.0/0 | bogo-relay |
| default-allow-icmp | icmp | 0.0.0.0/0 |  |
| default-allow-internal | tcp:0-65535, udp:0-65535, icmp | 10.128.0.0/9 |  |
| default-allow-rdp | tcp:3389 | 0.0.0.0/0 |  |
| default-allow-ssh | tcp:22 | 0.0.0.0/0 |  |
| excerlock-allow-web | tcp:80, tcp:443 | 0.0.0.0/0 | excerlock-api |

The VM retains its existing tags and adds only the BOGO tag. No host firewall
was installed or altered. Apple Bridge's port 443, process, certificate and
response matched the baseline as recorded above.

## 6. Credential scope and permissions

Created token `BOGO relay DNS-01` through Chrome. After creation, reopened
its configuration without changing or saving it. Cloudflare's summary showed:

```text
NAME: BOGO relay DNS-01
Permission policies:
  eilmer.si
  Zone: Read
  DNS: Edit
EXPIRATION: No expiration
```

The resource editor showed `Include / Specific zone / eilmer.si`; no other
zone or account permissions. Zone Read permits lego's zone discovery.
The token value was transferred from the typed page snapshot in memory
directly to remote stdin; never written to a local file, command argument,
repository, screenshot or log. The unused clipboard was cleared.

```console
$ sudo stat -c '%a %U:%G %n' /etc/bogo-relay/cloudflare.env
600 root:root /etc/bogo-relay/cloudflare.env
$ systemctl show bogo-relay-renew.service -p User
User=root
```

A read check as `bogo-relay` failed as required (`relay-user-cannot-read-token`).
Root owns the renewal job and ACME account state; the application receives
only its certificate and key.

## Local validation and review

Applied the `agent-testing` skill. Earlier artifact verification passed:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked -p bogo-relay-proto -p bogo-relay --all-targets -- -D warnings`.
- `cargo test --locked -p bogo-relay-proto -p bogo-relay` — full selected
  package suites, no existing tests in those packages.
- `sh -n`, ShellCheck, VM `systemd-analyze verify`, and installed binary `--help`.
- Sol review of `8de9636`: **APPROVE**, no findings. Reviewer independently
  used a local TLS relay for bidirectional sealed delivery and restart recovery.

[Sol review](t3-thread://v2/11126312-8eb7-42aa-9f84-bfeaf199a584/thread:delegated-task:command%3Amcp%3Ab0bc3b0a-38d4-4403-bf0b-1d204bfdaf3b%3Adelegate-task%3Abogo-relay-sol-r1-20261115)

## Not checked

A physical phone on cellular was not used; the ticket's two Mac clients
exercised the public internet endpoint and both protocol directions. Actual
VM boot was intentionally not tested, per the corrected ticket. A future
scheduled production renewal was not waited for; staging issuance/renewal and
the production renewal service/timer configuration cover that path today.
