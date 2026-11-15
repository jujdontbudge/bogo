# T3 implementation evidence

Local run, 2026-11-15. Branch `t3/crypto-relay-crates`. No VPS deployment.
See [the wire contract and reproduction commands](../RELAY-PROTOCOL.md).

## Actual client use (verification steps 1–4)

Command:

```
cargo build -p bogo-relay
cargo run -p bogo-relay-proto --example conversation -- target/debug/bogo-relay /tmp/bogo-relay-local-evidence
```

The temporary directory held a two-day, self-made P-256 TLS certificate with
`DNS:localhost` SAN, private key mode 0600, directory mode 0700. The example
trusts that certificate explicitly without disabling TLS validation. Mailbox
private keys were generated in memory and never printed or written.

Observed output:

```
bogo-relay listening with TLS on 127.0.0.1:52287
auth: missing bearer, wrong service, replayed challenge -> 401
allowlists: owner-only configuration, unlisted writer -> 403
HPKE: Mac -> phone exact plaintext; replay ID recognised; ciphertext/header/context/sender tampering refused
SQLite: columns=["recipient", "msg_id", "sender", "body", "created"]; rows=1, ciphertext_bytes=131; plaintext absent
durability: idempotent resend; full mailbox and ID collision -> 409
bogo-relay listening with TLS on 127.0.0.1:52287
restart after kill: both undelivered ciphertexts recovered; allowlists retained; old bearer rejected
ack/retract: recipient ack, sender-only retract, and long-poll delivery passed
lobby: publish/refresh/list, one peer, bidirectional opaque phase data, owner-only delete passed
allowlist revocation persisted; conversation complete
```

The same client also opened phone → Mac bytes, acknowledged that reply, and
compared the SQLite BLOB byte-for-byte with the original envelope. It checked
that a different sender cannot retract a delivery, a different phone cannot
read/send on a claimed offer, a nonowner cannot replace/delete an offer, and
revoking the allowlist immediately prevents further sends. The restart was a
hard child-process kill, not a graceful flush. Deduplication was demonstrated
by pending-row uniqueness and by an endpoint set keyed by the envelope ID;
durable endpoint tombstones belong to the later endpoint store/log implementation.

## APNs (verification step 5)

Command: `cargo run -p bogo-apns --example sandbox`.
The one explicitly authorized `.p8` path was read at runtime; its contents and
JWT were never printed, copied to this checkout, or committed. Team/bundle
values came only from the explicitly authorized iPhone `project.yml` read.
No Apple Bridge Mac repository, relay, gateway or APNs implementation was used.

```
HTTP/2 APNs status=400 reason=BadDeviceToken apns-id=22859E5F-97DB-27B7-2FED-6E8F042900F3
```

Apple returned the expected bad-token response, with no provider-auth error.
After this run the collapse ID was corrected to hash the full request ID so
its boot prefix cannot collapse distinct requests. This local header-only
change was typechecked/linted; a second external push was unnecessary.

## Exact-byte approval signatures (verification step 6)

Commands:

```
cargo run -p bogo-verify --example exact_bytes
cargo run -p bogo-verify --features test-approvers --example exact_bytes
```

Output:

```
P-256: exact bytes accepted; changed message/signature, DER and unknown tag rejected
default build: soft Ed25519 tag refused
P-256: exact bytes accepted; changed message/signature, DER and unknown tag rejected
test-approvers build: valid soft signature accepted; changed bytes rejected
```

## Named App Attest steps (verification step 7)

Command:

```
cargo run -p bogo-attest --example steps -- /tmp/bogo-relay-local-evidence/cert.pem
```

The example uses the self-signed local certificate and synthetic authData.
It checks positive field inputs independently and deliberately refuses the
whole synthetic object because the chain is not Apple's. It never changes
the pinned root or provides an alternate trusted root entry point.

```
decode (invalid CBOR): invalid input rejected at Decode
pinned chain (self-signed local certificate): invalid input rejected at CertificateChain
nonce (different registration binding): invalid input rejected at Nonce
key ID (different public-key hash): invalid input rejected at KeyId
RP ID (another app): invalid input rejected at RpIdHash
counter (nonzero): invalid input rejected at Counter
AAGUID (production disallowed): invalid input rejected at Aaguid
AAGUID (unknown constant): invalid input rejected at Aaguid
credential ID (different ID): invalid input rejected at CredentialId
COSE key (different certified point): invalid input rejected at CredentialKey
category (development binary in production): invalid input rejected at ValidationCategory
bundle version (not accepted): invalid input rejected at BundleVersion
bundle version (wrong CBOR type): invalid input rejected at BundleVersion
full verifier (untrusted synthetic chain): invalid input rejected at CertificateChain
All named steps exercised; positive synthetic fields accepted; real-device chain pending device session
```

Pinned Apple root DER fingerprint was independently checked with OpenSSL:
`1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32`.
The named steps follow Apple's current
[validation procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
including the category and version extensions, and compare the COSE and
certificate keys. Bundle versions are explicit caller policy.

## Build and guardrails (verification step 8)

- `cargo check --workspace --all-targets`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test --workspace`: full suite passed (3 existing integration checks,
  zero new unit tests; all new APIs were exercised through examples above).
- `cargo tree -p bogo-verify --edges normal`: only the `p256` dependency tree;
  no `ed25519-dalek`. Default verifier refused 0xff00. Mailbox Ed25519 auth is
  separate and does not enable the soft approval feature.
- `git diff --check`: passed.
- Relay source/dependency inspection: no daemon, E2E private-key, APNs or
  Apple Bridge dependency. It stores only envelopes and routing metadata.
- No application input, envelope, token or key is logged. HTTP failures are
  sanitized; signing/client structs do not derive Debug; temporary PEM is
  zeroized. Logs from the real runs above contain only status/routing metadata.
- No sudo, password prompts, Keychain writes, VPS connections or deployment.

## Not checked here

- Successful real-device App Attest chain/registration, provisioned App ID
  prefix, Secure Enclave/Face ID, CryptoKit interoperability, or real pushes
  to a phone. These belong to the phone/device session and route tickets.
- Full registration commitment/SAS/owner confirmation; this ticket provides
  its lobby transport, not the registration driver.
- Apple's optional receipt risk service or subsequent App Attest assertions.
- Elapsed retention/lobby/session expiry and certificate rotation under SIGHUP
  were implemented but not exercised by waiting in real time. Restart and
  delivery races were exercised with the actual service.
- Public hosting, systemd, DNS, firewall, certificate issuance/renewal, VPS
  deployment, or production APNs. These are outside this local-only checkpoint.

Sol review ledger is recorded below after review.
