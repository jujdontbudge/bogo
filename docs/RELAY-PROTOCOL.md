# Crypto and relay v1 contract

This implements ARCHITECTURE §3.4, §3.11–3.12 and §6. Nothing connects to an
Apple Bridge Mac service. The relay is a separate TLS-only binary. It stores
ciphertext and routing metadata and has no E2E, approval, or APNs private key.

## Envelope

All integers are unsigned big endian. IDs are raw bytes inside the envelope:

```
"BOGOE2E\0" | version:u8=1 | direction:u8 | type:u8 | msgId:16
| encLength:u32=32 | enc:32 | ciphertextLength:u32 | ciphertext
```

Direction 0 is Mac → phone; 1 is phone → Mac. The first 27 bytes are AAD.
The suite is DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305,
HPKE authenticated mode, with `bogo/e2e/v1 || bogoId:32 || approverId:32`
as info. Every seal uses a new ephemeral key. Limits are 1 MiB plaintext and
1 MiB + 83 bytes total. Empty plaintext is supported.

`Header.kind` is the route's message discriminator. The route defines its
payload codec and discriminator assignments; these crates never interpret a
request or decision payload. After authentication the route ignores unknown
noncritical types; this version rejects all critical (high-bit) types.
`peek_id` supports checking an endpoint's durable tombstone before decryption.
Only record an ID after authentication and a durable effect; never acknowledge
before that. The route must keep replay records, boot/session binding and
idempotent effects; HPKE itself does not prevent replay. Outbox retries reuse
the same sealed bytes. `request_message_id` hashes the full 40-byte request ID
and 32-byte approver ID. Other IDs use `message_id()` once per outbox item.

## Mailbox transport

JSON binary fields use lowercase hex. Mailboxes are SHA-256(Ed25519 public key).
A client starts with `POST /v1/auth/challenge {"pub": <32-byte hex>}`. The relay
returns a random 32-byte challenge, valid for 60 seconds. The signature input is:

```
"bogo/relay/auth/v1\0" || serviceLength:u32 || service UTF-8
|| mailbox:32 || challenge:32
```

The owner configures the relay's public service identity (normally its hostname
and port) and supplies that same identity to the client. The challenge binds
both that service and mailbox. `POST /v1/auth/verify {pub,sig}` consumes it even
on a bad signature and returns a random 32-byte hex bearer token valid for one
hour. All remaining endpoints require that bearer. Tokens and challenges are
bounded in memory (4096 each), never stored or logged, and vanish on restart.
Clients reconnect/authenticate when they get 401. TLS certificates and hostnames
are always checked; redirects are disabled. Keep client/key values out of logs.

- `POST /v1/allow {senders:[mailbox]}` atomically replaces the authenticated
  recipient's allowlist (at most 1000 entries); it starts empty.
- `POST /v1/send {to,msg_id,body}` stores a sealed envelope BLOB. `msg_id` is
  16 bytes and must match its header. The sender must be on the recipient's
  allowlist. Equal `(to,msg_id,sender,body)` retries return 200. A changed
  sender or body for a pending ID returns 409; so does a full mailbox.
- `POST /v1/fetch {wait:bool}` returns up to 32 `{msg_id,from,body}` objects,
  without deleting anything. A long poll waits up to 25 seconds. Subscribe
  before reading so a concurrent send cannot lose its wake-up.
- `POST /v1/ack {msg_ids:[id]}` deletes only from the authenticated recipient.
- `POST /v1/retract {to,msg_ids:[id]}` deletes only that sender's deliveries.
  Ack/retract accept at most 1000 IDs, and absent IDs succeed idempotently.

The relay validates only outer envelope framing, never decrypts or interprets
payloads. A malicious relay may still drop, forge routing fields, repeat or
reorder data: endpoints must authenticate HPKE and signatures and check session
binding. A relay cannot enforce that a malicious client actually encrypted its
bytes; privacy depends on endpoints using `bogo-e2e`.

SQLite uses WAL and synchronous FULL. Allowlist replacement, send, ack and
retract commit before success. Messages have recipient, message ID, sender,
opaque body and creation time only. Retention is explicitly set with
`--max-message-age SECONDS`, and expired messages are removed on send/fetch.
Retention is never approval expiry. Endpoint obligations must be resent if
still live. Endpoint deduplication also covers messages resent after relay ack.

## Registration lobby

The lobby carries the registration protocol's public commitment handshake and,
after SAS comparison, opaque sealed phase data. It never authorizes registration.
Both endpoints must implement the commitment, SAS, owner confirmation, App Attest
and proof-of-possession steps from ARCHITECTURE §3.11.

- `POST /v1/lobby/offer {offer_id,e_pub_m,mac_label}` creates or refreshes an
  offer. IDs are 16 bytes; the ephemeral key is 32 bytes. Labels are 1–128 UTF-8
  bytes. Only its owner can refresh it, and its key/label cannot change.
- `GET /v1/lobby` returns open, unclaimed offers, with `age_seconds` added.
- `POST /v1/lobby/{id}/msg {msg_id,body}` carries hex phase data, up to 64 KiB.
  The first nonowner writer claims the sole phone slot. A different phone is
  refused. Owner and phone can send; repeated identical phase IDs are idempotent.
- `POST /v1/lobby/{id}/fetch` returns all other-side `{msg_id,from,body}` phases;
  each endpoint deduplicates IDs. Outsiders are refused.
- `DELETE /v1/lobby/{id}` removes an offer, owner only.

At most 256 offers and 64 phases per offer are held in memory. Offers expire
120 seconds after their owner's last refresh. The owner should refresh at less
than that interval. Restart removes all offers. Abort requires removing the
offer and starting a new one, with new ephemeral keys and IDs.

## Approval verifier and attestation

`bogo_verify::verify` accepts tag 1, SEC1 P-256 public keys and a raw 64-byte
`r || s` signature over SHA-256 of the exact message bytes. DER signatures and
unknown tags fail. The C entry point `bogo_rs_verify` has the architecture's ABI;
its documented unsafe pointer conversion is this crate's sole unsafe exception.
No panic crosses the ABI. Tag 0xff00 is compiled only with `test-approvers`;
the optional Ed25519 dependency is absent from this crate's default graph.
Relay mailbox Ed25519 auth remains present independently of approval verification.

`bogo-attest` embeds Apple's App Attestation Root from
<https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>.
Its DER SHA-256 is
`1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`.
No system trust or network is used. Each public named step returns only its step
name on failure, without input bytes. `verify` executes all steps in order:
CBOR/format, certificate chain (including constraints, signatures and time),
nonce, key ID, RP ID hash, zero counter, AAGUID/environment, credential ID, COSE
key agreement with the certificate, Apple validation category and bundle version.

The caller supplies trusted time, the exact App ID prefix + bundle ID, allowed
environments and accepted bundle versions. Production accepts Apple's categories
2 (TestFlight) and 4 (App Store); explicitly allowed development accepts 3.
The category is Apple's four-byte little-endian UInt32 CBOR byte string.
Certificate signing digests (SHA-256/SHA-384) are selected independently of
the P-256/P-384 issuer curve, as in Apple's published sample chain.
The registration driver computes `registration_client_data_hash` from its own
transcript hash, one-use challenge and submitted registration keys; it must
consume the challenge and reject previously registered transactions/keys. A
verified receipt is returned as opaque bytes for future fraud-risk assessment;
this crate does not contact Apple's receipt service or validate later assertions.
A real-device attestation and App ID prefix provisioning-profile check remain
part of the device session.

## APNs

`bogo-apns` reads the referenced `.p8` at runtime, zeroizes the temporary PEM,
uses ES256 JWT provider auth over HTTP/2 and caches tokens for 50 minutes.
The client only emits the fixed generic BOGO wake payload and routing IDs.
Its collapse ID is the SHA-256 of the full request ID (64 ASCII bytes), so all
40 request-ID bytes distinguish notifications. APNs rejection details expose
only status, Apple's reason and request UUID, never auth/key data. The caller
owns retry and device-token/environment updates. Sandbox and production hosts
are fixed and redirects disabled.

## Local use

Generate a short-lived certificate outside the repository, with OpenSSL:

```sh
mkdir -p /tmp/bogo-relay-local
chmod 700 /tmp/bogo-relay-local
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /tmp/bogo-relay-local/key.pem -out /tmp/bogo-relay-local/cert.pem \
  -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -addext basicConstraints=critical,CA:FALSE
chmod 600 /tmp/bogo-relay-local/key.pem
cargo build -p bogo-relay
cargo run -p bogo-relay-proto --example conversation -- \
  target/debug/bogo-relay /tmp/bogo-relay-local
cargo run -p bogo-attest --example steps -- /tmp/bogo-relay-local/cert.pem
cargo run -p bogo-verify --example exact_bytes
cargo run -p bogo-verify --features test-approvers --example exact_bytes
```

The conversation example starts its own local TLS relay on a free port, uses
three independent in-memory mailbox keys, checks refusals, exchanges envelopes,
inspects SQLite, kills/restarts the relay, checks delivery, and stops it on exit.
Use a fresh directory/database per run. Run `cargo run -p bogo-apns --example
sandbox` only when deliberately checking the owner's credentials; it sends one
made-up token to Apple's sandbox using the explicitly authorized key path.

For a manually managed relay:

```sh
target/debug/bogo-relay --listen 127.0.0.1:8843 --service localhost:8843 \
  --database /tmp/bogo-relay-local/manual.sqlite --max-message-age 86400 \
  --cert /tmp/bogo-relay-local/cert.pem --key /tmp/bogo-relay-local/key.pem
```

SIGHUP reloads the configured certificate and key atomically; a failed reload
keeps the current certificate. Deployment, DNS, public certificates and the VPS
service are a separate checkpoint. Protect the relay's state directory and TLS
key with filesystem permissions when configuring that deployment.
