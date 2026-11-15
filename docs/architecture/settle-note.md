# How the architecture was settled

The base is Design B's structure, which is the more concrete of the two and runs on one log. Design A's corrections are applied wherever A was right on the facts. Each point is listed under the side that raised it.

## Points Design A raised

1. **Crash classification and audit boundary: A, applied inside B's log.** B's recovery rule reported "`authorized` with no `forwarded`" as "not sent". But `forwarded` is written after the send, so a crash between the two gives a false "nothing happened". The rule now counts only positive evidence (`not_sent`) as not sent; everything else open is "outcome unknown", never replayed. A's other ask, verifying registrations at the final dispatch, is met without new storage. `forward` carries the core's `registrySeq`, and `bogo log verify` checks the threshold against the registry as of that sequence.

2. **The actual final gate: A, mostly.** The rmcp 3.10.0 source confirms both of A's facts:
   - `call_tool` goes through an mpsc channel to the service loop, which then runs the transport `send` in a spawned task.
   - The HTTP worker can queue a POST and resend it after re-initializing the session (`reinit_on_expired_session`).

   So the `dispatch` gate moved into BOGO's own exact transport, at the write. That puts every SDK queue before it while keeping rmcp's ID allocation and correlation, which answers B's objection. Re-init is turned off, and the marker is one-shot. On an upstream that is down, A wins too: a broken upstream fails closed (Principle 1), and no approved call is left waiting to run much later.

3. **Durable authority and delivery recovery: B.** Every phone→Mac message is idempotent, and the relay is acked only after the effect is durable. A phone `sync` answered from the log recovers lost outcomes after a crash or a relay loss. So a SQLite registry, outboxes and durable receipts add machinery without adding safety. Two cases A raised are closed with idempotent actions rather than new tables:
   - On every boot, BOGO re-applies its relay allowlist and resends `registered{txId}` to every active approver.
   - A `removed` from an approver that is already revoked is acknowledged again.

4. **Justification schema compatibility: B.** A's closed-subset compiler would reject most real MCP schemas, which often don't set `additionalProperties: false`. That breaks "works with any MCP server". And there is no safety gain, because what runs is exactly what was signed whatever the advertised schema says. B's widening rules, plus the `strict-client-risk` flag and the owner question, are kept. A's honest limit is added as a documented "known limit": an open schema can't carry an undeclared upstream key with the reserved name.

5. **Sandbox DNS isolation: A on the fact; B's concrete setup kept.** Docker's resolver lives at loopback address `127.0.0.11` and forwards outside lookups, so "allow loopback" and "no DNS" conflict as B wrote them. The rules now drop `127.0.0.11` first and accept loopback only for `127.0.0.1`. Current Moby skips forwarding for containers that are only on internal networks (CVE-2024-29018), but the rule doesn't rely on that. Both sides agreed on the fixed TCP forwarder.

6. **Proof and ABI boundaries: A.**
   - `@[export]` emits exactly the name it is given, so B's Lean `bogo_core_step` would have collided with the C shim's `bogo_core_step`. Exports are now in three separate namespaces: `bogo_lean_*`, `bogo_core_*` and `bogo_rs_verify`.
   - The `extern` target is a C shim that reads Lean `ByteArray` objects. It was a raw-pointer Rust function, which the Lean FFI can't call directly.
   - Agent identity, clock and storage are now listed assumptions (A8–A10), on top of B's table of tagged origins.

7. **Expiry clock: B.** The wall clock is read once per boot, plus `CLOCK_MONOTONIC`, which counts sleep on macOS (`man clock_gettime`; Rust's `Instant` uses `CLOCK_UPTIME_RAW` on Darwin and doesn't count sleep). Rollback within a boot can't extend a lifetime, and no request survives a boot. A's second wall-clock check could only end requests earlier, so it adds no safety.

8. **Shim mechanism: A's wording.** The shim needs the negotiated protocol version, which arrives in the `initialize` response body, not a header. It now reads envelope fields only (`id`, `method`, `result.protocolVersion`) and still never touches or re-encodes `params`.

9. **Unresolved spec and trust choices: split.**
   - Default-allow: refused at startup and asked (both sides agreed this fails closed).
   - App Attest: production-only by default, development is opt-in, and it is asked.
   - Link's auth file: allowed as a path secret under `~/.bogo` and asked, since without it Scenario 1 can't run at all.
   - A was right that B's blanket path rule contradicted B's own Link auth path. The rule now covers upstream `command`/`args` (agent-reachable paths), and path secrets must sit inside `~/.bogo`.

## Points Design B raised

1. **One log versus SQLite: B** (as in A's point 3). One structure, one recovery rule, one thing to verify.
2. **No durable receipts: B.** Every phone message is safe to apply twice, so receipts would cost an fsync and add nothing.
3. **When an allowed call's record is written: A.** Writing it alongside the send means a crash after the send can lose the only record of a call that ran, which breaks "a crash loses nothing" and Scenario 15. The spec has no speed target. The trade-off is raised under Questions, tied to the PRD's "negligible overhead" open item.
4. **Tools whose schema can't be widened simply: B** (as in A's point 4).
5. **Where input decoding happens: B.** Lean decodes the wire bytes in `stepFfi`, so "malformed never forwards" is proved. Rust does no authorization validation. JSON lexing stays in `bogo-json`, under the stated faithful-shell assumption.
6. **The handoff boundary: A** (as in A's point 2). The verified rmcp source shows more than "one in-process hop": a spawned send task, plus the HTTP worker's retry queue. Gating inside the transport removes the gap without replacing rmcp.
7. **The sandbox forwarder: agreed.** A fixed `socat` forwarder that parses nothing.

## Other choices worth noting

- **Every forward now comes from `dispatch`,** allowed calls included. That gives the proof a single forward source.
- **App Attest uses BOGO's own named steps** (`ciborium`, `x509-cert`, `p384`) against a pinned root. That replaces a young third-party crate, and the macOS system trust store.
- **The phone store is system SQLite,** so a state change and its outbox row commit together.
- **Six-digit code: `u64 mod 10^6`.** The bias is below 2^-44, so no rejection loop is needed.
