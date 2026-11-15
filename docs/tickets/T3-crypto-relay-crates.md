# Crypto and relay crates, and the relay service

## Goal
Build the Rust pieces that carry BOGO's messages between the Mac and the phone and check what comes back: `bogo-e2e` (envelope format, HPKE auth-mode seal and open, message IDs), `bogo-relay-proto` (relay wire types, mailbox auth, async client), the `bogo-relay` service binary (mailboxes, allowlists, the registration lobby, SQLite, TLS), `bogo-apns` (APNs token-auth HTTP/2 client), `bogo-verify` (P-256 approval signature check, plus the soft Ed25519 check only behind `test-approvers`), and `bogo-attest` (App Attest verification as named steps against a pinned Apple root). All as `docs/ARCHITECTURE.md` describes them (§2 rows, §3.4, §3.11, §3.12, §6) for the behaviour in `docs/SPEC.md` §3.13–§3.16.

The relay is trusted with nothing: it may only pass ciphertext along, and every decision is signed end to end. These crates are what make that true, and the approver hub, the phone link and the relay deployment all build on them. When this is done: two local clients exchange sealed messages through a locally running `bogo-relay` over TLS, with mailbox auth, allowlists and the registration lobby working, and the relay never able to read a payload; messages survive a relay restart; an envelope altered in transit fails to open; `bogo-apns` authenticates to Apple's sandbox APNs with the owner's existing key (a push to a made-up device token comes back as Apple's "bad device token" answer, which proves the auth works without a phone); `bogo-verify` accepts a valid P-256 signature over exact bytes and rejects any change; `bogo-attest` walks every named step of Apple's validation procedure.

This ticket builds and runs the relay locally only. Deploying it to the VPS is a separate checkpoint ticket.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md`. The workspace and `bogo-json` come from the Foundations ticket already merged on `build/bogo`.
- The owner's APNs key is at `~/.config/apple-bridge/apns/AuthKey_L2854KRF5Z.p8` (key ID `L2854KRF5Z`, sandbox environment, the app's bundle ID is in `/Users/johansardar/apple-bridge-iphone/ios/project.yml`). Read it from that path at run time; never copy it into the repo or logs.
- The relay will run at `bogo.eilmer.si` on the VPS that also hosts Apple Bridge's relay, as a completely separate service.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Never touch, reuse or connect to anything from Apple Bridge (`/Users/johansardar/apple-bridge`, its relay, its gateway). The owner ruled this out.
- Don't deploy anything to the VPS in this ticket.
- No password prompts: no Keychain writes; `sudo` only as `sudo -n`.

## Guardrails
- The relay can never read message contents; only ciphertext and routing data reach it.
- Secrets (the APNs key, mailbox keys) never appear in logs, errors or the repo.
- The soft Ed25519 verifier is absent from a default build.

## How to verify
1. Start `bogo-relay` locally with a self-made test certificate. With two clients, send sealed messages both ways; show the relay's stored rows contain only ciphertext.
2. Restart the relay mid-conversation; undelivered messages are still delivered afterward.
3. Flip one byte of a sealed envelope in transit; opening fails. Replay a message; it is recognised by its message ID.
4. A client without mailbox auth, or not on the allowlist, is refused.
5. Send one push with `bogo-apns` to Apple's sandbox with a made-up token; show Apple's response proving the JWT was accepted (bad device token, not an auth error).
6. `bogo-verify`: a valid signature passes; changing one byte of the message or signature fails.
7. `bogo-attest`: run each named step and show which input each step rejects; a real device attestation is checked later in the device session.
8. Build without `test-approvers` and show the Ed25519 path is absent. `cargo clippy --workspace` passes.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
