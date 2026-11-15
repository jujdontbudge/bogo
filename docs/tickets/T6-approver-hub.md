# The approver hub, the iPhone route, the registry, and the stand-in Mac

## Goal
Build the Mac side of approvals: `bogo-approver` (the `ApproverRoute` trait and the hub that fans each request out to eligible approvers, retries delivery, takes in decisions and answers `sync`, plus the registration driver), `bogo-approver-iphone` (numeric-comparison registration with App Attest, delivery through BOGO's relay, decision intake, notices and APNs pushes), `bogo-state` (the `~/.bogo` layout and permissions, the single-writer lock, BOGO's own keys, registry caches rebuilt from the log), the registry part of `bogo-log`, and the `bogo-standin` binary, all as `docs/ARCHITECTURE.md` §2, §3.9–§3.11, §5, §6 and §8 step 4–5 describe for `docs/SPEC.md` §3.8, §3.8.1, §3.13–§3.16.

This is how a request reaches the owner's phone and how a signed decision gets back, and it is where registration decides which keys BOGO will ever trust. When this is done, `bogo-standin` on this Mac and the BOGO section of the iPhone app in the iOS Simulator (the `build/bogo` branch of `/Users/johansardar/apple-bridge-iphone`) complete the whole loop through a real relay: the owner runs registration on the Mac, taps Add Mac in the app, both show the same 6 digits, the owner confirms on both, and the app is registered; then the stand-in sends real requests built from the Lean vectors, the app shows them, and the decisions that come back are verified with `bogo-verify` against the exact request bytes and recorded in the hash-chained log; removing the Mac on the phone revokes it on the Mac; the stand-in sends `settled`, `ended`, `boot` and `outcome` on command and the app reflects each. Every message across the relay stays safe to apply late, early or twice, and nothing is acknowledged before its effect is durable. A registration without valid App Attest evidence is refused, except the simulator-only test path, which only a test build of both sides accepts.

The real relay at `bogo.eilmer.si` may not be live yet; if it isn't, run `bogo-relay` locally and point both sides at it. The real device, Secure Enclave key and real App Attest wait for the final device session.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md`. Already merged on `build/bogo`: `bogo-json`, `bogo-config`, `bogo-e2e`, `bogo-relay-proto`, `bogo-relay`, `bogo-apns`, `bogo-verify`, `bogo-attest`, the Lean core and `bogo-core`, `bogo-upstream`, `bogo-filter`, and the vectors.
- The iPhone side (BogoKit, with `StandInMacLink`, its SQLite store and outbox, and the simulator-only key) is on branch `build/bogo` of `/Users/johansardar/apple-bridge-iphone`. Its `RelayMacLink` is a later ticket; to exercise the loop, drive the app with whatever the iPhone ticket's stand-in offers, or a small test harness, without changing the app's code.
- The owner's APNs key is at `~/.config/apple-bridge/apns/AuthKey_L2854KRF5Z.p8`; read it at run time only.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Never touch the Apple Bridge Mac repo, its relay or its gateway.
- Don't change the iPhone app's code in this ticket.
- No password prompts: no Keychain writes; `sudo` only as `sudo -n`.

## Guardrails
- Only keys registered through a confirmed numeric comparison (and valid App Attest, outside test builds) are ever trusted.
- A revoked approver's decisions are rejected.
- Nothing is acknowledged before its effect is durable; replays and reordering lose nothing and apply nothing twice.

## How to verify
1. Register the Simulator app with `bogo-standin` through a relay: show both 6-digit codes matching, then the registered approver in the log.
2. Send a payment request and a filesystem request from the vectors; approve one and deny one in the app; show both decisions verified against the request bytes and in the log.
3. Replay a decision message and deliver two out of order: each applies once.
4. Kill the stand-in mid-delivery and restart it; nothing is lost and nothing applied twice. Run `sync` from the app after a restart and show missing outcomes come back.
5. Remove the Mac in the app; show the approver revoked on the Mac, and a later decision from it rejected.
6. Try registration with a mismatched code, and without attestation in a non-test build: both refused.
7. `cargo clippy --workspace` passes.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
