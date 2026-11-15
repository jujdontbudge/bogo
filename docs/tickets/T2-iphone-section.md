# The BOGO section in the iPhone app, working against a stand-in

## Goal
Build the BOGO section inside the existing Apple Bridge iPhone app (`/Users/johansardar/apple-bridge-iphone`), replacing the app's old Approvals feature entirely, so that the owner can see BOGO approval requests, read exactly what will run, and approve with Face ID or deny. It is the `BogoKit` package (BogoModel, BogoCrypto, the stand-in half of BogoRelay with its SQLite store and outbox, and BogoSection) plus the host-app edge edits, as `docs/ARCHITECTURE.md` §3.13 and §3.14 describe and `docs/SPEC.md` §3.14–§3.15 and §3.5 define. It runs against `StandInMacLink`, which replays requests from BOGO's Lean-generated `vectors/`, so nothing here waits on a relay or a Mac.

This is the owner's whole experience of BOGO: the screen where they decide. The promise depends on it showing the truth, so the review screen is built only from the exact bytes being signed, never from a summary. When this is done, in the iOS Simulator: the old Approvals tab is gone and a BOGO tab shows Inbox, History and Macs. Requests from the vectors appear in the Inbox; identical requests are grouped with a count; ended ones are greyed out and can't be approved. Opening one shows "Will execute (exact)" (upstream, tool, every argument, "Requested by <agent name>", highlighted fields in their display format, a countdown only when there is an expiry) and, clearly separate, "Agent's reason (unverified)" (justification, the client's self-reported name, a session tag, and the money-only mismatch warning). Approve becomes tappable only after the short arm delay and signs with a Face ID–gated key; Deny takes an optional note; Pause agent works; decisions land in History and in the outbox. A request that fails to decode or isn't canonical shows "Unreadable request" with Deny only. Capture commands come back denied and Apple Bridge's old approval jobs are ignored.

The real device has a Secure Enclave and App Attest, but the Simulator has neither, and the owner wants everything that needs their phone or face deferred to one device session at the very end. So the Simulator path uses a simulator-only signing key with simulated Face ID, compiled only into Simulator/test builds and impossible to reach in a device or release build; the real Secure Enclave key (Face ID–bound, invalidated when enrollment changes) is written now and exercised in that final session.

The owner wants the BOGO UI and UX "extremely clean and simple". Before designing, study real examples of clean, minimal iOS design (Apple's own apps and Human Interface Guidelines, and the best minimal apps you can find) and note what makes them calm and clear. Then work in loops: build a screen, run it in the Simulator, screenshot it, critique it honestly against those references, and improve it. Repeat many times on every screen (Inbox, review, History, Macs, Add Mac, empty and unreadable states, light and dark mode) until each one is ultra clean: nothing on screen that doesn't need to be there, one clear thing to do, generous spacing, native components and type. A screen that merely works does not count as done. Clean never wins over truth, though: the review screen still shows every argument and keeps "Will execute" and "Agent's reason (unverified)" clearly distinct.

The rest of the app must keep working exactly as it does: every other capability, Apple Bridge pairing and delivery. If building BOGO and leaving the rest of the app untouched pull against each other, the rest of the app wins, except where the spec says the old Approvals feature and capture approval go away.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md` (§3.2 encoding, §3.11 message formats, §3.13, §3.14). The vectors live in `/Users/johansardar/.t3/projects/bogo/vectors/` on branch `build/bogo`.
- The app repo has its own rules: read its `README.md`, `ios/README.md` and `PRINCIPLES.md` (zero comments, enforced by `make lint`; E2E first; glossary words in code). Build with `make simulator`; checks are `make lint` and `make test`.
- The owner's words: the BOGO part "is build on the apple bridge iphone app… you can make a whole section for your UI… get the current approval feature entirely just totally dump it."
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Never touch anything in the Apple Bridge Mac repo (`/Users/johansardar/apple-bridge`), and never change Apple Bridge pairing, its gateway client, its relay path or its push delivery beyond the edge edits in ARCHITECTURE §3.14.
- BOGO keeps its own keys, storage and Keychain items, shared with nothing in Apple Bridge.
- No physical iPhone and no Face ID from the owner in this ticket.
- The product is called BOGO, never "Gate".

## Guardrails
- Every other capability and Apple Bridge pairing behave exactly as before.
- `make lint` and `make test` pass as they do now (the existing checks that name the Approvals tab are updated to the BOGO tab, nothing else added).
- The simulator-only key and attestation skip cannot exist in a device or release build.
- The review screen shows only what is in the signed bytes.

## How to verify
1. `make simulator` builds; install and launch in the iOS Simulator. Take screenshots of: the BOGO tab, the Inbox with a grouped request and an ended one, the review screen for a Stripe-like payment vector, and History after a decision.
2. Pick a vector whose `amount` is 50000 cents with justification "$5": the review shows $500.00 under Will execute and the mismatch warning beside the reason. A justification mentioning "6pm" and "$47" against 4700 cents shows no warning.
3. Approve with simulated Face ID (Simulator → Features → Face ID → Matching Face): Approve is disabled until the arm delay passes; the signed decision appears in the outbox and verifies against the request bytes. Try Non-matching Face: nothing is signed.
4. Deny with a note, and Pause agent: both are recorded; a paused agent's requests show as refused.
5. Feed a corrupted vector: "Unreadable request" with Deny only.
6. Build a release/device configuration and show the simulator key path is absent (for example by symbol or build-setting inspection).
7. Open the other tabs and capabilities and compare with the app before the change: unchanged. A capture command is answered as denied.
8. `make lint` and `make test` pass.
9. Show the design loop: the references you studied, and for each screen the first and final screenshots plus the main changes between them, in light and dark mode. Judge the final screens the way a demanding designer would: would they hold up next to Apple's own apps?

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
