# The iPhone app talks to the Mac over BOGO's relay

## Goal
Give the BOGO section of the iPhone app its real link to the Mac. That means BogoKit's `RelayMacLink` and HPKE channel, plus the registration flow with numeric comparison and App Attest, as `docs/ARCHITECTURE.md` §3.11, §3.14, §4, §5 and §8 steps 3–4 describe for `docs/SPEC.md` §3.13–§3.16. The app's code lives in `/Users/johansardar/apple-bridge-iphone`, on its `build/bogo` branch.

Until now the app has talked only to its built-in stand-in Mac. The Mac side (`bogo-approver-iphone` and `bogo-standin`, merged on BOGO's `build/bogo`) worked through a test harness that played the phone's relay link. When this is done, the real app in the iOS Simulator registers with `bogo-standin` through a relay. The owner taps Add Mac, both sides show the same 6 digits, and the owner confirms on both. Requests the stand-in sends then appear in the app. Approve (Face ID, after the arm delay) and Deny with a note come back to the Mac verified against the exact request bytes. `settled`, `ended`, `boot` and `outcome` from the Mac each show correctly in the app. One case that must come out right: a request whose boot was killed must read as ended, not "Approved", in History. Remove Mac on the phone revokes it on the Mac, `sync` after a restart brings back missing outcomes, and every message stays safe to apply late, early or twice.

The stand-in Mac stays available in Debug builds for working without a Mac. Also fix a visual bug from the iPhone section ticket: the Deny/Approve bar overlaps the start of "Agent's reason". The app's BOGO screens must stay as clean and simple as they are now. Any screen you add or change is studied against clean, minimal references and iterated (build, screenshot, critique, improve) in light and dark mode until it is ultra clean.

The real iPhone, its Secure Enclave key, real App Attest, push wake-ups and Face ID on a real face wait for the final device session. Here, use the simulator-only key and the simulator-only attestation test path, which only test builds of both sides accept.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/ARCHITECTURE.md`, `docs/RELAY-PROTOCOL.md` (including its "iPhone route messages" section) and `docs/verification/` on BOGO's `build/bogo`. The Mac side's own evidence, including how its harness drove the app, is in the T6 report folder `/private/tmp/claude-501/-Users-johansardar--t3-worktrees-bogo-t3-9be58da8-dd6d684fe0a61dc6/edadca25-85d3-4d6e-8ce2-143ff81b60bf/scratchpad/evidence/REPORT.md`.
- The relay at `bogo.eilmer.si` may not be live yet; if it isn't, run `bogo-relay` locally. Check again before you finish, and if it is live, also run the registration and one approval through it.
- A simulator named "BOGO iPhone" may be in use by another session; use your own simulator.
- Running at the same time: the daemon and CLI ticket in the BOGO repo. Don't change BOGO's Rust crates except for a real bug in the iPhone route, which you report.
- In the app repo, work on a branch off `build/bogo` in a separate worktree, with small commits each ending in `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Don't push; the owner's GitHub account is unavailable.

## Constraints
- Never touch the Apple Bridge Mac repo, its relay, gateway, pairing or APNs path, or any non-BOGO part of the iPhone app beyond the edges the iPhone section ticket already set.
- No password prompts on this Mac: no Keychain writes outside the app's own simulator sandbox, `sudo` only as `sudo -n`.

## Guardrails
- The app signs only the exact bytes it received and showed.
- A test-only key or attestation path can never be accepted by a release build.
- The app's other tabs and features work exactly as before.
- The BOGO screens look at least as clean as the iPhone section ticket's final screenshots in `/private/tmp/claude-501/-Users-johansardar--t3-projects-bogo/be44f81b-a4f2-44bb-a00e-e93d420ec895/scratchpad/shots/final/`.

## How to verify
1. Register the Simulator app with `bogo-standin` over the relay. Screenshot both codes matching, and show the registered approver in the Mac's log.
2. Approve a payment request and deny a filesystem request with a note in the app. Show both verified on the Mac against the request bytes.
3. Send `settled`, `ended`, `boot` and `outcome` from the stand-in, and screenshot the app after each. Kill the stand-in mid-request, restart it, and show History reads ended.
4. Replay and reorder messages: each applies once. Restart the app offline, approve, reconnect: the outbox delivers once.
5. Remove the Mac in the app: show it revoked on the Mac.
6. Screenshot the review screen with a long reason: the bar no longer covers it. Compare light and dark mode against the final screenshots.
7. Build a Release configuration and show that it rejects the simulator key and the test attestation path.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
