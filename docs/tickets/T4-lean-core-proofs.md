# The Lean decision core, its proofs, and linking it into Rust

## Goal
Write BOGO's decision core in Lean 4, prove the core promise about it, and link that exact compiled code into Rust. This is `BogoCore`'s `Policy`, `Core`, `Wire` and `Ffi` modules, `BogoProofs`, and the `bogo-core-sys` and `bogo-core` crates, as `docs/ARCHITECTURE.md` §3.1, §3.3 and §3.4 describe, for the promise in `docs/SPEC.md` §3.8, §3.8.1 and §3.18.

The core is the whole point of BOGO: given policy, requests, approvals, registered approvers and state, it alone decides execute or reject, and the promise is only as good as this code. The owner chose to prove it in Lean and to run the same Lean code the proof is about. When this is done: `lake build` builds the core and the proofs; the theorems state and prove, for a fully adversarial agent sending any input in any order, that every forward is **approved** (the any-of or k-of-n requirement met by distinct, registered, eligible approvers), **exact** (each approval covers exactly that call), **single-use**, **fresh** (session alive, expiry not passed when set), and **fail-closed**, covering revocation, per-agent policy, session binding, pause and the flood limit, and that `allow` cannot be the default. The only axioms beyond Lean's standard ones are the named assumptions in ARCHITECTURE §3.3 (signature unforgeability via the verify hook, hash collision resistance, and the rest listed there), each one visible in `#print axioms`. A Rust program linked against the compiled Lean library through `bogo-core` runs real scenarios and gets the decisions the spec requires.

A proof that holds only because the model leaves out an input the agent controls does not count, and neither does a theorem weaker than the property the spec states. If proving something forces the core to change, change the core; if the architecture's core design and the spec disagree, the spec wins.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md`. `BogoCore`'s JSON and encoding modules, their proofs, `bogo-json` and the vectors come from the Foundations ticket already merged on `build/bogo`; build on them.
- The Lean toolchain is installed with elan (Foundations did this); the pinned version is in `lean/lean-toolchain`.
- Running at the same time: the upstream manager ticket (`bogo-upstream`, which will call the core only through a `Gate` port) and the crypto crates ticket (which provides `bogo-verify`, the function behind the core's verify hook). Keep to the ABI and crate boundaries the architecture names.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- `BogoCore` imports only `Init` and `Std`; nothing imports `BogoProofs`; only `bogo-core-sys` touches `lean.h` or `unsafe` FFI.
- Never touch the Apple Bridge Mac repo.
- No password prompts; `sudo` only as `sudo -n`.

## Guardrails
- No `sorry` anywhere in BOGO's Lean code.
- No axioms beyond Lean's standard ones and the assumptions ARCHITECTURE §3.3 names.
- The proofs in Foundations (encoding round trip and injectivity) still hold.

## How to verify
1. `lake build` succeeds; grep for `sorry` finds none; `#print axioms` on each of the five promise theorems lists only standard axioms and the named assumptions.
2. Read each theorem statement next to SPEC §3.8 and confirm it says what the spec says, for an adversarial input sequence.
3. From Rust through `bogo-core`, run: an allowed call (forwards at once); a protected call approved once (forwards once); the same approval reused (rejected); `amount` 4700 approved then 4701 sent (rejected); the identical call from another session (rejected); a different justification (new request); a late approval after the session ended or the expiry passed (rejected); a revoked approver's approval (rejected); 2-of-2 with one approval, then the same approver twice (no forward), then a second distinct approver (forwards); a paused agent (rejected); an agent over its pending limit (rejected quietly); malformed input bytes (rejected).
4. The ABI check at startup refuses a mismatched library.
5. `cargo clippy --workspace` passes.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
