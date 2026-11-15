# Foundations: the exact request bytes, in Lean and Rust

## Goal
Lay the foundation every other part of BOGO is built on: the Cargo workspace and Lean project, the JSON value tree and the signed request encoding written in Lean with their proofs, the test vectors the Lean encoder generates, the `bogo-json` Rust crate that parses and writes tool arguments exactly, and the `bogo-config` crate that reads `bogo.toml` and `secrets.toml`. Everything is as `docs/ARCHITECTURE.md` describes it (§2 units, §3.2 request encoding, §6 data and versions, §7 repo layout, the `bogo-json` and `bogo-config` rows), and the meaning comes from `docs/SPEC.md`.

This matters because the bytes an approver signs are the heart of BOGO's promise: the owner approves exactly what they see, and two different requests must never encode the same way. The iPhone app, the Rust daemon and the proofs will all be checked against the vectors this ticket produces, so the vectors are the shared truth, and four parallel tickets start from this one.

When it is done: `lake build` in `lean/` builds `BogoCore`'s JSON and encoding modules and `BogoProofs`, with the proofs that decoding an encoding gives back the original request and that the encoding is injective, and with no `sorry` and no axioms beyond Lean's standard ones. Running `BogoVectors` writes `vectors/*.json` covering real-looking requests and the messy cases (numbers like `4700`, `4700.0`, `4.7e3`, `4.7E3`, `-0`, very long numbers, nested objects with keys in different orders, unicode, empty and absent arguments, optional expiry present and absent). `bogo-json` parses those same argument texts and writes them back byte for byte, keeping every number's exact text, rejecting duplicate keys and lone surrogates; a `bogo-json` that normalises any number does not count. `bogo-config` loads a realistic `bogo.toml` and `secrets.toml` (the shape in SPEC §7), refuses unknown fields, refuses `allow` as the default policy, and never prints a secret value in `Debug` or errors. `cargo build` and `cargo clippy` pass for the workspace.

If the architecture and the spec disagree, the spec wins; if making something convenient would weaken exactness, exactness wins.

## Context
- BOGO is a new product in this repo (`/Users/johansardar/.t3/projects/bogo`, branch `build/bogo`). Read `docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md` first. `docs/architecture/` is design history; the settled design is `docs/ARCHITECTURE.md`.
- Lean 4 is not installed on this Mac. The `lean` on PATH is an unrelated Anaconda package. Install the Lean toolchain with elan in your home directory; no password is needed.
- Four tickets start right after this one: the iPhone section (Swift, decodes these bytes), the crypto and relay crates, the Lean decision core and proofs (builds on your JSON and encoding modules), and the upstream manager (uses `bogo-json` and `bogo-config`). Keep the module and crate boundaries the architecture names so they can build on yours.
- Commit your work on your own branch in your worktree, in small commits, ending each message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Never touch, depend on or reuse anything from the Apple Bridge Mac repo (`/Users/johansardar/apple-bridge`). The owner ruled this out.
- The product is called BOGO, never "Gate".
- No password prompts on this Mac: no Keychain writes; `sudo` only as `sudo -n`.

## Guardrails
- Numbers keep their exact text from parse to write; `4700`, `4700.0` and `4.7e3` stay different values everywhere.
- The Lean encoding proofs use no `sorry` and no extra axioms.
- Secrets never appear in logs, errors or `Debug` output.

## How to verify
1. `lake build` in `lean/` succeeds; grep the Lean sources for `sorry` and `axiom` and find none in BOGO code; `#print axioms` on the injectivity and round-trip theorems shows only Lean's standard axioms.
2. Run `BogoVectors`; inspect `vectors/` and confirm it contains each messy case listed in the Goal, with encoded bytes and the decoded form.
3. Feed every vector's argument text through `bogo-json` and compare the written bytes with the input, byte for byte. Show that `4.7E3` comes back as `4.7E3`, not `4.7e+3` or `4700`. Feed it a duplicate key and a lone surrogate and show both are rejected.
4. Load a realistic `bogo.toml` and `secrets.toml` with `bogo-config`; then add an unknown field, then set the default policy to `allow`, and show each is refused with a clear message. Format a loaded secret with `{:?}` and show the value does not appear.
5. `cargo build --workspace` and `cargo clippy --workspace` pass.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
