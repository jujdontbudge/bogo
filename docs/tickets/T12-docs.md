# BOGO's docs: quick start, configuration, threat model, and what is proved

## Goal
Write BOGO's user docs, as `docs/ARCHITECTURE.md` §8 step 12 lists: a README quick start, a configuration reference, the threat model and its assumptions, and "What is proved / What is assumed". The last one is written from the theorem statements in `lean/BogoProofs/Promise.lean` and the axioms `#print axioms` lists, not from memory or the spec.

The owner and anyone they share BOGO with will read these docs first, so they have to be true of the code as it is now on `build/bogo`. When this is done, someone new to BOGO can follow the README on this Mac from nothing to a running daemon with the filesystem upstream and a named agent in Claude Code, plus one protected call approved. The configuration reference covers every key `bogo.toml` and `secrets.toml` accept, with what each does and the values BOGO refuses. The threat model says, in plain words, what BOGO protects against and what it doesn't. "What is proved" states each proved property in words a non-expert can check against the theorem it names, and "What is assumed" lists each named assumption, including A1, and what breaks if it fails. A claim the code or the proofs don't back does not count. Where something isn't built or checked yet (the real device, push, App Attest on hardware, the public relay, the Link login), the docs say so rather than describing it as working.

If being complete and being correct pull against each other, correct wins.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/`, `docs/ARCHITECTURE.md`, `docs/daemon.md`, `docs/RELAY-PROTOCOL.md`, `sandbox/` and every file in `docs/verification/`. All tickets except the relay deployment and the final device session are merged on `build/bogo`.
- The iPhone side lives in `/Users/johansardar/apple-bridge-iphone` on its `build/bogo` branch; read it, but don't change it.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Docs only: don't change code. Report any bug you find instead.
- Never touch the Apple Bridge Mac repo. No password prompts; `sudo` only as `sudo -n`.
- No secrets, tokens or the owner's personal details in the docs.

## Guardrails
- Existing docs (`SPEC.md`, `ARCHITECTURE.md`, ADRs, verification records) keep what they say; you may link to them.

## How to verify
1. Follow the README yourself from an empty temporary BOGO home, exactly as written, through to one protected call approved with the soft approver from real `claude -p`. Every command works as written.
2. Check every key in the configuration reference against what BOGO's config parser accepts and refuses, by trying each refused value.
3. Read each statement in "What is proved" next to its theorem in `Promise.lean`, and the assumptions list next to the `#print axioms` output. Each one matches.
4. Read the threat model against SPEC's threat model and the bypass suite's report. Nothing is claimed that they don't support.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
