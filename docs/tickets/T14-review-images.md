# Show real pictures on the iPhone's Review screen

## Goal
When an agent's request includes a picture link (for example Link's `lineItem[].image_url`, or any argument whose key ends in `image_url`, `image` or `picture`, or an `https://` link in the agent's reason that points at an image), the iPhone's BOGO Review screen shows the actual picture, not just the link text. The owner is deciding whether to let an agent spend money or act for them, and a picture of the item is how a person checks "is this the thing I wanted". Today the phone shows only the URL as text, which the owner tested on a real iPhone on 2026-11-16 with a Rubik's Cube purchase and found useless.

When this is done, a request like the one in Evidence below shows the picture right under the argument (or under the reason) it came from, sized to the screen, and the screen stays as clean as the rest of the T2 BOGO section. The picture is clearly marked as coming from the agent and unverified, in the same voice as "Agent's reason (unverified)": the link is part of what the owner signs, but what the link shows is not, and it can change after approval. Nothing about what gets signed, forwarded or logged changes: this is display only, in the app.

If showing more and keeping the owner safe pull against each other, safe wins. The exact link text stays visible and inspectable under the picture, so the owner can always see what is really being signed.

## Context
- The iPhone app lives in `/Users/johansardar/apple-bridge-iphone`; work on a branch from `build/bogo` there (its worktree `/Users/johansardar/.t3/worktrees/apple-bridge-iphone/bogo-relay-link` is at `build/bogo`'s head). The Review screen is `ios/BogoKit/BogoSection/ReviewScreen.swift`, with `Formatting.swift` and `BogoModel/Review.swift`.
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md` (§3.5 Justification, §3.6 approval requests, the phone's review screen), `docs/ARCHITECTURE.md` around "Will execute (exact)", and `docs/tickets/T2-iphone-section.md` for the visual bar.
- The signed request already carries the full arguments and the justification; the phone decodes them in `BogoModel`. No Rust, Lean, relay or wire change is needed or wanted.
- A real request to test with (from the live run): Link `spend-request_create`, `lineItem` = `[{"name":"Classic 3x3 Rubik's Cube","image_url":"https://upload.wikimedia.org/wikipedia/commons/a/a6/Rubik%27s_cube.svg","quantity":1,"unit_amount":1199}]`. Note that link is an SVG.
- Use the stand-in Mac in a Simulator to put requests in front of the app, as T2 and T8 did (`docs/verification/` and the memory notes on simulator driving describe the drop folder). Use your own Simulator; others may be in use.
- Commit on your own branch, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Fetch pictures privately: an ephemeral URL session with no cookies, credentials or shared cache, `https` only, a size cap (about 5 MB) and a short timeout. Never follow a link to anything that isn't an image.
- Formats: at least JPEG, PNG, HEIC, GIF (first frame) and WebP; render SVG if it can be done safely without a web view, otherwise show a clear "can't preview this picture" with the link.
- A failed, slow or oversized picture never blocks Approve/Deny or delays the review. Show a quiet placeholder and the link.
- Don't touch any file outside the BOGO section and its model, the Apple Bridge Mac repo, or the BOGO Rust repo.

## Guardrails
- Approve/Deny, the arm delay, the mismatch warning and "Will execute (exact)" behave exactly as before. The full argument tree with raw values is still there; the picture is added, nothing is hidden or truncated.
- Light and dark mode both stay ultra clean, matching the T2 final screenshots.

## How to verify
1. Put the Rubik's Cube request above, plus one with a JPEG/PNG `image_url`, in front of the app in a Simulator. Show the Review screen with the picture under its argument, light and dark.
2. A link in the agent's reason to an image shows the picture under the reason.
3. A non-image link, an `http://` link, a 404, a 20 MB image and a slow server each show the placeholder and the link, and Approve still works with no delay.
4. Approve a request with a picture; the Mac's verification of the signature is unchanged (it signs the same bytes as without this feature).
5. `make lint` and `make test` pass.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. Iterate the design with screenshots until it is ultra clean. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
