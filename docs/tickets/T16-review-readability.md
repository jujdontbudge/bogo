# Make the iPhone's Review screen readable at a glance

## Goal
Make the BOGO Review screen something the owner can understand in a few seconds. In the first real-device test on 2026-11-16, the owner opened a Link request and said "I don't understand what happened here": the screen listed all 14 arguments of a catalog search in one long tree, most of them empty `[ ]`, with the agent's name, the action and the reason far apart, and nothing saying in plain words what would happen. The facts were all there; the owner couldn't find them.

When this is done, the top of the Review screen answers, in order: who is asking (the agent), what will happen (the upstream, the tool, and for wrapper tools like Link's `call_write_tool` the action in its `name` argument), the values that matter (highlighted fields in their formats, such as "$11.99", merchant, test mode, plus the agent's picture from T14), and the agent's reason, labelled unverified. Below that, the full "Will execute (exact)" argument tree stays, complete and inspectable, but empty values (`[]`, `{}`, `""`, `null`) fold into one quiet "N empty fields" row the owner can expand, and long trees are easy to scan. A new owner who has never seen BOGO can tell a search from a payment without reading raw JSON.

If being short and being complete pull against each other, complete wins: nothing the owner signs may be hidden without a visible way to see it, and every raw value stays one tap away.

## Context
- The iPhone app is `/Users/johansardar/apple-bridge-iphone`, branch from `build/bogo` (which now includes T14's pictures). Its worktree `/Users/johansardar/.t3/worktrees/apple-bridge-iphone/bogo-relay-link` is checked out at `build/bogo`'s head; make your own branch there or in a new worktree. The screen is `ios/BogoKit/BogoSection/ReviewScreen.swift`, with `AgentPicture.swift`, `Formatting.swift` and `BogoModel/Review.swift`.
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md` (§3.5, §3.6 and the review screen), `docs/ARCHITECTURE.md` "Will execute (exact)", and `docs/tickets/T2-iphone-section.md` and `T14-review-images.md` for the visual bar and what's already there.
- Two real requests to reproduce, both from the live run: a Link `call_read_tool`/`call_write_tool` with `name = "ucp_catalog_search"` and 14 arguments (brand, category, color, condition, gender, material, size as `[]`; currency "USD"; includeFacets false; limit 5; offset 0; priceMax 1300; query "fun quirky desk toy"; test false), reason "Find a fun item under the user's $20 total budget."; and a Link `call_write_tool` with `name = "spend-request_create"`, amount 1199 usd, merchantName "Amazon", test true, a `lineItem` with `image_url`, `context` paragraph, and a reason. Use the stand-in Mac in your own Simulator to show them.
- Commit on your own branch, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Display only: no change to what is signed, forwarded or logged, and no change outside the BOGO section and its model.
- Don't touch the Apple Bridge Mac repo or the BOGO Rust repo.

## Guardrails
- Approve/Deny, the arm delay, the mismatch warning, T14's pictures and the full raw argument tree behave as before.
- Light and dark mode stay ultra clean, matching the T2 and T14 screenshots.

## How to verify
1. Show both real requests above, light and dark, before and after.
2. Show the empty-field fold expanding to the full raw values.
3. Show a request with a mismatch warning and one with a picture still look right.
4. Approve one request; the stand-in Mac verifies the signature as before.
5. `make lint` and `make test` pass.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. Iterate the design with screenshots until it is ultra clean. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
