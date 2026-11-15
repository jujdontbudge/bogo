# Threat model

BOGO controls MCP calls that pass through it. It treats the agent as hostile:
it may be prompt-injected, lie, send malformed messages, replay signatures,
change arguments, reorder requests or try a different session. An agent token
identifies a named agent; it grants no approval authority. The owner chooses
which tools are protected, allowed or denied.

The practical boundary is crucial: **BOGO does not sandbox an agent by itself.**
A Claude process on the owner's Mac can use its built-in shell or any other
available access to bypass MCP. The [README](../README.md) demonstrates the
approval path with those tools disabled for the run. For isolation, use and
verify the [reference Docker sandbox](../sandbox/README.md), with no owner home,
BOGO state, owner socket, upstream credentials or Docker socket mounted into
the agent. Local upstream executables run with the daemon's authority and
must be trusted; config path checks are not containment for arbitrary code.
The path checks run once, at startup, so a link changed after startup is not
re-checked; they are not complete path containment.

## Protection within that boundary

The compiled Lean core checks effective policy for every call and at final
dispatch. A protected forward requires enough distinct, still-registered
eligible approvers signing the exact stored request. The request binds the
upstream, tool, arguments, justification, agent, session, nonce and times.
Changing an argument or justification requires a new approval. A signature
cannot be stretched across sessions or reused for a second forward. Deny and
unknown tools fail closed; newly discovered unlisted tools require approval
unless the owner chose default deny.

An ended call/session, cancellation, pause, revocation or expiry observed
before the final gate removes or invalidates authority. The stdio shim keeps a
liveness connection so process death ends its session. Direct HTTP clients
that silently vanish between requests cannot always be detected: a pending
retry request can remain, but needs a retry in that same session to execute.
Use the shim for that lifecycle binding. There is no default request expiry;
configure one if a live session alone is not a sufficient lifetime.

The iPhone implementation renders the request from the bytes it signs. Its
review separates “Will execute (exact)” from “Agent's reason (unverified)”.
The reason can still be a lie; its simple currency-mismatch warning is not a
truth detector. The review, arm delay, grouping and pause controls reduce
fatigue, while the core's per-agent live-request limit rejects excess requests
without asking an approver. None guarantees an attentive owner or prevents
all denial of service.

For a correctly registered production iPhone, the intended key protection is
a nonexportable Secure Enclave P-256 key gated by current biometrics, with no
passcode fallback in the approval path. Changing biometric enrollment requires
re-registration. App Attest checks the genuine build at registration; it does
not directly attest the signing key's access controls. This relies on that
build's code and Apple's OS/hardware. **These claims have not yet been qualified
in the final real-device session.** A software approver or Debug simulator key
is not equivalent. In any-of mode, one weak eligible approver weakens the whole
policy; a software approver must never protect real actions.

The relay transports authenticated encrypted envelopes. With correct endpoint
crypto and registration, watching or altering relay traffic cannot reveal
request contents or forge an approval. The relay can observe addresses,
mailbox/routing metadata, ciphertext sizes and timing, and can drop, delay,
repeat or reorder deliveries. It can deny service. Registration lobby labels
and public handshake data are not encrypted request contents. The owner must
actually compare the six-digit registration codes; numeric comparison is not
a substitute for doing that check. Push is only a generic wake-up with routing
IDs, not an approval or the request queue. Transport privacy also rests on
crypto/library correctness, separate from the Lean decision theorem.

BOGO stores upstream credentials privately and scrubs known secret values from
upstream traffic. Per-tool result filters can strip/redact fields that might
give an agent a bypass capability; unfilterable text is withheld when filtering
is configured. The owner must choose the right tools and fields. This is not a
proof of complete information-flow control, and it does not make every result
safe. An allowed read or an approved tool can still disclose capabilities in
unexpected fields or representations.

## What it does not protect against

- A compromised Mac, daemon, owner account or executable/toolchain. Same-account
  processes can use the owner socket, read secrets or alter policy; filesystem
  mode 0600 is not isolation from that account.
- A compromised phone OS, broken biometrics/Secure Enclave, stolen usable keys,
  malicious trusted build, or failure of cryptography.
- An upstream provider or local MCP server that lies, ignores arguments, has an
  access-control bug, or performs side effects beyond the advertised call.
- The owner approving a harmful action whose arguments were shown accurately.
  Exact approval does not imply good judgment or truthful upstream descriptions.
- Effects already sent. Revoking or cancelling after dispatch does not roll back
  a provider action. If the connection fails after sending, the action may have
  happened; BOGO reports unknown and does not replay it.
- Guaranteed uptime, notification delivery, protection from all traffic floods,
  all covert channels, kernel/Docker escapes, or every possible sandbox bypass.

The audit is a local hash chain with signed approval evidence. `bogo log verify`
checks chain integrity, canonical request bytes, signatures and threshold
justification at recorded registry state. It does not prove that a provider
performed a business action. It also cannot detect replacement of the **whole**
log with a valid shorter history without an external anchor. Keep private
exports if an independent comparison is needed. Arguments and justifications
are recorded in plaintext locally; exports can contain sensitive action data.
Result bodies are not stored. Never put credentials into tool arguments on the
assumption that the audit will hide them.

## Assumptions and evidence

All named assumptions, including A1 and the exact Lean axiom dependencies, are
listed with failure consequences in
[What is proved / What is assumed](proved-and-assumed.md#what-is-assumed-and-what-fails-without-it).
They cover signatures/user verification, hashes, boot freshness, isolation,
provider authentication, faithful shell/toolchain, genuine app, owner/identity
origin, clock and storage. They are part of the guarantee, not optional caveats.
This boundary follows [SPEC §3.19](SPEC.md#319-threat-model).

The recorded [bypass run](verification/sandbox-e2e.md) stopped 145 attempts,
with zero failures and three controls. It tested direct networking, DNS,
forwarder proxying, modifying firewall rules, credential exposure in its scanned
scope, authentication, malformed MCP, forged/replayed approval and cross-agent
session reuse. It observes that sandbox and environment at that run; it does
not prove that every future installation or model edge is isolated.
In particular, the allowed model TCP forwarder reaches a shared service edge;
that edge refused other names and SNI/Host fronting during the run. That refusal
is external behavior, not an nftables guarantee. Model credentials remain in
the agent environment. Recheck the suite when changing isolation or egress.

Current verification includes the Mac daemon, real filesystem upstream,
software approval from real Claude Code, and local encrypted relay/software
phone flows. The public relay deployment and final real-device session remain
outstanding: no claim of completed Face ID, APNs delivery, App Attest on
hardware, or provisioning-prefix qualification follows from these records.
The Link login did not complete; forwarding a test payment request that returned
“Not authenticated” is not evidence of a successful payment or result filtering
against an authenticated Link response. Read
[daemon verification](verification/daemon-cli.md) and
[sandbox verification](verification/sandbox-e2e.md) for those distinctions.
