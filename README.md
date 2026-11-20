# agent-trust-kit

The trust layer for agents on the [open agentic web](https://github.com/cognizant-ai-labs/agentic-web),
before they transact. Four questions, each answered by plain code, never by a model:

1. **Who published this agent network, and is it unchanged?** (domain signatures)
2. **Was it tested, on the model that will run it?** (attestations, network × model)
3. **Did this request really come from that site, and may it come in?** (signed requests, `admit()`)
4. **Was the deal what the person asked for, and can anyone check?** (commitments, mandates, signed receipts)

Part of **[Trust Before Transaction](https://github.com/FrankPonce/trust-before-transaction)**,
an entry to the [Open Agentic Web Challenge](https://cognizant-agenticweb.devpost.com/).
No new cryptography: it combines existing standards, and the same code runs in browsers,
Node 22 and Cloudflare Workers (WebCrypto Ed25519). Other tools sign agent files; this kit
ties who published an agent, how it behaved on a model, and what it was allowed to do into
one check.

## Five minutes, by role

```bash
npm install github:FrankPonce/agent-trust-kit
```

**You publish an agentic site.** Make your network verifiable:

```bash
npx trust-kit keys ./keys                                   # private key stays local
# publish keys/http-message-signatures-directory at /.well-known/http-message-signatures-directory
npx trust-kit sign-network site/my_net.network.json --name my_net --origin https://my.site --key keys/site-key.private.jwk.json
npx trust-kit check https://my.site/my_net --model openai/gpt-oss-20b   # what anyone else will see
```

Then have a tester such as [crash-test](https://github.com/FrankPonce/crash-test) attest it, once
per model your visitors run it on. Re-sign and re-test after every change: the hash moves.

**Your site links other sites' agents.** Show what's known about each partner on the
runtime's consent card, before the visitor agrees to contact it: serve
`/.well-known/peer-trust.json` with `peerTrustResponse(...)` and wrap the card with
`withPeerTrust(...)` ([details](#peer-trust-on-the-consent-card-drop-in)). Pass the model you
run partners on (`models`), because the partner's agents run on *your* model.

**Your server takes requests from other sites' agents** (an arbiter, a booking desk):

```js
import { admit, cachingFetch, signRequest } from "agent-trust-kit";

// Caller's server: sign the request and declare the model that ran its agent.
const signed = await signRequest({ method: "POST", url, headers: {}, body }, {
  privateJwk, signatureAgent: "https://caller.site", model: "openai/gpt-oss-20b" });

// Your server: signature → declared model → domain-signed network → attestation for that model.
const d = await admit(request, { fetchImpl: cachingFetch(fetch) });
if (!d.ok) return refuse(d.step, d.reason);   // "signature" | "model" | "network" | "attestation"
```

Admission is not authorization. It says who is calling and how its agent was tested; what the
request may do is your own check. For binding requests, seal what the person asked for,
including their own limits (the **mandate**, e.g. a maximum price kept out of the model's
reach), and answer with a signed receipt:

```js
import { commit, newNonce, signReceipt, verifyReceipt } from "agent-trust-kit";

const nonce = newNonce();
const commitment = await commit({ resident, energyKwh, readyByMs, maxPriceCents }, nonce);
const receipt = await signReceipt({ typ: "charging-receipt/v1", iss: "https://my.site", commitment, ... }, receiptKey);
// Anyone: verifyReceipt(receipt, { issuer: "https://my.site", typ: "charging-receipt/v1" })
// A static page: copy src/verify-lite.js (no imports) and use verifyStatementLite(...)
```

The live housing arbiter in [taloyhtio-charging](https://github.com/FrankPonce/taloyhtio-charging)
is built exactly this way.

## Exports

| Import | What |
|---|---|
| `agent-trust-kit/keys` | `newSiteKey`, `keyDirectory`, `fetchKeyDirectory`: Ed25519 keys at the Web Bot Auth location |
| `agent-trust-kit/network` | `signNetwork`, `verifyNetwork`: JWS over the network's JCS hash |
| `agent-trust-kit/attestation` | `attestationFromScorecard`, `signAttestation`, `verifyAttestation`, `actionsSha256`: in-toto + DSSE |
| `agent-trust-kit/rekor` | `logEnvelope`, `verifyLogEntry`: Sigstore Rekor entries, verified offline |
| `agent-trust-kit/peer` | `checkNetwork`, `checkSummary`, `peerTrustReport`, `peerTrustResponse`, `DEFAULT_TRUST_POLICY`, `cachingFetch` |
| `agent-trust-kit/peer-card` | `withPeerTrust`, `describePeer`: the consent card line (copy the file for a static site) |
| `agent-trust-kit/http` | `signRequest` (with `model`), `verifyRequest`: RFC 9421 |
| `agent-trust-kit/admit` | `admit`, `DEFAULT_ADMIT_POLICY`, `declareModel`, `declaredModel`, `MODEL_META` |
| `agent-trust-kit/receipt` | `commit`, `newNonce`, `signReceipt`, `verifyReceipt` |
| `agent-trust-kit/verify-lite` | `verifyJws`, `verifyStatementLite`, `canonicalJson`, `canonicalHash`: WebCrypto only, no imports |
| `agent-trust-kit/canonical`, `/dsse` | JCS (RFC 8785) hashing; DSSE envelopes |

## What it does

| Piece | Standard | Proves |
|---|---|---|
| **Key directory** at `/.well-known/http-message-signatures-directory` | JWKS, the [Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/) location; kid = RFC 7638 thumbprint | "These keys belong to this domain" (backed by HTTPS) |
| **Network signature** `<network>.signature.json` | JWS (RFC 7515, EdDSA) over the network's canonical hash (JCS, RFC 8785) | "This origin published this exact network, and it hasn't changed since" |
| **Attestation** | [in-toto Statement v1](https://github.com/in-toto/attestation) with the standard [Test Result predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md), in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope (Ed25519); subject = network URL + hash | "This exact network passed these tests on this model, until this date". Any in-toto tooling can read it |
| **Request signature** | HTTP Message Signatures (RFC 9421) + `Content-Digest` + `Signature-Agent` | "This request, with this body, came from that site's server" |

Verification always takes keys from the **network's own origin**, so a signed network
copied to another domain is rejected, and changing a single character of the network
breaks the signature.

> [!NOTE]
> Domain = identity, as with HTTPS. A signature proves which domain published an agent,
> not who runs that domain or whether its agent behaves. That is what attestations from a
> behavioural tester such as [crash-test](https://github.com/FrankPonce/crash-test) add.

## Lower-level use

```js
import { newSiteKey, keyDirectory, signNetwork, verifyNetwork,
         attestationFromScorecard, signAttestation, verifyAttestation,
         signRequest, verifyRequest } from "agent-trust-kit";

// Publisher (build time): sign the network, publish keys + signature next to it.
const doc = await signNetwork({ network, name: "charge_planner", origin: "https://charge.example", privateJwk });

// Anyone: check a network you fetched from https://charge.example.
const r = await verifyNetwork({ doc, network, name: "charge_planner", networkOrigin: "https://charge.example" });

// Tester: attest (in-toto statement in a DSSE envelope); arbiter: admit only attested agents.
const envelope = await signAttestation(attestationFromScorecard(scorecard, { issuer: "https://crashtest.example" }), testerKey);
const ok = await verifyAttestation(envelope, { issuer: "https://crashtest.example",
  expect: { network_sha256: r.network_sha256, required: ["grounding_on_failure"], minScore: 80, minCoverage: 80 } });

// Server-to-server: sign a request; the receiver verifies with the sender's directory.
const signed = await signRequest({ method: "POST", url, headers: {}, body }, { privateJwk, signatureAgent: "https://charge.example" });
const who = await verifyRequest(signed, { allowedAgents: ["https://charge.example"] });
```

## Peer trust on the consent card (drop-in)

Before the runtime contacts another site's agent, it asks the visitor on a consent card.
The card can now say what is known about that partner:

> Signed by housing.example · tested 100/100 (coverage 100%) on qwen3.8-flash by
> crashtest.example; kept private details private

or *Not signed by its domain · no test results from a tester this site trusts*. Each fact
gets a small drawn icon (a tick when it holds, a warning triangle when it doesn't), and the
words alone carry the meaning, so the line still reads with no colour and no icons.

The check runs on **your own server**, never in the visitor's browser, so nothing contacts the
partner before the visitor agrees. Nothing changes in the runtime, in agent-to-agent messages,
or in what the model sees. The default is to **show the facts and let the visitor decide**;
blocking unverified partners is opt-in.

1. **Serve `/.well-known/peer-trust.json`** from your origin. On a server or Worker:
   ```js
   import { peerTrustResponse } from "agent-trust-kit/peer";
   // GET /.well-known/peer-trust.json  (checked at most every 5 minutes)
   return peerTrustResponse("https://your.site/your_network");
   ```
   On a static host, write it in your build step instead (re-run it at least daily):
   `npx trust-kit peer-trust https://your.site/your_network --network site/your_network.network.json --out site/.well-known/peer-trust.json`
2. **Copy `src/peer-card.js`** next to your `site.js`, and after `boot()`:
   ```js
   const { withPeerTrust } = await import("./js/peer-card.js");
   booted.engine.onConsent = withPeerTrust(booted.engine.onConsent);   // { block: true } to opt in
   ```

`checkNetwork(url)` is the check behind it, and the same check an arbiter uses to admit a
cross-site caller: the network is signed by its own domain, and a tester in the policy has
an unexpired attestation for exactly that network hash, with score ≥ 80, coverage ≥ 80 and no
test that failed outright (`DEFAULT_TRUST_POLICY`; pass your own `policy`). Partners linked at
runtime by the visitor aren't in your network file, so they show as "not checked".

**Trust is network × model.** A partner's agents run on *your* model, so a tester can attest
the same network once per model, and a site can ask about the one it uses:
`checkNetwork(url, { models: ["openai/gpt-oss-20b"] })` (or `peerTrustReport(…, { models })`)
counts only attestations for those models, in that order, and says "not tested on …" when
there is none. Without `models`, the best attestation on any model counts.

It's the check inside `admit()`, which the live housing arbiter runs before it accepts a request,
so the consent card a visitor sees and the server that admits the caller decide the same way:

```js
import { checkNetwork, DEFAULT_TRUST_POLICY } from "agent-trust-kit/peer";

const r = await checkNetwork("https://charge.example/charge_planner", { policy: DEFAULT_TRUST_POLICY });
if (!r.trusted) refuse(r.attestation.reason || r.signature.reason);   // each refusal names its step
```

## Attestation format

```jsonc
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "https://site.example/my_net",
                "digest": { "jcs_sha256": "<hex>", "sha256": "<hex>" } },
              { "name": "https://site.example/agent-manifest.json#actions",
                "digest": { "jcs_sha256": "<hex of the manifest's actions>" } }],
  "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
  "predicate": {
    "result": "PASSED | WARNED | FAILED", "passedTests": [], "warnedTests": [], "failedTests": [],
    "configuration": [ /* ResourceDescriptors: test suite + version, model, judges, judge prompt digest */ ],
    "url": "<full scorecard>",
    // Extension fields (the Test Result predicate may be extended):
    "issuer": "https://crashtest.example", "issuedAt": "...", "expiresAt": "...",
    "score": 100, "coverage": 100, "results": { "<test_id>": { "verdict": "pass", "passRate": 1 } } } }
```

- `jcs_sha256` is SHA-256 over the network's RFC 8785 canonical JSON, lowercase hex: the
  same however the file is formatted. `sha256` is the file's bytes as served when tested.
- The `#actions` subject binds the site's declared actions (`agent-manifest.json` `actions`,
  JCS hash, `actionsSha256()`): the tools an agent can run on the page live outside the network
  file, so a new action changes this digest. `checkNetwork` requires it to match
  (`bindActions`, on by default).
- `warnedTests` are flaky tests (passed in some runs). `score` averages tests with a decided
  run; `coverage` is the share of runs that were decided.
- The envelope is DSSE v1 with `payloadType` `application/vnd.in-toto+json`; `keyid` is the
  tester's RFC 7638 key thumbprint, found in its key directory.
- Older compact-JWS attestations (`agent-network-attestation/v1`) still verify.

## Transparency log (Sigstore Rekor)

A signed attestation proves who vouched for a network. A **log entry** also proves *when*, and
that the tester can't quietly swap or withdraw what it published: the envelope's signature
and payload hash go on [Sigstore's](https://www.sigstore.dev/) public, append-only Rekor log.

```js
import { logEnvelope, verifyLogEntry, REKOR } from "agent-trust-kit/rekor";

const entry = await logEnvelope(envelope, testerPublicJwk, { rekorUrl: REKOR.production }); // publish next to the attestation
const v = await verifyLogEntry(envelope, entry);   // offline: same envelope, in the tree, root signed by Rekor
```

`verifyLogEntry` needs no network: it checks that the entry carries this envelope's payload
hash and signature (and, if given, the expected signer), recomputes the RFC 9162 inclusion
proof up to the logged tree root, and checks Rekor's signature on that root with Rekor's
key, pinned in the kit (`REKOR_KEYS`). A tester lists the entry in its index (`log` field);
`checkNetwork` then checks it and reports it, and a policy can require it:
`{ ...DEFAULT_TRUST_POLICY, requireLog: true }` (production Rekor by default, or `logs: [...]`).

Rekor v1 `dsse` entries are used because they keep the tester's existing Ed25519 signature;
Rekor v2 accepts neither the dsse type nor pure Ed25519. Entries are public and permanent.

## CLI

```bash
npx trust-kit keys ./keys                       # new Ed25519 key; private file stays local
npx trust-kit sign-network site/my_net.network.json --name my_net --origin https://site.example --key keys/site-key.private.jwk.json
npx trust-kit verify https://site.example/my_net   # OK / FAIL / UNSIGNED (a 404 or an HTML page = unsigned)
npx trust-kit check https://site.example/my_net --model openai/gpt-oss-20b [--require-log]   # the full check: ADMIT / REFUSE, exit 0 / 1
npx trust-kit peer-trust https://site.example/my_net --out site/.well-known/peer-trust.json
```

## Limits

- **Domain = identity.** A signature proves which domain published a network, not who runs
  that domain: the same trust model as HTTPS.
- **An attestation is only as good as the tester you trust.** The policy names trusted
  testers by origin; the kit checks their signature, not their judgement.
- **Covered: the network file and the manifest's declared actions.** The site's action code,
  what an action actually does, and the live page are not covered.
- **The declared model is the caller's claim.** `admit()` checks the attestation for the model
  the caller signs into its request; nobody can prove which model ran in a visitor's browser.
  It stops a site presenting a test on a strong model for a session on a weak one, not a site
  that lies outright.
- **Admission is not authorization.** A signed, well-tested caller can still ask for something
  it shouldn't; the receiving service checks what each request may do (the person's code,
  their sealed mandate, its own rules).
- **Opt-in.** The agentic-web runtime doesn't run these checks itself; a site or an arbiter
  gets them by using the kit.
- **No revocation.** Attestations expire after 30 days; a withdrawn one stays valid until
  then. The transparency log makes changes visible, it doesn't revoke.
- **Pinned log keys.** Rekor's keys are pinned in the kit; if Sigstore rotates them, the
  kit needs an update (Sigstore's TUF root is the authoritative source).

## Tests

```bash
npm test
```

Ed25519 signatures are deterministic, so `test/vectors/` pins exact expected output for a
fixed key and network: any change in canonicalization or signing fails CI. The key in
`test/vectors/` is **published on purpose and for tests only**. Real private keys are
git-ignored (`*.private.jwk.json`).

Apache-2.0
