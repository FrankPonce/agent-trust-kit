# agent-trust-kit

Domain-signed identity for agents on the [open agentic web](https://github.com/cognizant-ai-labs/agentic-web):
who published this agent network, is it unchanged, did a trusted tester check it, and
did this request really come from that site?

Part of **[Trust Before Transaction](https://github.com/FrankPonce/trust-before-transaction)**,
an entry to the [Open Agentic Web Challenge](https://cognizant-agenticweb.devpost.com/).
No new cryptography: it combines existing standards, and the same code runs in browsers,
Node 22 and Cloudflare Workers (WebCrypto Ed25519).

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

## Use

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

> ✓ Signed by housing.example · ✓ tested 100/100 (coverage 100%) on qwen3.8-flash by
> crashtest.example; kept private details private

or *⚠ Not signed by its domain · ⚠ no test results from a tester this site trusts*.

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

## CLI

```bash
npx trust-kit keys ./keys                       # new Ed25519 key; private file stays local
npx trust-kit sign-network site/my_net.network.json --name my_net --origin https://site.example --key keys/site-key.private.jwk.json
npx trust-kit verify https://site.example/my_net   # OK / FAIL / UNSIGNED (a 404 or an HTML page = unsigned)
npx trust-kit peer-trust https://site.example/my_net --out site/.well-known/peer-trust.json
```

## Tests

```bash
npm test
```

Ed25519 signatures are deterministic, so `test/vectors/` pins exact expected output for a
fixed key and network: any change in canonicalization or signing fails CI. The key in
`test/vectors/` is **published on purpose and for tests only**. Real private keys are
git-ignored (`*.private.jwk.json`).

Apache-2.0
