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
| **Attestation** | JWS from a tester, bound to the network hash and the model | "This exact network passed these tests on this model, until this date" |
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

// Tester: attest; arbiter: admit only attested agents.
const jws = await signAttestation(attestationFromScorecard(scorecard, { issuer: "https://crashtest.example" }), testerKey);
const ok = await verifyAttestation(jws, { issuer: "https://crashtest.example",
  expect: { network_sha256: r.network_sha256, required: ["grounding_on_failure"], minScore: 80 } });

// Server-to-server: sign a request; the receiver verifies with the sender's directory.
const signed = await signRequest({ method: "POST", url, headers: {}, body }, { privateJwk, signatureAgent: "https://charge.example" });
const who = await verifyRequest(signed, { allowedAgents: ["https://charge.example"] });
```

## CLI

```bash
npx trust-kit keys ./keys                       # new Ed25519 key; private file stays local
npx trust-kit sign-network site/my_net.network.json --name my_net --origin https://site.example --key keys/site-key.private.jwk.json
npx trust-kit verify https://site.example/my_net
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
