// Makes test/vectors/rekor-staging.json: a real Rekor STAGING entry for a throwaway key and a
// test statement, so the kit's log-entry verification is tested offline against real data.
// Run (writes to Sigstore's public staging log): node test/vectors/make-rekor-fixture.mjs
import { writeFileSync } from "node:fs";
import { newSiteKey } from "../../src/keys.js";
import { signEnvelope } from "../../src/dsse.js";
import { REKOR, logEnvelope, verifyLogEntry } from "../../src/rekor.js";

const key = await newSiteKey();
const statement = { _type: "https://in-toto.io/Statement/v1", subject: [{ name: "https://example.invalid/agent-trust-kit-test", digest: { sha256: "0".repeat(64) } }], predicateType: "https://agent-trust-kit.invalid/test/v1", predicate: { note: "agent-trust-kit test vector for Rekor staging", at: new Date().toISOString() } };
const envelope = await signEnvelope(JSON.stringify(statement), "application/vnd.in-toto+json", key.privateJwk);
const entry = await logEnvelope(envelope, key.publicJwk, { rekorUrl: REKOR.staging });
const check = await verifyLogEntry(envelope, entry, { signerJwk: key.publicJwk });
console.log(check);
writeFileSync(new URL("rekor-staging.json", import.meta.url), JSON.stringify({ publicJwk: key.publicJwk, envelope, entry }, null, 2) + "\n");
