import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  canonicalHash, canonicalJson, keyDirectory, newSiteKey, publicPart, signNetwork, verifyNetwork,
  attestationFromScorecard, signAttestation, verifyAttestation, signRequest, verifyRequest, KEY_DIRECTORY_PATH,
} from "../src/index.js";

const read = async (f) => JSON.parse(await readFile(new URL(`./vectors/${f}`, import.meta.url), "utf8"));
const { _comment, ...TEST_KEY } = await read("test-key.private.jwk.json");
const NETWORK = await read("network.json");
const EXPECTED = await read("expected.json");
const SIGNATURE = await read("vector_net.signature.json");
const JWKS = await keyDirectory([TEST_KEY]);
const ORIGIN = "https://vectors.example";

/** A fake fetch that serves one key directory per origin. */
function keyServer(byOrigin) {
  return async (url) => {
    const u = new URL(url);
    if (u.pathname !== KEY_DIRECTORY_PATH || !byOrigin[u.origin]) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(byOrigin[u.origin]), { headers: { "content-type": "application/json" } });
  };
}

// ---- canonical JSON and keys --------------------------------------------------------

test("canonical JSON ignores key order and whitespace (RFC 8785)", async () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, "x"] }), '{"a":[true,null,"x"],"b":1}');
  assert.equal(await canonicalHash({ b: 1, a: 2 }), await canonicalHash(JSON.parse('{ "a" : 2 , "b":1 }')));
  assert.notEqual(await canonicalHash({ a: 1 }), await canonicalHash({ a: 2 }));
});

test("keys: kid is the JWK thumbprint, and the directory holds no private part", async () => {
  const k = await newSiteKey();
  assert.match(k.kid, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(k.publicJwk.d, undefined);
  const dir = await keyDirectory([k.privateJwk]);
  assert.equal(dir.keys[0].d, undefined, "never publish d");
  assert.equal(dir.keys[0].kid, k.kid);
  await assert.rejects(publicPart({ kty: "RSA", n: "x" }), /Ed25519/);
});

// ---- test vectors (Ed25519 is deterministic) ------------------------------------------------

test("vector: the same key and network give the exact same signature", async () => {
  assert.equal(await canonicalHash(NETWORK), EXPECTED.network_sha256);
  const doc = await signNetwork({ network: NETWORK, name: "vector_net", origin: ORIGIN, privateJwk: TEST_KEY, issuedAt: "2026-11-17T00:00:00.000Z" });
  assert.equal(doc.jws, EXPECTED.jws);
  assert.equal(TEST_KEY.kid, EXPECTED.kid);
});

// ---- network signatures -----------------------------------------------------------------------

test("verifyNetwork: accepts the published signature with the origin's own keys", async () => {
  const r = await verifyNetwork({ doc: SIGNATURE, network: NETWORK, name: "vector_net", networkOrigin: ORIGIN, fetchImpl: keyServer({ [ORIGIN]: JWKS }) });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.statement.origin, ORIGIN);
  // Key order and whitespace in the served file don't matter.
  const reordered = JSON.parse(JSON.stringify({ tools: NETWORK.tools, metadata: NETWORK.metadata }));
  assert.equal((await verifyNetwork({ doc: SIGNATURE, network: reordered, name: "vector_net", networkOrigin: ORIGIN, jwks: JWKS })).ok, true);
});

test("verifyNetwork: refuses a changed network, another name, another origin, foreign keys", async () => {
  const changed = structuredClone(NETWORK);
  changed.tools[0].instructions = "Invent prices.";
  assert.match((await verifyNetwork({ doc: SIGNATURE, network: changed, name: "vector_net", networkOrigin: ORIGIN, jwks: JWKS })).reason, /changed after it was signed/);
  assert.match((await verifyNetwork({ doc: SIGNATURE, network: NETWORK, name: "other_net", networkOrigin: ORIGIN, jwks: JWKS })).reason, /not "other_net"/);
  // Copied to another site: keys come from that site, which does not have this key.
  const copied = await verifyNetwork({ doc: SIGNATURE, network: NETWORK, name: "vector_net", networkOrigin: "https://copycat.example", fetchImpl: keyServer({ "https://copycat.example": await keyDirectory([(await newSiteKey()).publicJwk]) }) });
  assert.equal(copied.ok, false);
  assert.match(copied.reason, /not in .* key directory/);
  // Even with the right key served by the copycat, the statement names the real origin.
  const spoof = await verifyNetwork({ doc: SIGNATURE, network: NETWORK, name: "vector_net", networkOrigin: "https://copycat.example", jwks: JWKS });
  assert.match(spoof.reason, /signed for https:\/\/vectors.example, served from https:\/\/copycat.example/);
});

test("verifyNetwork: refuses a tampered JWS, a missing directory, and plain http", async () => {
  const [h, p, s] = SIGNATURE.jws.split(".");
  const flipped = { ...SIGNATURE, jws: `${h}.${p}.${s.slice(0, -2)}${s.at(-2) === "A" ? "B" : "A"}${s.at(-1)}` };
  assert.match((await verifyNetwork({ doc: flipped, network: NETWORK, name: "vector_net", networkOrigin: ORIGIN, jwks: JWKS })).reason, /does not verify/);
  assert.match((await verifyNetwork({ doc: SIGNATURE, network: NETWORK, name: "vector_net", networkOrigin: ORIGIN, fetchImpl: keyServer({}) })).reason, /No key directory/);
  assert.match((await verifyNetwork({ doc: SIGNATURE, network: NETWORK, name: "vector_net", networkOrigin: "http://vectors.example", fetchImpl: keyServer({}) })).reason, /HTTPS/);
  assert.equal((await verifyNetwork({ doc: { typ: "x" }, network: NETWORK, name: "vector_net", networkOrigin: ORIGIN, jwks: JWKS })).ok, false);
});

// ---- attestations ----------------------------------------------------------------------------------

const TESTER = "https://crashtest.example";
const SCORECARD = {
  target: { network_url: `${ORIGIN}/vector_net`, network_sha256: EXPECTED.network_sha256 },
  model: { name: "alibaba/qwen3.8-flash", routerHost: "eu.api.otari.ai" },
  tester: { test_version: 6 },
  runs_per_test: 3,
  tests: [
    { id: "static_validity", verdict: "pass", pass_rate: 1 },
    { id: "grounding_on_failure", verdict: "pass", pass_rate: 1 },
    { id: "unknown_outcome", verdict: "flaky", pass_rate: 0.67 },
  ],
  summary: { score: 89 },
};

test("attestations: issue, verify, and bind to the exact network hash", async () => {
  const now = Date.parse("2026-11-17T12:00:00Z");
  const statement = attestationFromScorecard(SCORECARD, { issuer: TESTER, now });
  assert.equal(statement.exp, "2026-12-17T12:00:00.000Z");
  const jws = await signAttestation(statement, TEST_KEY);
  const ok = await verifyAttestation(jws, { issuer: TESTER, jwks: JWKS, now, expect: { network_sha256: EXPECTED.network_sha256, required: ["grounding_on_failure"], minScore: 80 } });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.statement.model.name, "alibaba/qwen3.8-flash");
  const v = (expect, at = now, issuer = TESTER) => verifyAttestation(jws, { issuer, jwks: JWKS, now: at, expect });
  assert.match((await v({ network_sha256: "0".repeat(64) })).reason, /different version/);
  assert.match((await v({ required: ["unknown_outcome"] })).reason, /did not pass \(flaky\)/);
  assert.match((await v({ minScore: 90 })).reason, /below 90/);
  assert.match((await v({}, Date.parse("2027-01-01T00:00:00Z"))).reason, /expired/);
  assert.match((await v({}, now, "https://other-tester.example")).reason, /issued by https:\/\/crashtest.example/);
});

// ---- RFC 9421 request signatures ---------------------------------------------------------------------

const AGENT = "https://charge.example";
const REQ = { method: "POST", url: "https://arbiter.example/requests", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kwh: 30, readyBy: "2026-11-18T07:00" }) };

test("signRequest/verifyRequest: a signed request verifies with the agent's published keys", async () => {
  const signed = await signRequest(REQ, { privateJwk: TEST_KEY, signatureAgent: AGENT });
  assert.match(signed.headers["signature-input"], /"signature-agent"/);
  assert.match(signed.headers["signature-input"], /tag="agent-trust-kit"/);
  assert.equal(signed.headers["signature-agent"], `"${AGENT}"`);
  const r = await verifyRequest(signed, { fetchImpl: keyServer({ [AGENT]: JWKS }) });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.agent, AGENT);
  assert.equal(r.kid, TEST_KEY.kid);
});

test("verifyRequest: refuses a changed body, a changed agent, an unknown key, an unlisted agent", async () => {
  const signed = await signRequest(REQ, { privateJwk: TEST_KEY, signatureAgent: AGENT });
  assert.match((await verifyRequest({ ...signed, body: REQ.body.replace("30", "60") }, { jwks: JWKS })).reason, /Content-Digest/);
  // Claim to be another site: that site's directory doesn't have the key.
  const other = { ...signed, headers: { ...signed.headers, "signature-agent": '"https://evil.example"' } };
  assert.equal((await verifyRequest(other, { fetchImpl: keyServer({ "https://evil.example": await keyDirectory([(await newSiteKey()).publicJwk]) }) })).ok, false);
  assert.equal((await verifyRequest(signed, { jwks: await keyDirectory([(await newSiteKey()).publicJwk]) })).ok, false);
  assert.match((await verifyRequest(signed, { jwks: JWKS, allowedAgents: ["https://someone-else.example"] })).reason, /not allowed/);
  assert.match((await verifyRequest({ ...REQ, headers: {} }, { jwks: JWKS })).reason, /Signature-Agent/);
});
