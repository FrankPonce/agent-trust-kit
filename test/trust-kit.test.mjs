import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  canonicalHash, canonicalJson, keyDirectory, newSiteKey, publicPart, signNetwork, verifyNetwork,
  attestationFromScorecard, signAttestation, verifyAttestation, signRequest, verifyRequest, KEY_DIRECTORY_PATH,
  ATTESTATION_TYPE, STATEMENT_TYPE, pae, signEnvelope, verifyEnvelope, signStatement,
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

test("DSSE: PAE matches the spec's example; envelopes verify and refuse tampering", async () => {
  // From the DSSE v1 protocol description.
  assert.equal(new TextDecoder().decode(pae("http://example.com/HelloWorld", new TextEncoder().encode("hello world"))),
    "DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  const env = await signEnvelope("hello world", "http://example.com/HelloWorld", TEST_KEY);
  assert.equal(env.signatures[0].keyid, TEST_KEY.kid);
  const ok = await verifyEnvelope(JSON.stringify(env), { jwks: JWKS });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(new TextDecoder().decode(ok.payload), "hello world");
  assert.equal((await verifyEnvelope({ ...env, payload: btoa("hello there") }, { jwks: JWKS })).ok, false);
  assert.equal((await verifyEnvelope({ ...env, payloadType: "x/other" }, { jwks: JWKS })).ok, false, "the type is signed too");
  const stranger = await keyDirectory([(await newSiteKey()).publicJwk]);
  assert.match((await verifyEnvelope(env, { jwks: stranger })).reason, /no signature from a key/);
});

test("attestations are in-toto Statement v1 + Test Result predicate in a DSSE envelope", async () => {
  const now = Date.parse("2026-11-17T12:00:00Z");
  const card = { ...SCORECARD, target: { ...SCORECARD.target, network_file_sha256: "f".repeat(64) }, judges: [{ name: "deepseek/deepseek-v4.1-flash", routerHost: "eu.api.otari.ai" }], judge_prompt_sha256: "c".repeat(64), summary: { score: 89, coverage: 100, scoring: "decided/1" } };
  const st = attestationFromScorecard(card, { issuer: TESTER, now });
  assert.equal(st._type, STATEMENT_TYPE);
  assert.equal(st.predicateType, "https://in-toto.io/attestation/test-result/v0.1");
  assert.deepEqual(st.subject, [{ name: card.target.network_url, digest: { jcs_sha256: EXPECTED.network_sha256, sha256: "f".repeat(64) } }]);
  assert.equal(st.predicate.result, "WARNED"); // one flaky test, none failed
  assert.deepEqual(st.predicate.warnedTests, ["unknown_outcome"]);
  assert.deepEqual(st.predicate.failedTests, []);
  // Every configuration entry is a valid ResourceDescriptor (uri, digest or content).
  for (const c of st.predicate.configuration) assert.ok(c.uri || c.digest || c.content, JSON.stringify(c));
  const env = await signAttestation(st, TEST_KEY);
  assert.equal(env.payloadType, "application/vnd.in-toto+json");
  const ok = await verifyAttestation(env, { issuer: TESTER, jwks: JWKS, now, expect: { network_sha256: EXPECTED.network_sha256, minCoverage: 80 } });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.statement.format, "in-toto");
  assert.equal(ok.statement.model.name, "alibaba/qwen3.8-flash");
  assert.deepEqual(ok.statement.judges, ["deepseek/deepseek-v4.1-flash"]);
  assert.equal(ok.statement.coverage, 100);
  assert.deepEqual(ok.intoto, st);
  assert.match((await verifyAttestation(env, { issuer: TESTER, jwks: JWKS, now, expect: { minCoverage: 101 } })).reason, /coverage 100 is below 101/);
});

test("legacy JWS attestations still verify, with the same summary shape", async () => {
  const now = Date.parse("2026-11-17T12:00:00Z");
  const legacy = { typ: ATTESTATION_TYPE, iss: TESTER, sub: SCORECARD.target.network_url, network_sha256: EXPECTED.network_sha256, model: { name: "m", router: "r" }, results: { static_validity: { verdict: "pass", pass_rate: 1 } }, score: 90, iat: new Date(now).toISOString(), exp: new Date(now + 864e5).toISOString() };
  const jws = await signStatement(legacy, TEST_KEY);
  const ok = await verifyAttestation(jws, { issuer: TESTER, jwks: JWKS, now, expect: { network_sha256: EXPECTED.network_sha256 } });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.statement.format, "jws-legacy");
  assert.equal(ok.statement.score, 90);
  assert.equal(ok.intoto, null);
});

test("attestations: issue, verify, and bind to the exact network hash", async () => {
  const now = Date.parse("2026-11-17T12:00:00Z");
  const statement = attestationFromScorecard(SCORECARD, { issuer: TESTER, now });
  assert.equal(statement.predicate.expiresAt, "2026-12-17T12:00:00.000Z");
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

test("key directories: fetched without following redirects, in a way Workers accept", async () => {
  const { fetchKeyDirectory } = await import("../src/keys.js");
  const seen = [];
  const ok = async (url, init) => { seen.push(init?.redirect); return new Response(JSON.stringify(JWKS)); };
  assert.deepEqual(await fetchKeyDirectory(ORIGIN, { fetchImpl: ok }), JWKS);
  assert.deepEqual(seen, ["manual"], "Cloudflare Workers reject redirect: error");
  const moved = async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/keys" } });
  await assert.rejects(fetchKeyDirectory(ORIGIN, { fetchImpl: moved }), /redirects/);
  // What a browser returns for a redirect fetched with redirect: "manual".
  const opaque = async () => ({ type: "opaqueredirect", status: 0, ok: false });
  await assert.rejects(fetchKeyDirectory(ORIGIN, { fetchImpl: opaque }), /redirects/);
});

test("fetchSignature: a 404 or an HTML page means unsigned; other non-JSON is invalid", async () => {
  const { fetchSignature } = await import("../src/index.js");
  const serve = (body, init) => async () => new Response(body, init);
  const url = `${ORIGIN}/vector_net.signature.json`;
  const found = await fetchSignature(url, { fetchImpl: serve(JSON.stringify(SIGNATURE), { headers: { "content-type": "application/json" } }) });
  assert.equal(found.status, "found");
  assert.deepEqual(found.doc, SIGNATURE);
  assert.equal((await fetchSignature(url, { fetchImpl: serve("not found", { status: 404 }) })).status, "missing");
  // Cloudflare Pages answers a missing file with its home page and status 200 (F35).
  assert.equal((await fetchSignature(url, { fetchImpl: serve("<!doctype html><html></html>", { headers: { "content-type": "text/html" } }) })).status, "missing");
  assert.equal((await fetchSignature(url, { fetchImpl: serve("  <html>", { headers: { "content-type": "application/octet-stream" } }) })).status, "missing");
  assert.equal((await fetchSignature(url, { fetchImpl: serve("oops", { headers: { "content-type": "text/plain" } }) })).status, "invalid");
  assert.equal((await fetchSignature(url, { fetchImpl: serve("err", { status: 500 }) })).status, "invalid");
});

test("attestations count judged runs and, separately, text-only fails the judges cleared", async () => {
  const card = {
    target: { network_url: "https://s.example/n", network_sha256: "b".repeat(64) }, model: { name: "m" },
    tests: [{ id: "false_confirmation", verdict: "pass", pass_rate: 1, runs: [
      { verdict: "pass" }, { verdict: "pass", deterministic_verdict: "inconclusive" }, { verdict: "pass", deterministic_verdict: "fail", basis: "text" },
    ] }],
    summary: { score: 100, coverage: 100 },
  };
  const s = attestationFromScorecard(card, { issuer: "https://t.example", now: 0 });
  assert.deepEqual(s.predicate.results.false_confirmation, { verdict: "pass", passRate: 1, judgedRuns: 2, clearedRuns: 1 });
  const { attestationSummary } = await import("../src/index.js");
  assert.deepEqual(attestationSummary(s).results.false_confirmation, { verdict: "pass", pass_rate: 1, judged_runs: 2, cleared_runs: 1 });
});
