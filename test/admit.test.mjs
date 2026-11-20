// admit(): who may call a service from another site. A fake web with a caller site (keys,
// manifest, signed network, signing server) and a tester (keys, index, in-toto attestations);
// every refusal names the step that failed. (Moved from taloyhtio-charging's arbiter, 20 Nov.)
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  KEY_DIRECTORY_PATH, attestationFromScorecard, canonicalHash, keyDirectory, newSiteKey, sha256Hex,
  signAttestation, signNetwork, signRequest, signStatement, ATTESTATION_TYPE, actionsSha256,
} from "../src/index.js";
import { MODEL_META, admit } from "../src/admit.js";

const ARBITER = "https://taloyhtio.example";
const CALLER = "https://charge.example";
const TESTER = "https://tester.example";
const POLICY = { testers: [{ origin: TESTER, index: "/attestations/index.json" }], minScore: 80, minCoverage: 80, requireModel: true };
const MODEL = "alibaba/qwen3.8-flash"; // the model the fixture attestation covers
const NOW = Date.parse("2026-12-22T10:00:00Z");
const NETWORK = { tools: [{ name: "charge_assistant", instructions: "Plan charging from real prices.", tools: [] }] };
const ACTIONS = { version: 1, agentTools: ["plan_charging", "send_night_request"] };


/** Build a fake web; options change one thing to make a step fail. */
async function world({ signNet = true, servedNetwork = NETWORK, score = 100, coverage = 100, legacy = false, expired = false, failedTest = false, servedActions = ACTIONS } = {}) {
  const caller = await newSiteKey();
  const tester = await newSiteKey();
  const files = new Map();
  const put = (url, body) => files.set(url, typeof body === "string" ? body : JSON.stringify(body));
  put(`${CALLER}${KEY_DIRECTORY_PATH}`, await keyDirectory([caller.publicJwk]));
  put(`${TESTER}${KEY_DIRECTORY_PATH}`, await keyDirectory([tester.publicJwk]));
  put(`${CALLER}/agent-manifest.json`, { networks: [{ name: "charge_planner", front_man: "charge_assistant", hocon: "./charge_planner.network.json" }], actions: servedActions });
  put(`${CALLER}/charge_planner.network.json`, servedNetwork);
  if (signNet) put(`${CALLER}/charge_planner.signature.json`, await signNetwork({ network: servedNetwork, name: "charge_planner", origin: CALLER, privateJwk: caller.privateJwk }));

  // The tester attested the network as it was (NETWORK), not necessarily as served now.
  const sha = await canonicalHash(NETWORK);
  const sub = `${CALLER}/charge_planner`;
  const iat = expired ? NOW - 40 * 864e5 : NOW - 864e5;
  let file;
  if (legacy) {
    file = await signStatement({ typ: ATTESTATION_TYPE, iss: TESTER, sub, network_sha256: sha, model: { name: "alibaba/qwen3.8-flash" }, results: {}, score, iat: new Date(iat).toISOString(), exp: new Date(iat + 30 * 864e5).toISOString() }, tester.privateJwk);
  } else {
    const card = { target: { network_url: sub, network_sha256: sha, manifest_url: `${CALLER}/agent-manifest.json`, actions_sha256: await actionsSha256({ actions: ACTIONS }) }, model: { name: "alibaba/qwen3.8-flash", routerHost: "eu.api.otari.ai" }, tester: { test_version: 15 }, runs_per_test: 3, tests: [{ id: "static_validity", verdict: "pass", pass_rate: 1 }, ...(failedTest ? [{ id: "grounding_on_failure", verdict: "fail", pass_rate: 0 }] : [])], summary: { score, coverage, scoring: "decided/1" } };
    file = JSON.stringify(await signAttestation(attestationFromScorecard(card, { issuer: TESTER, now: iat }), tester.privateJwk));
  }
  put(`${TESTER}/attestations/x.att`, file);
  put(`${TESTER}/attestations/index.json`, { attestations: [{ sub, model: "alibaba/qwen3.8-flash", attestation: "attestations/x.att" }] });

  const fetchImpl = async (url) => (files.has(String(url))
    ? new Response(files.get(String(url)), { headers: { "content-type": "application/json" } })
    : new Response("not found", { status: 404 }));
  const signed = async (body, key = caller.privateJwk) => {
    const s = await signRequest({ method: "POST", url: `${ARBITER}/mcp`, headers: { "content-type": "application/json" }, body }, { privateJwk: key, signatureAgent: CALLER });
    return new Request(s.url, { method: "POST", headers: s.headers, body: s.body });
  };
  return { fetchImpl, signed, caller };
}

const asPlain = async (req) => ({ method: req.method, url: req.url, headers: Object.fromEntries(req.headers), body: await req.clone().text() });
const BODY = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: { _meta: { [MODEL_META]: MODEL } } });

test("admitted: signed request, domain-signed network, fresh attestation for that exact hash", async () => {
  const w = await world();
  const d = await admit(await asPlain(await w.signed(BODY)), { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(d.ok, true, d.reason);
  assert.equal(d.agent, CALLER);
  assert.equal(d.network_url, `${CALLER}/charge_planner`);
  assert.equal(d.network_sha256, await canonicalHash(NETWORK));
  assert.deepEqual([d.attestation.iss, d.attestation.score, d.attestation.coverage], [TESTER, 100, 100]);
});

test("refused at each step, with the reason", async () => {
  const step = async (w, req) => {
    const d = await admit(await asPlain(req ?? (await w.signed(BODY))), { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
    assert.equal(d.ok, false);
    return d;
  };
  // Signature: a key the caller doesn't publish; a body changed after signing.
  let w = await world();
  assert.equal((await step(w, await w.signed(BODY, (await newSiteKey()).privateJwk))).step, "signature");
  const good = await asPlain(await w.signed(BODY));
  const tampered = await admit({ ...good, body: BODY.replace("ping", "pong") }, { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(tampered.step, "signature");
  // Network: not signed by its domain (like Spot Deals).
  const unsigned = await step(await world({ signNet: false }));
  assert.equal(unsigned.step, "network");
  assert.match(unsigned.reason, /not signed by its domain/);
  // Attestation: the network changed since it was tested; score too low; expired; old format without coverage.
  const changed = await step(await world({ servedNetwork: { ...NETWORK, extra: "new instructions" } }));
  assert.equal(changed.step, "attestation");
  assert.match(changed.reason, /different version of the network/);
  assert.match((await step(await world({ score: 71 }))).reason, /score 71 is below 80/);
  assert.match((await step(await world({ coverage: 60 }))).reason, /coverage 60 is below 80/);
  assert.match((await step(await world({ expired: true }))).reason, /expired/);
  assert.match((await step(await world({ legacy: true }))).reason, /does not cover the site's actions/);
  // F39: a new action declared in the manifest alone (network and signature unchanged).
  const newAction = await step(await world({ servedActions: { ...ACTIONS, agentTools: [...ACTIONS.agentTools, "pay_now"] } }));
  assert.equal(newAction.step, "attestation");
  assert.match(newAction.reason, /different set of site actions/);
  // A high average does not hide a test that failed outright (F45: Spot Deals averaged 81).
  const hidden = await step(await world({ score: 81, failedTest: true }));
  assert.equal(hidden.step, "attestation");
  assert.match(hidden.reason, /failed outright: grounding_on_failure \(score 81\)/);
});

test("refusal reasons end with exactly one full stop", async () => {
  const w = await world({ signNet: false });
  const d = await admit(await asPlain(await w.signed(BODY)), { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.match(d.reason, /[^.]\.$/);
  const sig = await admit({ method: "POST", url: `${ARBITER}/mcp`, headers: { "signature-agent": '"https://nokeys.example"' }, body: BODY }, { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.match(sig.reason, /[^.]\.$/);
});

test("network × model: the caller must say which model ran its agent, and only that model's attestation counts", async () => {
  const w = await world();
  const noModel = await admit(await asPlain(await w.signed(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }))), { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(noModel.ok, false);
  assert.equal(noModel.step, "model");
  assert.match(noModel.reason, /does not say which model ran https:\/\/charge\.example's agent/);
  const other = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: { _meta: { [MODEL_META]: "mistralai/ministral-3-8b" } } });
  const weak = await admit(await asPlain(await w.signed(other)), { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(weak.ok, false);
  assert.equal(weak.step, "attestation");
  assert.match(weak.reason, /as published now on mistralai\/ministral-3-8b .*not tested on mistralai\/ministral-3-8b \(tested on alibaba\/qwen3\.8-flash\)/);
  const ok = await admit(await asPlain(await w.signed(BODY)), { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.model, MODEL);
  assert.equal(ok.attestation.model, MODEL);

  // The model is inside the signed body: changing it after signing breaks the signature.
  const signed = await asPlain(await w.signed(BODY));
  const swapped = await admit({ ...signed, body: BODY.replace(MODEL, "openai/gpt-oss-20b") }, { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(swapped.step, "signature");
});

test("signRequest({ model }) declares the model inside the signed body, and admit() reads it", async () => {
  const { declareModel, declaredModel, verifyRequest } = await import("../src/index.js");
  const w = await world();
  const plain = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_rules", arguments: {} } });
  const s = await signRequest({ method: "POST", url: `${ARBITER}/mcp`, headers: { "content-type": "application/json" }, body: plain }, { privateJwk: w.caller.privateJwk, signatureAgent: CALLER, model: MODEL });
  assert.equal(declaredModel(s.body), MODEL);
  assert.equal(JSON.parse(s.body).params.arguments.constructor, Object, "the call itself is unchanged");
  assert.equal((await verifyRequest(s, { fetchImpl: w.fetchImpl })).ok, true);
  const d = await admit(s, { policy: POLICY, fetchImpl: w.fetchImpl, now: NOW });
  assert.equal(d.ok, true, d.reason);
  assert.equal(d.model, MODEL);
  // Existing _meta is kept; no model leaves the body as it was.
  assert.deepEqual(JSON.parse(declareModel(JSON.stringify({ params: { _meta: { a: 1 } } }), "m")).params._meta, { a: 1, [MODEL_META]: "m" });
  assert.equal(declareModel(plain, ""), plain);
});
