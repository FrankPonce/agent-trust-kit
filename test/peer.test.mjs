// Peer trust: checkNetwork (signature + attestation, one check for arbiters and consent
// cards), peerTrustReport (what a site serves at /.well-known/peer-trust.json) and the
// browser card's wording. A fake web: a site, two partners, an MCP server and a tester.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  KEY_DIRECTORY_PATH, attestationFromScorecard, canonicalHash, keyDirectory, newSiteKey,
  signAttestation, signNetwork, checkNetwork, peerTrustReport, peerTrustResponse, clearPeerTrustCache,
  cachingFetch, isMcpRef, PEER_TRUST_TYPE, actionsSha256, verifyAttestation,
} from "../src/index.js";
import { describePeer, withPeerTrust } from "../src/peer-card.js";

const SITE = "https://charge.example";
const GOOD = "https://housing.example";
const BAD = "https://deals.example";
const TESTER = "https://tester.example";
const POLICY = { testers: [{ origin: TESTER, index: "/attestations/index.json" }], minScore: 80, minCoverage: 80, noFailedTests: true };
const NOW = Date.parse("2026-12-22T10:00:00Z");
const net = (name) => ({ tools: [{ name, instructions: `I am ${name}.`, tools: [] }] });
const SITE_NETWORK = {
  link_labels: { [`${GOOD}/housing`]: "Housing company" },
  tools: [{ name: "front", instructions: "x", tools: [`${GOOD}/housing`, `${BAD}/deals`, "https://tools.example/mcp", `${SITE}/other_own`, "local_helper"] }],
};

beforeEach(() => clearPeerTrustCache());

const GOOD_ACTIONS = { version: 1, agentTools: ["get_rules"] };

async function web({ goodScore = 100, goodLeak = "pass", servedGood = net("housing"), servedActions = GOOD_ACTIONS, bindActions = true } = {}) {
  const tester = await newSiteKey();
  const good = await newSiteKey();
  const files = new Map();
  const put = (url, body, type = "application/json") => files.set(url, { body: typeof body === "string" ? body : JSON.stringify(body), type });
  put(`${TESTER}${KEY_DIRECTORY_PATH}`, await keyDirectory([tester.publicJwk]));
  put(`${GOOD}${KEY_DIRECTORY_PATH}`, await keyDirectory([good.publicJwk]));
  put(`${SITE}/agent-manifest.json`, { networks: [{ name: "charge_planner", hocon: "./charge_planner.network.json" }] });
  put(`${SITE}/charge_planner.network.json`, SITE_NETWORK);
  put(`${GOOD}/agent-manifest.json`, { networks: [{ name: "housing", hocon: "./housing.network.json" }], actions: servedActions });
  put(`${GOOD}/housing.network.json`, servedGood);
  put(`${GOOD}/housing.signature.json`, await signNetwork({ network: net("housing"), name: "housing", origin: GOOD, privateJwk: good.privateJwk }));
  put(`${BAD}/agent-manifest.json`, { networks: [{ name: "deals", hocon: "./deals.network.json" }] });
  put(`${BAD}/deals.network.json`, net("deals"));
  // A single-page host: a missing signature file comes back as its HTML home page.
  put(`${BAD}/deals.signature.json`, "<!doctype html><title>Deals</title>", "text/html");

  // The tester saw each site's manifest as first published (GOOD_ACTIONS for the good one).
  const actions = { [`${GOOD}/housing`]: { actions: GOOD_ACTIONS }, [`${BAD}/deals`]: {} };
  const attest = async (sub, network, tests, score) => JSON.stringify(await signAttestation(attestationFromScorecard({
    target: {
      network_url: sub, network_sha256: await canonicalHash(network),
      ...(bindActions ? { manifest_url: new URL("agent-manifest.json", sub).href, actions_sha256: await actionsSha256(actions[sub]) } : {}),
    },
    model: { name: "alibaba/qwen3.8-flash", routerHost: "eu.api.otari.ai" }, tester: { test_version: 18 }, runs_per_test: 3,
    tests, summary: { score, coverage: 100, scoring: "decided/1" },
  }, { issuer: TESTER, now: NOW - 864e5 }), tester.privateJwk));
  put(`${TESTER}/a/good.att`, await attest(`${GOOD}/housing`, net("housing"), [{ id: "private_context_leak", verdict: goodLeak, pass_rate: goodLeak === "pass" ? 1 : 0 }], goodScore));
  put(`${TESTER}/a/bad.att`, await attest(`${BAD}/deals`, net("deals"), [{ id: "grounding_on_failure", verdict: "fail", pass_rate: 0 }], 81));
  put(`${TESTER}/attestations/index.json`, { attestations: [{ sub: `${GOOD}/housing`, attestation: "a/good.att" }, { sub: `${BAD}/deals`, attestation: "a/bad.att" }] });

  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    const f = files.get(String(url));
    return f ? new Response(f.body, { headers: { "content-type": f.type } }) : new Response("not found", { status: 404 });
  };
  return { fetchImpl, calls };
}

test("checkNetwork: a signed, attested partner is trusted, with the facts to show", async () => {
  const { fetchImpl } = await web();
  const r = await checkNetwork(`${GOOD}/housing`, { policy: POLICY, fetchImpl, now: NOW });
  assert.equal(r.trusted, true, JSON.stringify(r));
  assert.equal(r.signature.status, "valid");
  assert.equal(r.signature.by, GOOD);
  assert.equal(r.attestation.score, 100);
  assert.equal(r.attestation.model, "alibaba/qwen3.8-flash");
  assert.equal(r.attestation.results.private_context_leak, "pass");
  // {origin} picks the manifest's first network, as the arbiter does for a caller.
  assert.equal((await checkNetwork({ origin: GOOD }, { policy: POLICY, fetchImpl, now: NOW })).network_url, `${GOOD}/housing`);
});

test("checkNetwork: an HTML 'signature' is unsigned, and an 81 with a failed test is shown but not vouched for", async () => {
  const { fetchImpl } = await web();
  const r = await checkNetwork(`${BAD}/deals`, { policy: POLICY, fetchImpl, now: NOW });
  assert.equal(r.trusted, false);
  assert.equal(r.signature.status, "unsigned");
  assert.match(r.signature.reason, /HTML/);
  assert.equal(r.attestation.ok, false);
  assert.equal(r.attestation.score, 81);
  assert.match(r.attestation.reason, /failed outright: grounding_on_failure \(score 81\)/);
  // A policy may turn the failed-test rule off; the signature still decides.
  const lenient = await checkNetwork(`${BAD}/deals`, { policy: { ...POLICY, noFailedTests: false }, fetchImpl, now: NOW });
  assert.equal(lenient.attestation.ok, true);
  assert.equal(lenient.trusted, false);
});

test("checkNetwork: a changed network loses both its signature and its attestation", async () => {
  const { fetchImpl } = await web({ servedGood: net("housing, now changed") });
  const r = await checkNetwork(`${GOOD}/housing`, { policy: POLICY, fetchImpl, now: NOW });
  assert.equal(r.trusted, false);
  assert.match(r.signature.reason, /changed after it was signed/);
  assert.match(r.attestation.reason, /different version of the network/);
  const low = await checkNetwork(`${GOOD}/housing`, { policy: POLICY, fetchImpl: (await web({ goodScore: 71 })).fetchImpl, now: NOW });
  assert.match(low.attestation.reason, /score 71 is below 80/);
  const gone = await checkNetwork("https://nowhere.example/x", { policy: POLICY, fetchImpl, now: NOW });
  assert.match(gone.error, /Could not load/);
});

test("peerTrustReport: lists other origins' networks and MCP servers, not the site's own tools", async () => {
  const { fetchImpl } = await web();
  const report = await peerTrustReport(`${SITE}/charge_planner`, { policy: POLICY, fetchImpl, now: NOW });
  assert.equal(report.typ, PEER_TRUST_TYPE);
  assert.deepEqual(report.peers.map((p) => [p.host, p.kind, p.trusted]), [
    ["housing.example", "network", true], ["deals.example", "network", false], ["tools.example", "mcp", false],
  ]);
  assert.equal(report.peers[0].label, "Housing company");
  assert.deepEqual(report.policy, { testers: [TESTER], minScore: 80, minCoverage: 80, noFailedTests: true, bindActions: true });
  assert.equal(isMcpRef("https://a.example/mcp"), true);
  assert.equal(isMcpRef("https://a.example/agent"), false);
});

test("peerTrustResponse and cachingFetch: one check per period, served as JSON", async () => {
  const { fetchImpl, calls } = await web();
  const opts = { policy: POLICY, fetchImpl, now: NOW, network: SITE_NETWORK };
  const first = await peerTrustResponse(`${SITE}/charge_planner`, opts);
  assert.match(first.headers.get("content-type"), /application\/json/);
  assert.match(first.headers.get("cache-control"), /max-age=300/);
  const n = calls.length;
  assert.equal((await (await peerTrustResponse(`${SITE}/charge_planner`, { ...opts, now: NOW + 60_000 })).json()).peers.length, 3);
  assert.equal(calls.length, n, "served from memory within the period");
  await peerTrustResponse(`${SITE}/charge_planner`, { ...opts, now: NOW + 6 * 60_000 });
  assert.ok(calls.length > n, "checked again after the period");

  let t = 0;
  const cf = cachingFetch(fetchImpl, { now: () => t });
  const before = calls.length;
  await (await cf(`${GOOD}/agent-manifest.json`)).json();
  assert.deepEqual(await (await cf(`${GOOD}/agent-manifest.json`)).json(), { networks: [{ name: "housing", hocon: "./housing.network.json" }], actions: GOOD_ACTIONS });
  assert.equal(calls.length, before + 1);
  t = 6 * 60_000;
  await cf(`${GOOD}/agent-manifest.json`);
  assert.equal(calls.length, before + 2);
});

test("card wording: plain facts, warnings for anything not proven", async () => {
  const { fetchImpl } = await web();
  const report = await peerTrustReport(`${SITE}/charge_planner`, { policy: POLICY, fetchImpl, now: NOW });
  const [good, bad, mcp] = report.peers.map(describePeer);
  assert.equal(good.level, "ok");
  assert.equal(good.text, "✓ Signed by housing.example · ✓ tested 100/100 (coverage 100%) on qwen3.8-flash by tester.example; kept private details private");
  assert.equal(bad.level, "warn");
  assert.equal(bad.text, "⚠ Not signed by its domain · ⚠ tested 81/100 but not vouched for");
  assert.match(bad.detail, /failed outright/);
  assert.match(mcp.text, /tool service/);
  assert.match(describePeer(null).text, /has not checked this partner/);
  const leaky = (await peerTrustReport(`${SITE}/charge_planner`, { policy: POLICY, fetchImpl: (await web({ goodLeak: "fail" })).fetchImpl, now: NOW })).peers[0];
  assert.match(describePeer(leaky).text, /leaked private details in tests/);
});

test("withPeerTrust: the card shows at once; block mode declines untrusted partners without asking", async () => {
  const report = { typ: PEER_TRUST_TYPE, peers: [{ host: "housing.example", kind: "network", trusted: true, signature: { ok: true, by: GOOD }, attestation: { ok: true, score: 100, coverage: 100, model: "m", iss: TESTER, results: {} } }] };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(url, "/.well-known/peer-trust.json", "only this site's own origin is fetched");
    return new Response(JSON.stringify(report));
  };
  try {
    const shown = [];
    const card = async (info) => {
      shown.push(info.peerOrigin);
      return "allow";
    };
    assert.equal(await withPeerTrust(card, { doc: null })({ peerOrigin: "housing.example" }), "allow");
    const blocking = withPeerTrust(card, { block: true, doc: null });
    assert.equal(await blocking({ peerOrigin: "deals.example", peerLabel: "Deals" }), "decline");
    assert.equal(await blocking({ peerOrigin: "housing.example" }), "allow");
    assert.deepEqual(shown, ["housing.example", "housing.example"], "no card for the declined partner");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("actions binding: a new action in the manifest alone takes the attestation away (F39)", async () => {
  // Same network, same signature; only the manifest gained an irreversible action.
  const { fetchImpl } = await web({ servedActions: { version: 1, agentTools: ["get_rules", "pay_now"] } });
  const r = await checkNetwork(`${GOOD}/housing`, { policy: POLICY, fetchImpl, now: NOW });
  assert.equal(r.signature.ok, true, "the network signature can't see it");
  assert.equal(r.trusted, false);
  assert.match(r.attestation.reason, /different set of site actions/);
  assert.match(describePeer({ kind: "network", ...r }).text, /changed since it was tested/);
  // Key order in the manifest doesn't matter (JCS).
  const reordered = await web({ servedActions: { agentTools: ["get_rules"], version: 1 } });
  assert.equal((await checkNetwork(`${GOOD}/housing`, { policy: POLICY, fetchImpl: reordered.fetchImpl, now: NOW })).trusted, true);
});

test("actions binding: attestations from before it are refused unless a policy allows them", async () => {
  const { fetchImpl } = await web({ bindActions: false });
  const r = await checkNetwork(`${GOOD}/housing`, { policy: POLICY, fetchImpl, now: NOW });
  assert.match(r.attestation.reason, /does not cover the site's actions/);
  assert.equal((await checkNetwork(`${GOOD}/housing`, { policy: { ...POLICY, bindActions: false }, fetchImpl, now: NOW })).trusted, true);
});

test("actions subject: in the statement, in the summary, and checked by verifyAttestation", async () => {
  const sub = "https://s.example/net";
  const tester = await newSiteKey();
  const manifest = { actions: { version: 1, agentTools: ["a"] } };
  const statement = attestationFromScorecard({
    target: { network_url: sub, network_sha256: "a".repeat(64), manifest_url: "https://s.example/agent-manifest.json", actions_sha256: await actionsSha256(manifest) },
    model: { name: "m" }, tests: [], summary: { score: 100, coverage: 100 },
  }, { issuer: TESTER, now: NOW });
  assert.deepEqual(statement.subject[1], { name: "https://s.example/agent-manifest.json#actions", digest: { jcs_sha256: await actionsSha256(manifest) } });
  assert.equal(await actionsSha256({}), await actionsSha256({ actions: {} }), "no actions = {}");
  const env = await signAttestation(statement, tester.privateJwk);
  const jwks = await keyDirectory([tester.publicJwk]);
  const ok = await verifyAttestation(env, { issuer: TESTER, jwks, now: NOW, expect: { actions_sha256: await actionsSha256(manifest) } });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.statement.actions_sha256, await actionsSha256(manifest));
  const other = await verifyAttestation(env, { issuer: TESTER, jwks, now: NOW, expect: { actions_sha256: await actionsSha256({ actions: { agentTools: ["a", "b"] } }) } });
  assert.match(other.reason, /different set of site actions/);
});
