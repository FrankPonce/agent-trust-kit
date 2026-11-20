// Attestations: "this tester ran these tests on this exact network, on this model, and
// got these results". Issued by a tester (such as crash-test), verified by anyone, for
// example an arbiter deciding whether to admit an agent.
//
// Format (since 18 Nov 2026): an in-toto Statement v1 with the standard Test Result
// predicate (https://in-toto.io/attestation/test-result/v0.1), signed in a DSSE envelope.
// Any in-toto tooling can read it; nothing here is a new container format.
//
//   {_type: "https://in-toto.io/Statement/v1",
//    subject: [{name: <network URL>, digest: {jcs_sha256, sha256?}}],
//    predicateType: "https://in-toto.io/attestation/test-result/v0.1",
//    predicate: {
//      result: PASSED | WARNED | FAILED, passedTests, warnedTests (flaky), failedTests,
//      configuration: [test suite, model, judges, judge prompt] as ResourceDescriptors,
//      url?: the full scorecard,
//      // Extension fields (the Test Result predicate "may be extended"):
//      issuer, issuedAt, expiresAt, score, coverage, results: {test_id: {verdict, passRate, judgedRuns?, clearedRuns?}}}}
//   judgedRuns: runs the judge panel settled; clearedRuns: of those, text-only fails that every
//   judge said were passes (crash-test v20).
//
// Subject digests: `jcs_sha256` is SHA-256 over the RFC 8785 (JCS) canonical JSON of the
// network file, lowercase hex: stable however the file is formatted. `sha256`, when given,
// is SHA-256 of the file's bytes exactly as served at test time.
// The attestation is bound to the network hash: change the network and it no longer applies.
//
// Second subject (since 18 Nov 2026, crash-test FINDINGS F39): the site's declared actions,
//   {name: <manifest URL>#actions, digest: {jcs_sha256: actionsSha256(manifest)}}
// The tools an agent can run on the page (and which may be irreversible) are declared in
// agent-manifest.json `actions`, outside the network file. Binding them means a publisher
// can't add an action through the manifest alone and keep an old attestation.
//
// Older attestations (compact JWS, typ "agent-network-attestation/v1") still verify.

import { canonicalHash } from "./canonical.js";
import { signEnvelope, verifyEnvelope } from "./dsse.js";
import { verifyStatement } from "./statements.js";

export const ACTIONS_SUBJECT_SUFFIX = "#actions";

/**
 * The digest of a site's declared actions: SHA-256 over the JCS canonical JSON of
 * agent-manifest.json `actions` ({} when the site declares none).
 */
export async function actionsSha256(manifest) {
  const a = manifest?.actions;
  return canonicalHash(a && typeof a === "object" ? a : {});
}

export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const TEST_RESULT_PREDICATE = "https://in-toto.io/attestation/test-result/v0.1";
export const INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
/** The legacy (JWS) attestation type, still accepted by verifyAttestation. */
export const ATTESTATION_TYPE = "agent-network-attestation/v1";
export const DEFAULT_TEST_SUITE_URI = "https://github.com/FrankPonce/crash-test";
const DAY_MS = 24 * 60 * 60 * 1000;

const modelDescriptor = (name, model) => ({
  name,
  // A ResourceDescriptor needs a uri, digest or content: the router the model ran on.
  uri: model?.routerHost ? `https://${model.routerHost}` : `urn:x-model:${model?.name ?? "unknown"}`,
  annotations: { model: model?.name ?? null },
});

/**
 * Turn a crash-test scorecard into an in-toto attestation statement.
 *
 * :param scorecard: A crash-test/scorecard@1 object.
 * :param opts: {issuer: tester origin, now: ms, ttlDays: validity (default 30), url: the
 *     published scorecard (optional), testSuiteUri}.
 * :return: The in-toto Statement (not yet signed).
 */
export function attestationFromScorecard(scorecard, { issuer, now = Date.now(), ttlDays = 30, url = null, testSuiteUri = DEFAULT_TEST_SUITE_URI }) {
  const target = scorecard?.target ?? {};
  if (!target.network_sha256) throw new Error("The scorecard has no network hash.");
  const tests = scorecard.tests || [];
  const ids = (v) => tests.filter((t) => t.verdict === v).map((t) => t.id);
  const results = {};
  for (const t of tests) {
    const judged = (t.runs || []).filter((r) => r.deterministic_verdict === "inconclusive").length;
    const cleared = (t.runs || []).filter((r) => r.deterministic_verdict === "fail").length;
    results[t.id] = { verdict: t.verdict, passRate: t.pass_rate, ...(judged + cleared ? { judgedRuns: judged + cleared } : {}), ...(cleared ? { clearedRuns: cleared } : {}) };
  }
  const failed = ids("fail");
  const warned = ids("flaky");
  const s = scorecard.summary ?? {};
  const configuration = [
    {
      name: "crash-test",
      uri: testSuiteUri,
      annotations: { testVersion: scorecard.tester?.test_version ?? null, scoring: s.scoring ?? null, runsPerTest: scorecard.runs_per_test ?? null },
    },
    modelDescriptor("model", scorecard.model),
    ...(scorecard.judges || []).map((j) => modelDescriptor("judge", j)),
    ...(scorecard.judge_prompt_sha256 ? [{ name: "judge-prompt", digest: { sha256: scorecard.judge_prompt_sha256 } }] : []),
  ];
  return {
    _type: STATEMENT_TYPE,
    subject: [
      { name: target.network_url, digest: { jcs_sha256: target.network_sha256, ...(target.network_file_sha256 ? { sha256: target.network_file_sha256 } : {}) } },
      ...(target.actions_sha256 && target.manifest_url
        ? [{ name: `${target.manifest_url}${ACTIONS_SUBJECT_SUFFIX}`, digest: { jcs_sha256: target.actions_sha256 } }]
        : []),
    ],
    predicateType: TEST_RESULT_PREDICATE,
    predicate: {
      result: failed.length ? "FAILED" : warned.length ? "WARNED" : "PASSED",
      configuration,
      ...(url ? { url } : {}),
      passedTests: ids("pass"),
      warnedTests: warned,
      failedTests: failed,
      issuer: new URL(issuer).origin,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlDays * DAY_MS).toISOString(),
      score: s.score ?? null,
      coverage: s.coverage ?? null,
      results,
    },
  };
}

/** Sign an attestation statement. Returns the DSSE envelope (an object; serialize as JSON). */
export async function signAttestation(statement, privateJwk) {
  if (statement?._type !== STATEMENT_TYPE || statement?.predicateType !== TEST_RESULT_PREDICATE) throw new Error("Not an in-toto test-result statement.");
  return signEnvelope(JSON.stringify(statement), INTOTO_PAYLOAD_TYPE, privateJwk);
}

/**
 * A flat summary of an attestation, the same shape for both formats, for display and policy:
 * {format, iss, sub, network_sha256, network_file_sha256, model: {name, router},
 *  test_version, scoring, runs_per_test, results: {id: {verdict, pass_rate, judged_runs?, cleared_runs?}},
 *  score, coverage, result, judges, judge_prompt_sha256, iat, exp}.
 */
export function attestationSummary(statement) {
  if (statement?._type !== STATEMENT_TYPE) {
    // Legacy JWS statement: already flat.
    return { format: "jws-legacy", network_file_sha256: null, actions_sha256: null, coverage: null, scoring: null, result: null, judges: [], judge_prompt_sha256: null, ...statement };
  }
  const p = statement.predicate ?? {};
  const subject = statement.subject?.[0] ?? {};
  const conf = (name) => (p.configuration || []).filter((c) => c?.name === name);
  const suite = conf("crash-test")[0]?.annotations ?? {};
  const model = conf("model")[0];
  const results = {};
  for (const [id, r] of Object.entries(p.results || {})) {
    results[id] = { verdict: r.verdict, pass_rate: r.passRate, ...(r.judgedRuns ? { judged_runs: r.judgedRuns } : {}), ...(r.clearedRuns ? { cleared_runs: r.clearedRuns } : {}) };
  }
  const host = (u) => (u?.startsWith("https://") ? new URL(u).host : null);
  return {
    format: "in-toto",
    iss: p.issuer ?? null,
    sub: subject.name ?? null,
    network_sha256: subject.digest?.jcs_sha256 ?? null,
    network_file_sha256: subject.digest?.sha256 ?? null,
    actions_sha256: (statement.subject || []).find((x) => x?.name?.endsWith(ACTIONS_SUBJECT_SUFFIX))?.digest?.jcs_sha256 ?? null,
    actions_subject: (statement.subject || []).find((x) => x?.name?.endsWith(ACTIONS_SUBJECT_SUFFIX))?.name ?? null,
    model: { name: model?.annotations?.model ?? null, router: host(model?.uri) },
    test_version: suite.testVersion ?? null,
    scoring: suite.scoring ?? null,
    runs_per_test: suite.runsPerTest ?? null,
    results,
    score: p.score ?? null,
    coverage: p.coverage ?? null,
    result: p.result ?? null,
    judges: conf("judge").map((j) => j.annotations?.model).filter(Boolean),
    judge_prompt_sha256: conf("judge-prompt")[0]?.digest?.sha256 ?? null,
    iat: p.issuedAt ?? null,
    exp: p.expiresAt ?? null,
  };
}

const looksLikeJws = (x) => typeof x === "string" && !x.trim().startsWith("{") && x.trim().split(".").length === 3;

/** Longest validity an attestation may claim. crash-test issues 30 days. */
export const MAX_ATTESTATION_DAYS = 90;
const VERDICTS = new Set(["pass", "fail", "flaky", "inconclusive", "not_applicable", "skipped", "error"]);
const HEX64 = /^[0-9a-f]{64}$/;
const pct = (x) => x === null || x === undefined || (typeof x === "number" && x >= 0 && x <= 100);

/** What is wrong with a summary's signed fields, or null. */
function schemaProblem(s) {
  const iat = Date.parse(s.iat);
  const exp = Date.parse(s.exp);
  if (!Number.isFinite(iat)) return `has no valid issue date (${s.iat})`;
  if (!Number.isFinite(exp)) return `has no valid expiry date (${s.exp})`;
  if (exp <= iat) return "expires before it was issued";
  if (exp - iat > MAX_ATTESTATION_DAYS * 864e5) return `claims validity for more than ${MAX_ATTESTATION_DAYS} days`;
  if (!HEX64.test(String(s.network_sha256))) return "has no valid network digest";
  if (s.actions_sha256 !== null && !HEX64.test(String(s.actions_sha256))) return "has an invalid actions digest";
  if (!pct(s.score) || !pct(s.coverage)) return "has a score or coverage outside 0-100";
  for (const [id, r] of Object.entries(s.results || {})) {
    if (!VERDICTS.has(r?.verdict)) return `has an unknown verdict for ${id}`;
  }
  return null;
}

/**
 * Verify an attestation: a DSSE envelope (object or JSON text), or a legacy compact JWS.
 *
 * :param attestation: The envelope or JWS.
 * :param opts: {issuer: the tester origin you trust, jwks?, fetchImpl?, now: ms,
 *     expect: {network_sha256?, sub?, actions_sha256?, minScore?, minCoverage?, required: [test ids that must pass]}}.
 * :return: {ok: true, statement: summary, intoto: the raw statement or null} or
 *     {ok: false, reason, statement?}. statement is attestationSummary()'s flat view.
 */
export async function verifyAttestation(attestation, { issuer, jwks = null, fetchImpl, now = Date.now(), expect = {} } = {}) {
  let raw;
  let s;
  if (looksLikeJws(attestation)) {
    const v = await verifyStatement(attestation.trim(), { issuer, jwks, fetchImpl });
    if (!v.ok) return { ok: false, reason: v.reason };
    if (v.statement.typ !== ATTESTATION_TYPE) return { ok: false, reason: "not an attestation" };
    s = attestationSummary(v.statement);
  } else {
    const v = await verifyEnvelope(attestation, { issuer, jwks, fetchImpl, payloadType: INTOTO_PAYLOAD_TYPE });
    if (!v.ok) return { ok: false, reason: v.reason };
    try {
      raw = JSON.parse(new TextDecoder().decode(v.payload));
    } catch {
      return { ok: false, reason: "payload is not JSON" };
    }
    if (raw?._type !== STATEMENT_TYPE) return { ok: false, reason: "not an in-toto Statement v1" };
    if (raw.predicateType !== TEST_RESULT_PREDICATE) return { ok: false, reason: `predicate type is ${raw.predicateType}, not test-result` };
    s = attestationSummary(raw);
  }
  const fail = (reason) => ({ ok: false, reason, statement: s });
  if (issuer && s.iss !== new URL(issuer).origin) return fail(`issued by ${s.iss}, not ${new URL(issuer).origin}`);
  // The signed content must make sense before any of it is trusted: a signature over a
  // malformed date or score is still a malformed claim (an unparseable expiry used to pass,
  // because comparisons with NaN are false).
  const problem = schemaProblem(s);
  if (problem) return fail(problem);
  const iat = Date.parse(s.iat);
  const exp = Date.parse(s.exp);
  if (exp <= now) return fail(`expired on ${s.exp}`);
  if (iat > now + 5 * 60 * 1000) return fail("issued in the future");
  if (expect.actions_subject && s.actions_subject && s.actions_subject !== expect.actions_subject) return fail(`binds the actions of ${s.actions_subject}, not ${expect.actions_subject}`);
  if (expect.network_sha256 && s.network_sha256 !== expect.network_sha256) return fail("attests a different version of the network");
  if (expect.sub && s.sub !== expect.sub) return fail(`attests ${s.sub}, not ${expect.sub}`);
  if (expect.actions_sha256) {
    if (!s.actions_sha256) return fail("does not cover the site's actions (tested before actions were bound)");
    if (s.actions_sha256 !== expect.actions_sha256) return fail("attests a different set of site actions");
  }
  if (Number.isFinite(expect.minScore) && !(s.score >= expect.minScore)) return fail(`score ${s.score} is below ${expect.minScore}`);
  if (Number.isFinite(expect.minCoverage) && !(s.coverage >= expect.minCoverage)) return fail(`coverage ${s.coverage ?? "unknown"} is below ${expect.minCoverage}`);
  for (const id of expect.required || []) {
    if (s.results?.[id]?.verdict !== "pass") return fail(`required test ${id} did not pass (${s.results?.[id]?.verdict ?? "missing"})`);
  }
  return { ok: true, statement: s, intoto: raw ?? null };
}
