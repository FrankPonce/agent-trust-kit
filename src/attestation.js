// Attestations: "this tester ran these tests on this exact network, on this model, and
// got these results". Issued by a tester (such as crash-test), verified by anyone, for
// example an arbiter deciding whether to admit an agent.
//
// Statement:
//   {typ, iss: tester origin, sub: network URL, network_sha256, model: {name, router},
//    test_version, results: {test_id: {verdict, pass_rate}}, score, iat, exp}
// The attestation is bound to the network hash: change the network and it no longer applies.

import { signStatement, verifyStatement } from "./statements.js";

export const ATTESTATION_TYPE = "agent-network-attestation/v1";
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Turn a crash-test scorecard into an attestation statement.
 *
 * :param scorecard: A crash-test/scorecard@1 object.
 * :param opts: {issuer: tester origin, now: ms, ttlDays: validity (default 30)}.
 * :return: The statement (not yet signed).
 */
export function attestationFromScorecard(scorecard, { issuer, now = Date.now(), ttlDays = 30 }) {
  if (!scorecard?.target?.network_sha256) throw new Error("The scorecard has no network hash.");
  const results = {};
  for (const t of scorecard.tests || []) results[t.id] = { verdict: t.verdict, pass_rate: t.pass_rate };
  return {
    typ: ATTESTATION_TYPE,
    iss: new URL(issuer).origin,
    sub: scorecard.target.network_url,
    network_sha256: scorecard.target.network_sha256,
    model: { name: scorecard.model?.name ?? null, router: scorecard.model?.routerHost ?? null },
    test_version: scorecard.tester?.test_version ?? null,
    runs_per_test: scorecard.runs_per_test ?? null,
    results,
    score: scorecard.summary?.score ?? null,
    iat: new Date(now).toISOString(),
    exp: new Date(now + ttlDays * DAY_MS).toISOString(),
  };
}

/** Sign an attestation statement. Returns the compact JWS. */
export async function signAttestation(statement, privateJwk) {
  if (statement?.typ !== ATTESTATION_TYPE) throw new Error("Not an attestation statement.");
  return signStatement(statement, privateJwk);
}

/**
 * Verify an attestation.
 *
 * :param jws: The compact JWS.
 * :param opts: {issuer: the tester origin you trust, jwks?, fetchImpl?, now: ms,
 *     expect: {network_sha256?, sub?, minScore?, required: [test ids that must pass]}}.
 * :return: {ok: true, statement} or {ok: false, reason, statement?}.
 */
export async function verifyAttestation(jws, { issuer, jwks = null, fetchImpl, now = Date.now(), expect = {} } = {}) {
  const v = await verifyStatement(jws, { issuer, jwks, fetchImpl });
  if (!v.ok) return { ok: false, reason: v.reason };
  const s = v.statement;
  const fail = (reason) => ({ ok: false, reason, statement: s });
  if (s.typ !== ATTESTATION_TYPE) return fail("not an attestation");
  if (issuer && s.iss !== new URL(issuer).origin) return fail(`issued by ${s.iss}, not ${new URL(issuer).origin}`);
  if (Date.parse(s.exp) <= now) return fail(`expired on ${s.exp}`);
  if (Date.parse(s.iat) > now + 5 * 60 * 1000) return fail("issued in the future");
  if (expect.network_sha256 && s.network_sha256 !== expect.network_sha256) return fail("attests a different version of the network");
  if (expect.sub && s.sub !== expect.sub) return fail(`attests ${s.sub}, not ${expect.sub}`);
  if (Number.isFinite(expect.minScore) && !(s.score >= expect.minScore)) return fail(`score ${s.score} is below ${expect.minScore}`);
  for (const id of expect.required || []) {
    if (s.results?.[id]?.verdict !== "pass") return fail(`required test ${id} did not pass (${s.results?.[id]?.verdict ?? "missing"})`);
  }
  return { ok: true, statement: s };
}
