// Admission: should this signed, cross-site request be let in? For an arbiter, a booking
// service or any server that other sites' agents call. No model involved.
//
// A request is admitted only if, in order:
//   1. signature    its RFC 9421 signature verifies against the keys its domain publishes
//                   (Signature-Agent names the domain);
//   2. model        it declares which model ran the caller's agent (MODEL_META in the signed
//                   body), unless the policy says requireModel: false;
//   3. network      the caller's agent network is signed by that same domain;
//   4. attestation  a tester the policy trusts vouches for exactly that network hash, the
//                   site's declared actions and the declared model, meeting the policy
//                   (score, coverage, no failed test, optional public log).
// Every refusal names the step and the reason, so the caller can fix it.
//
// Admission is not authorization: it says who is calling and how its agent was tested. What
// the request may do (whose account, how much) is the receiving service's own check.

import { verifyRequest } from "./http.js";
import { DEFAULT_TRUST_POLICY, checkNetwork } from "./peer.js";
import { MODEL_META, declaredModel } from "./model.js";

export { MODEL_META, declaredModel, declareModel } from "./model.js";

/**
 * The default admission policy: the kit's trust policy, and the caller must declare its model.
 * Trust is network × model (crash-test FINDINGS F1, F48): the same network can pass on one
 * model and fail outright on another, so only an attestation for the model that ran counts.
 * The model is the caller's own claim (signed with the body; nobody can prove which model
 * ran in a visitor's browser), which stops a site from presenting a test on a strong model
 * for a session on a weak one.
 */
export const DEFAULT_ADMIT_POLICY = Object.freeze({ ...DEFAULT_TRUST_POLICY, requireModel: true });

// Reasons from other checks may end with a full stop; ours add one, so drop doubles.
const refuse = (step, reason, extra = {}) => ({ ok: false, step, reason: String(reason).replace(/\.{2,}$/, "."), ...extra });

/**
 * Decide whether a signed cross-site request may come in.
 *
 * :param request: {method, url, headers, body} as received (body as text).
 * :param opts: {policy (default DEFAULT_ADMIT_POLICY), fetchImpl (wrap it with cachingFetch to
 *     cache the caller's public files), now, jwks (tests: the caller's key directory)}.
 * :return: {ok: true, agent, model, network_url, network_sha256, attestation: {iss, score,
 *     coverage, model, exp}} or {ok: false, step: "signature"|"model"|"network"|"attestation",
 *     reason, agent?, network_url?}.
 */
export async function admit(request, { policy = DEFAULT_ADMIT_POLICY, fetchImpl = globalThis.fetch, now = Date.now(), jwks = null } = {}) {
  const sig = await verifyRequest(request, { jwks, fetchImpl });
  if (!sig.ok) return refuse("signature", `The request is not signed by a site's published key: ${sig.reason}.`);
  const agent = sig.agent;

  const model = declaredModel(request.body);
  if (!model && policy.requireModel) {
    return refuse("model", `The request does not say which model ran ${agent}'s agent (params._meta["${MODEL_META}"]). Trust depends on the network and the model, so both are needed.`, { agent });
  }

  const r = await checkNetwork({ origin: agent }, { policy, fetchImpl, now, jwks, models: model ? [model] : null });
  const { network_url } = r;
  if (r.error) return refuse("network", `${r.error}.`, { agent, network_url });
  if (r.signature.status === "unsigned") return refuse("network", `${network_url} is not signed by its domain (no signature file).`, { agent, network_url });
  if (!r.signature.ok) return refuse("network", `${network_url} is not validly signed by ${agent}: ${r.signature.reason}.`, { agent, network_url });
  const a = r.attestation;
  if (!a.ok) {
    return refuse("attestation", `No trusted tester vouches for ${network_url} as published now${model ? ` on ${model}` : ""} (score ≥ ${policy.minScore}, coverage ≥ ${policy.minCoverage}${policy.noFailedTests !== false ? ", no failed test" : ""}): ${a.reason}.`, { agent, network_url });
  }
  return { ok: true, agent, model, network_url, network_sha256: r.network_sha256, attestation: { iss: a.iss, score: a.score, coverage: a.coverage, model: a.model, exp: a.exp } };
}
