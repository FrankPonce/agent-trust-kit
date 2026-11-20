// RFC 9421 HTTP Message Signatures for server-to-server requests, in the Web Bot Auth
// style: the request carries Signature-Agent (the signer's origin), and the receiver
// fetches that origin's key directory to verify. The body is bound with Content-Digest.

import { httpbis } from "http-message-signatures";
import { base64 } from "./canonical.js";
import { fetchKeyDirectory, findKey, importKey } from "./keys.js";
import { declareModel, declareNetwork } from "./model.js";

const COVERED = ["@method", "@authority", "@path", "content-digest", "content-type", "signature-agent"];
const enc = new TextEncoder();

async function contentDigest(body) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(body ?? ""));
  return `sha-256=:${base64(digest)}:`;
}

const lower = (headers) => Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), v]));

/**
 * Sign a request.
 *
 * :param request: {method, url, headers, body (string)}.
 * :param opts: {privateJwk (with kid), signatureAgent: the signer's origin, expiresIn: seconds (default 300),
 *     model: the model that ran this site's agent; added to a JSON-RPC body as params._meta
 *     (see model.js) before signing, so the signature covers it; network: the URL of the
 *     network that made the request, declared the same way}.
 * :return: A new request object whose headers include content-digest, signature-agent,
 *     signature-input and signature.
 */
export async function signRequest(request, { privateJwk, signatureAgent, expiresIn = 300, model = null, network = null }) {
  if (model) request = { ...request, body: declareModel(request.body, model) };
  if (network) request = { ...request, body: declareNetwork(request.body, network) };
  const key = await importKey(privateJwk);
  const headers = {
    ...lower(request.headers),
    "content-type": lower(request.headers)["content-type"] || "application/json",
    "content-digest": await contentDigest(request.body),
    "signature-agent": `"${new URL(signatureAgent).origin}"`,
  };
  const signer = {
    id: privateJwk.kid,
    alg: "ed25519",
    sign: async (data) => new Uint8Array(await crypto.subtle.sign("Ed25519", key, data)),
  };
  const created = new Date();
  const signed = await httpbis.signMessage(
    {
      key: signer,
      fields: COVERED,
      params: ["created", "expires", "keyid", "alg", "tag"],
      paramValues: { created, expires: new Date(created.getTime() + expiresIn * 1000), tag: "agent-trust-kit" },
    },
    { ...request, headers },
  );
  return { ...signed, headers: lower(signed.headers) };
}

/**
 * Verify a signed request.
 *
 * :param request: {method, url, headers, body}.
 * :param opts: {jwks?: a preloaded key directory, fetchImpl?, allowedAgents?: origins you accept,
 *     maxAgeSeconds (default 300): refuse older or longer-lived signatures, isReplay?: async
 *     (signature, expiresMs) => true if this signature was seen before (your one-time store),
 *     now}.
 * :return: {ok: true, agent, kid} or {ok: false, reason}.
 */
export async function verifyRequest(request, { jwks = null, fetchImpl, allowedAgents = null, maxAgeSeconds = 300, isReplay = null, now = Date.now() } = {}) {
  const headers = lower(request.headers);
  const agentHeader = String(headers["signature-agent"] || "").replace(/^"|"$/g, "");
  let agent;
  try {
    agent = new URL(agentHeader).origin;
  } catch {
    return { ok: false, reason: "missing or invalid Signature-Agent" };
  }
  // Keys only ever come from an https origin (localhost for development).
  if (!agent.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(agent)) return { ok: false, reason: `agent ${agent} is not an https origin` };
  if (allowedAgents && !allowedAgents.includes(agent)) return { ok: false, reason: `agent ${agent} is not allowed` };
  // Freshness, before any key is fetched: a signature that claims a long life, or was made
  // more than maxAgeSeconds ago, is refused even if the library would accept its expiry.
  const input = String(headers["signature-input"] || "");
  const created = Number(/;created=(\d+)/.exec(input)?.[1]);
  const expires = Number(/;expires=(\d+)/.exec(input)?.[1]);
  if (!Number.isFinite(created) || !Number.isFinite(expires)) return { ok: false, reason: "signature has no created or expires time" };
  if (expires - created > maxAgeSeconds + 30) return { ok: false, reason: `signature claims to be valid for more than ${maxAgeSeconds} seconds` };
  if (now / 1000 - created > maxAgeSeconds + 30) return { ok: false, reason: `signature is older than ${maxAgeSeconds} seconds` };
  if (headers["content-digest"] !== (await contentDigest(request.body))) return { ok: false, reason: "body does not match Content-Digest" };
  let keys = jwks;
  if (!keys) {
    try {
      keys = await fetchKeyDirectory(agent, { fetchImpl });
    } catch (error) {
      return { ok: false, reason: error.message };
    }
  }
  let usedKid = null;
  let ok = false;
  try {
    ok = await httpbis.verifyMessage({
      keyLookup: async (params) => {
        const jwk = findKey(keys, params.keyid);
        if (!jwk) return null;
        usedKid = jwk.kid;
        const key = await importKey(jwk);
        return { id: jwk.kid, algs: ["ed25519"], verify: async (data, sig) => crypto.subtle.verify("Ed25519", key, sig, data) };
      },
      requiredFields: COVERED,
      requiredParams: ["created", "expires", "keyid"],
      tolerance: 30,
    }, { ...request, headers });
  } catch (error) {
    return { ok: false, reason: `signature invalid: ${error.message}` };
  }
  if (!ok) return { ok: false, reason: "signature invalid or key unknown" };
  // One-time use, when the receiver keeps a store: each signature value is accepted once
  // within its short life. (Freshness is not idempotency: a service still needs its own
  // rule for a repeated request.)
  if (typeof isReplay === "function" && (await isReplay(String(headers.signature || ""), expires * 1000))) {
    return { ok: false, reason: "this signed request was already used" };
  }
  return { ok: true, agent, kid: usedKid };
}
