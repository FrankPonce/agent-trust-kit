// DSSE v1 envelopes (Dead Simple Signing Envelope, secure-systems-lab/dsse), the envelope
// the in-toto Attestation Framework recommends. Ed25519 signatures over the PAE encoding:
//   PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
// where LEN is the byte length in ASCII decimal. The payload is signed as raw bytes, so no
// canonicalization is needed for security. keyid = the signer's JWK kid (RFC 7638 thumbprint).

import { base64 } from "./canonical.js";
import { fetchKeyDirectory, findKey, importKey } from "./keys.js";

const enc = new TextEncoder();

/** The DSSE pre-authentication encoding of a payload type and body (bytes). */
export function pae(payloadType, body) {
  const type = enc.encode(payloadType);
  const head = enc.encode(`DSSEv1 ${type.length} ${payloadType} ${body.length} `);
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

/** Decode standard or URL-safe base64 (DSSE verifiers accept both). */
export function fromBase64(text) {
  const std = String(text).replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Sign a payload into a DSSE envelope.
 *
 * :param payload: The payload bytes (Uint8Array) or a string (encoded as UTF-8).
 * :param payloadType: Such as "application/vnd.in-toto+json".
 * :param privateJwks: One Ed25519 private JWK (with kid) or a list of them.
 * :return: {payloadType, payload, signatures: [{keyid, sig}]} (base64, standard alphabet).
 */
export async function signEnvelope(payload, payloadType, privateJwks) {
  const body = typeof payload === "string" ? enc.encode(payload) : payload;
  const keys = [].concat(privateJwks);
  if (!keys.length || keys.some((k) => !k?.kid)) throw new Error("Each signing key needs a kid.");
  const message = pae(payloadType, body);
  const signatures = [];
  for (const jwk of keys) {
    const sig = await crypto.subtle.sign("Ed25519", await importKey(jwk), message);
    signatures.push({ keyid: jwk.kid, sig: base64(sig) });
  }
  return { payloadType, payload: base64(body), signatures };
}

/**
 * Verify a DSSE envelope against an issuer's published keys. Valid when at least one
 * signature verifies with a key in the issuer's key directory (or the given JWKS).
 *
 * :param envelope: The envelope object, or its JSON text.
 * :param opts: {issuer: origin whose key directory to use, jwks: optional preloaded JWKS,
 *     fetchImpl, payloadType: the expected type (optional)}.
 * :return: {ok: true, payload: Uint8Array, payloadType, keyid} or {ok: false, reason}.
 */
export async function verifyEnvelope(envelope, { issuer, jwks = null, fetchImpl, payloadType } = {}) {
  let env = envelope;
  if (typeof env === "string") {
    try {
      env = JSON.parse(env);
    } catch {
      return { ok: false, reason: "not a DSSE envelope (not JSON)" };
    }
  }
  if (!env || typeof env.payloadType !== "string" || typeof env.payload !== "string" || !Array.isArray(env.signatures) || !env.signatures.length) {
    return { ok: false, reason: "not a DSSE envelope" };
  }
  if (payloadType && env.payloadType !== payloadType) return { ok: false, reason: `payload type is ${env.payloadType}, not ${payloadType}` };
  let body;
  try {
    body = fromBase64(env.payload);
  } catch {
    return { ok: false, reason: "payload is not base64" };
  }
  let keys = jwks;
  if (!keys) {
    try {
      keys = await fetchKeyDirectory(issuer, { fetchImpl });
    } catch (error) {
      return { ok: false, reason: error.message };
    }
  }
  const message = pae(env.payloadType, body);
  let known = false;
  for (const s of env.signatures) {
    const jwk = s?.keyid ? findKey(keys, s.keyid) : null;
    if (!jwk) continue;
    known = true;
    try {
      if (await crypto.subtle.verify("Ed25519", await importKey(jwk), fromBase64(s.sig), message)) {
        return { ok: true, payload: body, payloadType: env.payloadType, keyid: s.keyid };
      }
    } catch {
      // A malformed signature is just not a valid one.
    }
  }
  return { ok: false, reason: known ? "signature does not verify" : `no signature from a key in ${issuer ?? "the given"} key directory` };
}
