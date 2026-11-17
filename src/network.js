// Network signatures: "this origin published this exact agent network".
//
// The signature file sits next to the network file: <base>/<network>.signature.json
//   {"typ": "agent-network-signature/v1", "jws": "<compact JWS>"}
// The JWS payload is the statement:
//   {typ, network: <name>, origin, network_sha256, issued_at}
// network_sha256 is the SHA-256 of the network's canonical JSON (RFC 8785), so
// whitespace and key order don't matter, but any change to the content does.

import { canonicalHash } from "./canonical.js";
import { signStatement, verifyStatement } from "./statements.js";

export const NETWORK_SIGNATURE_TYPE = "agent-network-signature/v1";

/** Where a network's signature file is published. */
export function signatureUrl(base, name) {
  return new URL(`${encodeURIComponent(name)}.signature.json`, base).href;
}

/**
 * Sign a network.
 *
 * :param opts: {network: the parsed network JSON, name, origin: the publishing site's
 *     origin, privateJwk, issuedAt: ISO time (default now)}.
 * :return: The signature document to publish.
 */
export async function signNetwork({ network, name, origin, privateJwk, issuedAt = new Date().toISOString() }) {
  if (!name) throw new Error("name is required.");
  const statement = {
    typ: NETWORK_SIGNATURE_TYPE,
    network: name,
    origin: new URL(origin).origin,
    network_sha256: await canonicalHash(network),
    issued_at: issuedAt,
  };
  return { typ: NETWORK_SIGNATURE_TYPE, jws: await signStatement(statement, privateJwk) };
}

/**
 * Verify a published network against its signature.
 *
 * Checks, in order: the JWS verifies with a key from the *network's own origin*; the
 * statement names this network and origin; and the hash matches the network as served.
 *
 * :param opts: {doc: the signature document, network: the parsed network JSON, name,
 *     networkOrigin: the origin the network was fetched from, jwks?, fetchImpl?}.
 * :return: {ok: true, statement, kid, network_sha256} or {ok: false, reason, network_sha256}.
 */
export async function verifyNetwork({ doc, network, name, networkOrigin, jwks = null, fetchImpl }) {
  const origin = new URL(networkOrigin).origin;
  const network_sha256 = await canonicalHash(network);
  if (doc?.typ !== NETWORK_SIGNATURE_TYPE || typeof doc?.jws !== "string") {
    return { ok: false, reason: "not an agent-network-signature/v1 document", network_sha256 };
  }
  // Keys always come from the network's own origin: a signature from any other domain
  // does not say who published this network.
  const v = await verifyStatement(doc.jws, { issuer: origin, jwks, fetchImpl });
  if (!v.ok) return { ok: false, reason: v.reason, network_sha256 };
  const s = v.statement;
  if (s.typ !== NETWORK_SIGNATURE_TYPE) return { ok: false, reason: "wrong statement type", network_sha256 };
  if (s.origin !== origin) return { ok: false, reason: `signed for ${s.origin}, served from ${origin}`, network_sha256 };
  if (s.network !== name) return { ok: false, reason: `signed for network "${s.network}", not "${name}"`, network_sha256 };
  if (s.network_sha256 !== network_sha256) return { ok: false, reason: "the network changed after it was signed", network_sha256 };
  return { ok: true, statement: s, kid: v.kid, network_sha256 };
}
