// The transaction layer: sealed requests, mandates and signed receipts, for any service that
// lets agents make binding requests (an arbiter, a booking desk). No model involved.
//
//   commit(fields, nonce)   a commitment to exactly what was asked: SHA-256 of the canonical
//                           JSON of the fields plus a server nonce. The requester gets it back
//                           at once, nobody can choose it (so it can break ties fairly), and
//                           the receipt repeats it.
//   mandate                 the limits the person sets themselves (a maximum price, a date),
//                           kept out of the model's reach: put them in the committed fields,
//                           and the service enforces them. The model can propose; it can't
//                           widen what the person sealed.
//   signReceipt / verifyReceipt
//                           a JWS (signStatement) by the service's published key over a
//                           statement with your own `typ`, naming only the requester's own
//                           request. Anyone can verify it with the service's key directory;
//                           a browser can with verify-lite.js.

import { canonicalHash } from "./canonical.js";
import { signStatement, verifyStatement } from "./statements.js";

/** Random 128-bit nonce as hex. */
export function newNonce() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Commitment to a sealed request. Fields that are null or undefined are left out, so adding an
 * optional field later (a mandate) doesn't change the commitments of requests without it.
 *
 * :param fields: The sealed request, plain JSON data (no key named "nonce").
 * :param nonce: The server's nonce (hex, at least 128 bits), stored with the request.
 * :return: Hex SHA-256.
 * :raises TypeError: On a short nonce or a "nonce" field.
 */
export async function commit(fields, nonce) {
  if (typeof nonce !== "string" || nonce.length < 32) throw new TypeError("A commitment needs a server nonce of at least 128 bits.");
  if (!fields || typeof fields !== "object" || "nonce" in fields) throw new TypeError("Commit an object without a field named nonce.");
  const sealed = Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined && v !== null));
  return canonicalHash({ ...sealed, nonce });
}

/**
 * Sign a receipt.
 *
 * :param statement: {typ, iss, ...}: typ names your receipt format ("charging-receipt/v1").
 * :param privateJwk: The service's receipt key (its public part in the service's key directory).
 */
export function signReceipt(statement, privateJwk) {
  if (typeof statement?.typ !== "string" || !statement.typ) throw new TypeError("A receipt needs a typ.");
  if (typeof statement.iss !== "string" || !statement.iss) throw new TypeError("A receipt needs an issuer (iss).");
  return signStatement(statement, privateJwk);
}

/**
 * Verify a receipt against its issuer's published keys.
 *
 * :param opts: {issuer (origin), typ (expected receipt format), jwks (optional), fetchImpl}.
 * :return: {ok: true, receipt, kid} or {ok: false, reason}.
 */
export async function verifyReceipt(jws, { issuer, typ = null, jwks = null, fetchImpl } = {}) {
  const r = await verifyStatement(jws, { issuer, jwks, fetchImpl });
  if (!r.ok) return r;
  if (typ && r.statement.typ !== typ) return { ok: false, reason: `not a ${typ} receipt` };
  if (issuer && r.statement.iss !== new URL(issuer).origin) return { ok: false, reason: "issued by another site" };
  return { ok: true, receipt: r.statement, kid: r.kid };
}
