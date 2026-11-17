// Signed statements: compact JWS (RFC 7515, EdDSA) over the canonical JSON of a small
// statement. Used for network signatures and test attestations.

import { CompactSign, compactVerify, decodeProtectedHeader } from "jose";
import { canonicalJson } from "./canonical.js";
import { fetchKeyDirectory, findKey, importKey } from "./keys.js";

/**
 * Sign a statement.
 *
 * :param statement: A JSON object with a "typ" field.
 * :param privateJwk: The signer's Ed25519 private JWK (with kid).
 * :return: The compact JWS string.
 */
export async function signStatement(statement, privateJwk) {
  if (!statement?.typ) throw new Error("A statement needs a typ.");
  if (!privateJwk?.kid) throw new Error("The signing key needs a kid.");
  const payload = new TextEncoder().encode(canonicalJson(statement));
  return new CompactSign(payload)
    .setProtectedHeader({ alg: "EdDSA", kid: privateJwk.kid, typ: "JOSE", cty: statement.typ })
    .sign(await importKey(privateJwk));
}

/**
 * Verify a statement against the issuer's published keys.
 *
 * :param jws: The compact JWS.
 * :param opts: {issuer: origin whose key directory to use, jwks: optional preloaded JWKS,
 *     fetchImpl}.
 * :return: {ok: true, statement, kid} or {ok: false, reason}.
 */
export async function verifyStatement(jws, { issuer, jwks = null, fetchImpl } = {}) {
  let header;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    return { ok: false, reason: "not a compact JWS" };
  }
  if (header.alg !== "EdDSA" || !header.kid) return { ok: false, reason: "unsupported algorithm or missing kid" };
  let keys = jwks;
  if (!keys) {
    try {
      keys = await fetchKeyDirectory(issuer, { fetchImpl });
    } catch (error) {
      return { ok: false, reason: error.message };
    }
  }
  const jwk = findKey(keys, header.kid);
  if (!jwk) return { ok: false, reason: `key ${header.kid} is not in ${issuer ?? "the given"} key directory` };
  let payload;
  try {
    ({ payload } = await compactVerify(jws, await importKey(jwk)));
  } catch {
    return { ok: false, reason: "signature does not verify" };
  }
  let statement;
  try {
    statement = JSON.parse(new TextDecoder().decode(payload));
  } catch {
    return { ok: false, reason: "payload is not JSON" };
  }
  if (header.cty && statement.typ !== header.cty) return { ok: false, reason: "header and payload types differ" };
  return { ok: true, statement, kid: header.kid };
}
