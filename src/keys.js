// Ed25519 site keys and the public key directory.
//
// A site publishes its public keys as a JWKS at the Web Bot Auth location, so one key
// file serves network signatures, attestations and RFC 9421 request signatures:
//   https://<origin>/.well-known/http-message-signatures-directory
// Key IDs are RFC 7638 JWK thumbprints, as in Web Bot Auth.

import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK } from "jose";

export const KEY_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const KEY_DIRECTORY_TYPE = "application/http-message-signatures-directory+json";

/**
 * Make a new Ed25519 key pair.
 *
 * :return: {privateJwk, publicJwk, kid}. Keep privateJwk secret (a server secret, never in a page).
 */
export async function newSiteKey() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  const withMeta = (jwk) => ({ ...jwk, kid, alg: "EdDSA", use: "sig" });
  return { privateJwk: withMeta(await exportJWK(privateKey)), publicJwk: withMeta(publicJwk), kid };
}

/**
 * The public part of a JWK, with kid, alg and use.
 *
 * :param jwk: A private or public Ed25519 JWK.
 * :return: The public JWK.
 */
export async function publicPart(jwk) {
  const { kty, crv, x } = jwk;
  if (kty !== "OKP" || crv !== "Ed25519" || !x) throw new Error("Only Ed25519 (OKP) keys are supported.");
  const kid = jwk.kid || (await calculateJwkThumbprint({ kty, crv, x }));
  return { kty, crv, x, kid, alg: "EdDSA", use: "sig" };
}

/** A JWKS key directory for the given public keys. */
export async function keyDirectory(jwks) {
  return { keys: await Promise.all(jwks.map(publicPart)) };
}

/** Import a JWK as a WebCrypto key for signing (private) or verifying (public). */
export async function importKey(jwk) {
  return importJWK(jwk, "EdDSA");
}

/**
 * Fetch an origin's key directory.
 *
 * :param origin: Such as https://site.example.
 * :param opts: {fetchImpl}.
 * :return: The JWKS object.
 * :raises Error: When the directory is missing, not JSON, or not on HTTPS (loopback excepted).
 */
export async function fetchKeyDirectory(origin, { fetchImpl = globalThis.fetch } = {}) {
  const url = new URL(KEY_DIRECTORY_PATH, origin);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !loopback) throw new Error(`Key directories must be served over HTTPS: ${url.origin}`);
  const resp = await fetchImpl(url.href, { redirect: "error" });
  if (!resp.ok) throw new Error(`No key directory at ${url.href} (HTTP ${resp.status}).`);
  const jwks = await resp.json();
  if (!Array.isArray(jwks?.keys)) throw new Error(`The key directory at ${url.href} is not a JWKS.`);
  return jwks;
}

/**
 * Find a public key by kid in a JWKS.
 *
 * :return: The JWK, or null.
 */
export function findKey(jwks, kid) {
  return (jwks?.keys || []).find((k) => k.kid === kid && k.kty === "OKP" && k.crv === "Ed25519") || null;
}
