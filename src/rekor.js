// Transparency log for attestations: Sigstore Rekor (v1 API), "dsse" entries.
//
// Logging an attestation puts its DSSE envelope's signature and payload hash on a public,
// append-only log run by Sigstore, with a time Rekor vouches for. Afterwards the issuer can't
// quietly backdate, swap or withdraw what it published: anyone holding the envelope and its
// log entry can check, offline, that
//   1. the entry is for this envelope (same payload hash, same signature, same signing key),
//   2. the entry is in the log (an RFC 9162 inclusion proof up to a logged tree root), and
//   3. Rekor signed that tree root (the checkpoint), with Rekor's own published key.
//
// Why Rekor v1 "dsse" entries: the envelope keeps its pure Ed25519 signature (the tester's
// existing key, no second key); Rekor v2 accepts neither the dsse type nor pure Ed25519.
// Volume is a handful of entries a month (one per published attestation).

import { base64 } from "./canonical.js";
import { fromBase64 } from "./dsse.js";

const enc = new TextEncoder();

/** The two public Sigstore Rekor v1 instances. Staging is public too, but for tests. */
export const REKOR = Object.freeze({
  production: "https://rekor.sigstore.dev",
  staging: "https://rekor.sigstage.dev",
});

// Rekor's checkpoint keys (ECDSA P-256), pinned so a verifier never has to trust a key the
// log hands out at verification time. Source: each instance's /api/v1/log/publicKey,
// fetched 19 Nov 2026 (the production key is the one in Sigstore's TUF root).
export const REKOR_KEYS = Object.freeze({
  "https://rekor.sigstore.dev": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
  "https://rekor.sigstage.dev": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==",
});

/** An Ed25519 public JWK as a PEM SubjectPublicKeyInfo (what Rekor takes as a verifier). */
export function ed25519Pem(publicJwk) {
  if (publicJwk?.kty !== "OKP" || publicJwk.crv !== "Ed25519" || !publicJwk.x) throw new Error("An Ed25519 public JWK is required.");
  const prefix = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const raw = fromBase64(publicJwk.x);
  const der = new Uint8Array(prefix.length + raw.length);
  der.set(prefix);
  der.set(raw, prefix.length);
  return `-----BEGIN PUBLIC KEY-----\n${base64(der).match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/**
 * Add a DSSE envelope to Rekor. Logging the same envelope twice returns the existing entry.
 *
 * :param envelope: The DSSE envelope (object or JSON text), signed by publicJwk's key.
 * :param publicJwk: The signer's Ed25519 public JWK.
 * :param opts: {rekorUrl (default production), fetchImpl}.
 * :return: A log entry record (see toLogEntry), to publish next to the attestation.
 */
export async function logEnvelope(envelope, publicJwk, { rekorUrl = REKOR.production, fetchImpl = globalThis.fetch } = {}) {
  const text = typeof envelope === "string" ? envelope : JSON.stringify(envelope);
  const body = {
    apiVersion: "0.0.1",
    kind: "dsse",
    spec: { proposedContent: { envelope: text, verifiers: [base64(enc.encode(ed25519Pem(publicJwk)))] } },
  };
  const res = await fetchImpl(`${rekorUrl}/api/v1/log/entries`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status === 409) {
    // Already logged: Rekor points at the existing entry.
    const where = res.headers.get("location");
    if (!where) throw new Error("Rekor says the entry exists but gave no location.");
    const again = await fetchImpl(new URL(where, rekorUrl).href, { headers: { accept: "application/json" } });
    if (!again.ok) throw new Error(`Rekor: could not read the existing entry (HTTP ${again.status}).`);
    return toLogEntry(await again.json(), rekorUrl);
  }
  if (res.status !== 201) throw new Error(`Rekor refused the entry (HTTP ${res.status}): ${(await res.text()).slice(0, 300)}`);
  return toLogEntry(await res.json(), rekorUrl);
}

/** Rekor's {uuid: entry} answer as one flat record. */
export function toLogEntry(answer, rekorUrl) {
  const [uuid, e] = Object.entries(answer)[0] ?? [];
  if (!uuid || !e?.verification?.inclusionProof) throw new Error("Rekor's answer has no entry with an inclusion proof.");
  return {
    log: rekorUrl,
    uuid,
    logIndex: e.logIndex,
    logID: e.logID,
    integratedTime: e.integratedTime,
    body: e.body,
    inclusionProof: e.verification.inclusionProof,
    signedEntryTimestamp: e.verification.signedEntryTimestamp,
  };
}

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The tree root an RFC 9162 inclusion proof leads to (arithmetic, not 32-bit bit ops: Rekor's
 * shards hold billions of entries).
 */
export async function rootFromInclusionProof(index, size, leafHash, path) {
  if (!(index >= 0 && index < size)) throw new Error("leaf index outside the tree");
  let fn = index, sn = size - 1, r = leafHash;
  for (const p of path) {
    if (sn === 0) throw new Error("inclusion proof is too long");
    if (fn % 2 === 1 || fn === sn) {
      r = await sha256(concat([1], p, r));
      if (fn % 2 === 0) {
        do { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } while (fn % 2 === 0 && fn !== 0);
      }
    } else {
      r = await sha256(concat([1], r, p));
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("inclusion proof is too short");
  return r;
}

/** ASN.1 DER ECDSA signature to the raw r||s form WebCrypto verifies (P-256). */
function derToRaw(der) {
  let at = 2;
  if (der[1] & 0x80) at += der[1] & 0x7f;
  const read = () => {
    if (der[at] !== 0x02) throw new Error("bad DER signature");
    const len = der[at + 1];
    let v = der.slice(at + 2, at + 2 + len);
    at += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  return concat(read(), read());
}

/**
 * Check a signed checkpoint ("signed note"): its root and size, and Rekor's signature on it.
 *
 * :return: {ok: true, size, root} or {ok: false, reason}.
 */
export async function verifyCheckpoint(checkpoint, rekorKeyBase64) {
  const split = checkpoint.indexOf("\n\n");
  if (split < 0) return { ok: false, reason: "checkpoint has no signature block" };
  const text = checkpoint.slice(0, split + 1);
  const [, sizeLine, rootLine] = text.split("\n");
  const sigs = checkpoint.slice(split + 2).split("\n").filter((l) => l.startsWith("— "));
  const key = await crypto.subtle.importKey("spki", fromBase64(rekorKeyBase64), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  for (const line of sigs) {
    const raw = fromBase64(line.split(" ").pop());
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(raw.slice(4)), enc.encode(text)).catch(() => false);
    if (ok) return { ok: true, size: Number(sizeLine), root: fromBase64(rootLine) };
  }
  return { ok: false, reason: "the checkpoint is not signed by the log's pinned key" };
}

/**
 * Verify, offline, that a log entry is for this envelope and is in the log.
 *
 * :param envelope: The DSSE envelope (object or JSON text).
 * :param entry: The record logEnvelope returned (published next to the attestation).
 * :param opts: {signerJwk: the expected signer's public JWK (optional; else any signature
 *     in the envelope counts), rekorKey: base64 SPKI to use instead of the pinned key}.
 * :return: {ok: true, log, logIndex, integratedTime: ISO time} or {ok: false, reason}.
 */
export async function verifyLogEntry(envelope, entry, { signerJwk = null, rekorKey = null } = {}) {
  try {
    const env = typeof envelope === "string" ? JSON.parse(envelope) : envelope;
    const key = rekorKey ?? REKOR_KEYS[entry?.log];
    if (!key) return { ok: false, reason: `no pinned key for the log ${entry?.log}` };
    // 1. The entry is about this envelope: same payload, same signature, same signer.
    const bodyBytes = fromBase64(entry.body);
    const body = JSON.parse(new TextDecoder().decode(bodyBytes));
    if (body.kind !== "dsse") return { ok: false, reason: `log entry is of kind ${body.kind}, not dsse` };
    const payloadHash = hex(await sha256(fromBase64(env.payload)));
    if (body.spec?.payloadHash?.value !== payloadHash) return { ok: false, reason: "the log entry is for a different payload" };
    const pem = signerJwk ? ed25519Pem(signerJwk) : null;
    const matched = (body.spec.signatures || []).some((s) => env.signatures.some((e) => sameBytes(fromBase64(e.sig), fromBase64(s.signature)))
      && (!pem || new TextDecoder().decode(fromBase64(s.verifier)).trim() === pem.trim()));
    if (!matched) return { ok: false, reason: signerJwk ? "the log entry is not signed with the expected key" : "the log entry has a different signature" };
    // 2. The entry is in the tree whose root the proof gives.
    const p = entry.inclusionProof;
    const leaf = await sha256(concat([0], bodyBytes));
    const root = await rootFromInclusionProof(p.logIndex, p.treeSize, leaf, p.hashes.map(fromHex));
    if (hex(root) !== p.rootHash) return { ok: false, reason: "the inclusion proof does not lead to the logged root" };
    // 3. Rekor signed that root.
    const cp = await verifyCheckpoint(p.checkpoint, key);
    if (!cp.ok) return cp;
    if (cp.size !== p.treeSize || hex(cp.root) !== p.rootHash) return { ok: false, reason: "the checkpoint is for a different tree" };
    return { ok: true, log: entry.log, logIndex: entry.logIndex, integratedTime: new Date(entry.integratedTime * 1000).toISOString() };
  } catch (e) {
    return { ok: false, reason: `log entry could not be checked: ${e.message}` };
  }
}

/** A link where people can look the entry up (Sigstore's search UI). */
export function logEntryUrl(entry) {
  const host = entry.log === REKOR.staging ? "https://search.sigstage.dev" : "https://search.sigstore.dev";
  return `${host}/?logIndex=${entry.logIndex}`;
}
