// Transparency log entries (Rekor v1 "dsse"), verified offline against a real staging entry
// (test/vectors/rekor-staging.json, made by test/vectors/make-rekor-fixture.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { newSiteKey } from "../src/keys.js";
import { signEnvelope } from "../src/dsse.js";
import { REKOR, ed25519Pem, logEnvelope, logEntryUrl, rootFromInclusionProof, verifyLogEntry } from "../src/rekor.js";

const fx = JSON.parse(await readFile(new URL("./vectors/rekor-staging.json", import.meta.url), "utf8"));
const clone = (x) => JSON.parse(JSON.stringify(x));

test("a real Rekor staging entry verifies offline: same envelope, in the tree, root signed by Rekor", async () => {
  const r = await verifyLogEntry(fx.envelope, fx.entry, { signerJwk: fx.publicJwk });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.log, REKOR.staging);
  assert.match(r.integratedTime, /^\d{4}-\d\d-\d\dT/);
  assert.equal(logEntryUrl(fx.entry), `https://search.sigstage.dev/?logIndex=${fx.entry.logIndex}`);
});

test("the entry belongs to its envelope and its signer, nothing else", async () => {
  const other = clone(fx.envelope);
  other.payload = btoa('{"_type":"something else"}');
  assert.match((await verifyLogEntry(other, fx.entry)).reason, /different payload/);
  const stranger = await newSiteKey();
  assert.match((await verifyLogEntry(fx.envelope, fx.entry, { signerJwk: stranger.publicJwk })).reason, /expected key/);
  const resigned = await signEnvelope(atob(fx.envelope.payload), fx.envelope.payloadType, stranger.privateJwk);
  assert.match((await verifyLogEntry(resigned, fx.entry)).reason, /different signature/, "same payload, another signature: not this entry");
});

test("a tampered proof or a checkpoint from another key fails", async () => {
  const bent = clone(fx.entry);
  bent.inclusionProof.hashes[0] = "00".repeat(32);
  assert.match((await verifyLogEntry(fx.envelope, bent)).reason, /does not lead to the logged root/);
  const otherLog = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const spki = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("spki", otherLog.publicKey))));
  assert.match((await verifyLogEntry(fx.envelope, fx.entry, { rekorKey: spki })).reason, /not signed by the log's pinned key/);
  assert.match((await verifyLogEntry(fx.envelope, { ...fx.entry, log: "https://rekor.example" })).reason, /no pinned key/);
});

test("inclusion proofs: RFC 9162 on a small tree, and indexes past 2^31 work", async () => {
  const h = async (...parts) => new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(parts.flatMap((p) => [...p]))));
  const leaves = await Promise.all([0, 1, 2, 3, 4].map((i) => h([0], [i])));
  const n01 = await h([1], leaves[0], leaves[1]), n23 = await h([1], leaves[2], leaves[3]);
  const n0123 = await h([1], n01, n23), root = await h([1], n0123, leaves[4]);
  assert.deepEqual(await rootFromInclusionProof(2, 5, leaves[2], [leaves[3], n01, leaves[4]]), root);
  assert.deepEqual(await rootFromInclusionProof(4, 5, leaves[4], [n0123]), root);
  await assert.rejects(rootFromInclusionProof(5, 5, leaves[4], []), /outside the tree/);
  // A last leaf in a tree of 2^31 + 1 entries: one step, no 32-bit overflow.
  const big = 2 ** 31;
  assert.deepEqual(await rootFromInclusionProof(big, big + 1, leaves[4], [n0123]), await h([1], n0123, leaves[4]));
});

test("logEnvelope: sends a dsse entry with the signer's PEM; a repeat returns the existing entry", async () => {
  assert.match(ed25519Pem(fx.publicJwk), /^-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA/);
  const answer = { [fx.entry.uuid]: { body: fx.entry.body, integratedTime: fx.entry.integratedTime, logID: fx.entry.logID, logIndex: fx.entry.logIndex, verification: { inclusionProof: fx.entry.inclusionProof, signedEntryTimestamp: fx.entry.signedEntryTimestamp } } };
  const sent = [];
  const fetchImpl = async (url, init = {}) => {
    sent.push({ url, init });
    if (init.method === "POST") return new Response("exists", { status: 409, headers: { location: `/api/v1/log/entries/${fx.entry.uuid}` } });
    return new Response(JSON.stringify(answer), { status: 200 });
  };
  const entry = await logEnvelope(fx.envelope, fx.publicJwk, { rekorUrl: REKOR.staging, fetchImpl });
  const body = JSON.parse(sent[0].init.body);
  assert.equal(body.kind, "dsse");
  assert.equal(atob(body.spec.proposedContent.verifiers[0]), ed25519Pem(fx.publicJwk));
  assert.equal(sent[1].url, `${REKOR.staging}/api/v1/log/entries/${fx.entry.uuid}`);
  assert.equal((await verifyLogEntry(fx.envelope, entry, { signerJwk: fx.publicJwk })).ok, true);
});
