// The transaction layer: commitments (with a mandate) and signed receipts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalHash, commit, keyDirectory, newNonce, newSiteKey, signReceipt, verifyReceipt } from "../src/index.js";

const sealed = { resident: "B12", night: "2026-12-22", energyKwh: 20, chargerKw: 11, fromMs: 1, readyByMs: 2 };

test("a commitment binds every field and the nonce; an unset mandate leaves it unchanged", async () => {
  const nonce = newNonce();
  const c = await commit(sealed, nonce);
  assert.equal(c, await canonicalHash({ ...sealed, nonce }), "plain canonical hash: anyone can recompute it");
  assert.notEqual(await commit({ ...sealed, energyKwh: 21 }, nonce), c);
  assert.notEqual(await commit(sealed, newNonce()), c);
  assert.equal(await commit({ ...sealed, maxPriceCents: undefined }, nonce), c);
  assert.equal(await commit({ ...sealed, maxPriceCents: null }, nonce), c);
  assert.notEqual(await commit({ ...sealed, maxPriceCents: 8 }, nonce), c, "a mandate is sealed in");
  await assert.rejects(commit(sealed, "short"), /nonce/);
  await assert.rejects(commit({ nonce: "x" }, nonce), /nonce/);
});

test("receipts verify with the issuer's keys and refuse another type, issuer or key", async () => {
  const { privateJwk, publicJwk } = await newSiteKey();
  const jwks = await keyDirectory([publicJwk]);
  const jws = await signReceipt({ typ: "charging-receipt/v1", iss: "https://housing.example", request_id: "r1", total_eur: 1.2 }, privateJwk);
  const ok = await verifyReceipt(jws, { issuer: "https://housing.example", typ: "charging-receipt/v1", jwks });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.receipt.request_id, "r1");
  assert.match((await verifyReceipt(jws, { issuer: "https://housing.example", typ: "booking-receipt/v1", jwks })).reason, /not a booking-receipt\/v1/);
  assert.equal((await verifyReceipt(jws, { issuer: "https://other.example", jwks })).reason, "issued by another site");
  assert.equal((await verifyReceipt(jws, { issuer: "https://housing.example", jwks: await keyDirectory([(await newSiteKey()).publicJwk]) })).ok, false);
  assert.throws(() => signReceipt({ iss: "https://x.example" }, privateJwk), /typ/);
});
