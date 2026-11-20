// verify-lite must agree with the full kit: same canonical JSON, same signature verdicts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson as kitJson, canonicalHash as kitHash, keyDirectory, newSiteKey, signStatement } from "../src/index.js";
import { canonicalHash, canonicalJson, verifyJws, verifyStatementLite } from "../src/verify-lite.js";

test("canonical JSON and hash match the kit on awkward values", async () => {
  const values = [
    { b: 1, a: [3, 2, 1], c: { z: null, y: true, x: "é " } },
    { n: [0, -0, 1e21, 1.5e-7, 0.1 + 0.2, -12.345, 2 ** 53] },
    [{ start: 1764453600000, end: 1764454500000, price: 2.15 }],
    { "€": 1, "a\u0000": 2, A: 3, aa: 4 },
  ];
  for (const v of values) {
    assert.equal(canonicalJson(v), kitJson(v));
    assert.equal(await canonicalHash(v), await kitHash(v));
  }
});

test("verifies the kit's statements; refuses a wrong key, a changed payload, another issuer or type", async () => {
  const { privateJwk, publicJwk } = await newSiteKey();
  const dir = await keyDirectory([publicJwk]);
  const jws = await signStatement({ typ: "charging-receipt/v1", iss: "https://site.example", total: 1.5 }, privateJwk);
  const ok = await verifyJws(jws, dir);
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.statement.total, 1.5);
  assert.equal((await verifyJws(jws, await keyDirectory([(await newSiteKey()).publicJwk]))).ok, false);
  const [h, , s] = jws.split(".");
  const forged = `${h}.${Buffer.from(JSON.stringify({ typ: "charging-receipt/v1", iss: "https://site.example", total: 0 })).toString("base64url")}.${s}`;
  assert.equal((await verifyJws(forged, dir)).reason, "signature does not verify");
  assert.equal((await verifyStatementLite(jws, { issuer: "https://site.example", typ: "charging-receipt/v1", keyDirectory: dir })).ok, true);
  assert.equal((await verifyStatementLite(jws, { issuer: "https://other.example", keyDirectory: dir })).reason, "issued by another site");
  assert.match((await verifyStatementLite(jws, { issuer: "https://site.example", typ: "other/v1", keyDirectory: dir })).reason, /not a other\/v1/);
  // Fetches the issuer's own key directory when none is given.
  const fetchImpl = async (url) => (String(url) === "https://site.example/.well-known/http-message-signatures-directory" ? new Response(JSON.stringify(dir)) : new Response("no", { status: 404 }));
  assert.equal((await verifyStatementLite(jws, { issuer: "https://site.example", fetchImpl })).ok, true);
});

test("verify-lite has no imports, so a static page can copy it as one file", async () => {
  const { readFile } = await import("node:fs/promises");
  const text = await readFile(new URL("../src/verify-lite.js", import.meta.url), "utf8");
  assert.doesNotMatch(text, /^\s*import\s/m);
});
