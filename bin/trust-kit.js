#!/usr/bin/env node
// trust-kit keys <out-dir>
// trust-kit sign-network <network.json> --name <network> --origin <https://site> --key <private.jwk.json>
// trust-kit verify <network-url>
// trust-kit peer-trust <your-network-url> [--network <network.json>] [--out <peer-trust.json>]
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fetchSignature, keyDirectory, newSiteKey, peerTrustReport, signNetwork, signatureUrl, verifyNetwork } from "../src/index.js";

const [cmd, ...rest] = process.argv.slice(2);
const flag = (name) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};

async function keys() {
  const out = rest[0];
  if (!out) throw new Error("Usage: trust-kit keys <out-dir>");
  await mkdir(out, { recursive: true });
  const k = await newSiteKey();
  const priv = path.join(out, "site-key.private.jwk.json");
  await writeFile(priv, JSON.stringify(k.privateJwk, null, 2), { flag: "wx", mode: 0o600 });
  await writeFile(path.join(out, "http-message-signatures-directory"), JSON.stringify(await keyDirectory([k.publicJwk]), null, 2));
  console.log(`kid ${k.kid}\nprivate key: ${priv}  (secret: never commit or publish)\npublic directory: ${path.join(out, "http-message-signatures-directory")}  (publish at /.well-known/http-message-signatures-directory)`);
}

async function sign() {
  const file = rest[0];
  const name = flag("name");
  const origin = flag("origin");
  const keyFile = flag("key");
  if (!file || !name || !origin || !keyFile) throw new Error("Usage: trust-kit sign-network <network.json> --name <network> --origin <https://site> --key <private.jwk.json>");
  const network = JSON.parse(await readFile(file, "utf8"));
  const privateJwk = JSON.parse(await readFile(keyFile, "utf8"));
  const doc = await signNetwork({ network, name, origin, privateJwk });
  const out = path.join(path.dirname(file), `${name}.signature.json`);
  await writeFile(out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${out}`);
}

async function verify() {
  const url = rest[0];
  if (!url) throw new Error("Usage: trust-kit verify <network-url>");
  const u = new URL(url);
  const parts = u.pathname.split("/").filter(Boolean);
  const name = decodeURIComponent(parts.pop());
  const base = `${u.origin}/${parts.join("/")}${parts.length ? "/" : ""}`;
  const manifest = await getJson(new URL("agent-manifest.json", base).href);
  const entry = manifest?.networks?.find((n) => n.name === name);
  if (!entry) throw new Error(`No network named ${name} in the manifest.`);
  const network = await getJson(new URL(entry.hocon, base).href);
  const sig = await fetchSignature(signatureUrl(base, name));
  if (sig.status === "missing") {
    console.log(`UNSIGNED: ${sig.url}: ${sig.reason}. Who published ${name} is not proven.`);
    process.exit(1);
  }
  const r = sig.status === "found"
    ? await verifyNetwork({ doc: sig.doc, network, name, networkOrigin: u.origin })
    : { ok: false, reason: `${sig.url}: ${sig.reason}` };
  console.log(r.ok ? `OK: ${name} is signed by ${r.statement.origin} (key ${r.kid}), sha256 ${r.network_sha256}` : `FAIL: ${r.reason}`);
  process.exit(r.ok ? 0 : 1);
}

async function getJson(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`${url} answered HTTP ${resp.status}.`);
  const text = await resp.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${url} is not JSON.`);
  }
}

// Build step for a static site: check every partner its network can contact and write
// the result, to be served at /.well-known/peer-trust.json from the site's own origin.
async function peerTrust() {
  const url = rest[0];
  if (!url) throw new Error("Usage: trust-kit peer-trust <your-network-url> [--network <network.json>] [--out <peer-trust.json>]");
  const networkFile = flag("network");
  const network = networkFile ? JSON.parse(await readFile(networkFile, "utf8")) : null;
  const report = await peerTrustReport(url, { network });
  const text = `${JSON.stringify(report, null, 2)}\n`;
  const out = flag("out");
  if (out) {
    await mkdir(path.dirname(out), { recursive: true });
    await writeFile(out, text);
  }
  for (const p of report.peers) {
    const s = p.kind === "mcp" ? p.note
      : p.error ? `could not check: ${p.error}`
        : `${p.signature.ok ? "signed" : p.signature.status}; ${p.attestation.ok ? `attested ${p.attestation.score} (coverage ${p.attestation.coverage}) on ${p.attestation.model}` : `not vouched for: ${p.attestation.reason}`}`;
    console.error(`${p.trusted ? "✓" : "⚠"} ${p.host}: ${s}`);
  }
  if (out) console.error(`wrote ${out}`);
  else console.log(text.trimEnd());
}

const commands = { keys, "sign-network": sign, verify, "peer-trust": peerTrust };
if (!commands[cmd]) {
  console.log("Usage: trust-kit <keys | sign-network | verify | peer-trust> ...");
  process.exit(2);
}
commands[cmd]().catch((e) => {
  console.error(`trust-kit: ${e.message}`);
  process.exit(2);
});
