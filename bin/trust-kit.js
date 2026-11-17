#!/usr/bin/env node
// trust-kit keys <out-dir>
// trust-kit sign-network <network.json> --name <network> --origin <https://site> --key <private.jwk.json>
// trust-kit verify <network-url>
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { keyDirectory, newSiteKey, signNetwork, signatureUrl, verifyNetwork } from "../src/index.js";

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
  const manifest = await (await fetch(new URL("agent-manifest.json", base))).json();
  const entry = manifest.networks.find((n) => n.name === name);
  if (!entry) throw new Error(`No network named ${name} in the manifest.`);
  const network = await (await fetch(new URL(entry.hocon, base))).json();
  const sigResp = await fetch(signatureUrl(base, name));
  if (!sigResp.ok) throw new Error(`No signature at ${signatureUrl(base, name)} (HTTP ${sigResp.status}).`);
  const r = await verifyNetwork({ doc: await sigResp.json(), network, name, networkOrigin: u.origin });
  console.log(r.ok ? `OK: ${name} is signed by ${r.statement.origin} (key ${r.kid}), sha256 ${r.network_sha256}` : `FAIL: ${r.reason}`);
  process.exit(r.ok ? 0 : 1);
}

const commands = { keys, "sign-network": sign, verify };
if (!commands[cmd]) {
  console.log("Usage: trust-kit <keys | sign-network | verify> ...");
  process.exit(2);
}
commands[cmd]().catch((e) => {
  console.error(`trust-kit: ${e.message}`);
  process.exit(2);
});
