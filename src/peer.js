// Peer trust: "is this other site's agent network signed by its domain, and does a tester
// I trust vouch for exactly this version of it?" No model involved.
//
// checkNetwork() is the one check behind both uses:
//   - an arbiter admitting a cross-site caller (taloyhtio-charging admission.js), and
//   - a site telling its visitor, on the consent card, what is known about a partner
//     before the visitor agrees to contact it (peerTrustReport(), served from the
//     site's own origin, so the browser never contacts the peer before consent).

import { canonicalHash } from "./canonical.js";
import { verifyAttestation } from "./attestation.js";
import { fetchSignature, signatureUrl, verifyNetwork } from "./network.js";

export const PEER_TRUST_TYPE = "peer-trust/v1";
export const PEER_TRUST_PATH = "/.well-known/peer-trust.json";

export const DEFAULT_TRUST_POLICY = Object.freeze({
  // Testers whose attestations count, and where each publishes its index.
  testers: Object.freeze([Object.freeze({ origin: "https://crashtest.frankmp12357.workers.dev", index: "/attestations/index.json" })]),
  minScore: 80,
  minCoverage: 80,
  // An average can hide a critical failure (crash-test FINDINGS F45): refuse any network
  // with a test that failed outright, unless a policy sets this to false.
  noFailedTests: true,
});

/**
 * Wrap fetch with a small time-limited cache of successful answers (per process or isolate).
 *
 * :param fetchImpl: The fetch to wrap.
 * :param opts: {cache: a Map to keep entries in, ttlMs (default 5 min), now: () => ms}.
 * :return: A fetch-compatible function; each call returns a fresh Response.
 */
export function cachingFetch(fetchImpl, { cache = new Map(), ttlMs = 5 * 60_000, now = () => Date.now() } = {}) {
  return async (url, init = {}) => {
    const key = `${init.redirect ?? "follow"} ${String(url)}`;
    const hit = cache.get(key);
    if (hit && now() - hit.at < ttlMs) return new Response(hit.body, { status: hit.status, headers: hit.headers });
    const resp = await fetchImpl(url, init);
    // Opaque redirects (status 0) can't be rebuilt; pass them through uncached.
    if (!(resp.status >= 200 && resp.status < 600)) return resp;
    const body = await resp.text();
    const entry = { at: now(), status: resp.status, headers: [...resp.headers], body };
    if (resp.ok) cache.set(key, entry);
    return new Response(body, { status: entry.status, headers: entry.headers });
  };
}

async function getJson(url, fetchImpl, init = {}) {
  const resp = await fetchImpl(url, { headers: { accept: "application/json" }, ...init });
  if (!resp.ok) throw new Error(`${url} answered ${resp.status}`);
  const text = await resp.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${url} is not JSON`);
  }
}

/** The runtime's own rule for which tool refs are MCP servers (kernel is_mcp_ref). */
export function isMcpRef(ref) {
  if (typeof ref !== "string") return true;
  if (!/^https?:\/\//.test(ref)) return false;
  const s = ref.toLowerCase();
  return s.includes("/mcp/") || s.endsWith("/mcp") || s.includes("//mcp.") || s.includes(".mcp.");
}

/**
 * Check another site's agent network: its domain signature and its attestations.
 *
 * Both checks always run, so a caller can show the full picture; `trusted` is true only
 * when the network is validly signed by its own domain *and* an attestation from a tester
 * in the policy covers exactly the network as published now and meets the policy.
 *
 * :param target: A network URL ("https://site/path/<name>"), or {origin} for the first
 *     network in that origin's agent-manifest.json.
 * :param opts: {policy, fetchImpl, now (ms), jwks (tests: the peer's key directory)}.
 * :return: {network_url, origin, network_sha256, trusted, signature: {ok, status:
 *     "valid"|"unsigned"|"invalid", by?, kid?, reason?}, attestation: {ok, iss?, score?,
 *     coverage?, model?, exp?, test_version?, failed: [], results: {id: verdict}, reason?}}
 *     or {trusted: false, error, network_url?, origin} when the network can't be loaded.
 */
export async function checkNetwork(target, { policy = DEFAULT_TRUST_POLICY, fetchImpl = globalThis.fetch, now = Date.now(), jwks = null } = {}) {
  let base;
  let name = null;
  if (typeof target === "string") {
    const u = new URL(target);
    const parts = u.pathname.split("/").filter(Boolean);
    name = decodeURIComponent(parts.pop() || "");
    base = `${u.origin}/${parts.join("/")}${parts.length ? "/" : ""}`;
  } else {
    base = `${new URL(target.origin).origin}/`;
  }
  const origin = new URL(base).origin;

  let network_url = name ? new URL(encodeURIComponent(name), base).href : null;
  let network;
  let network_sha256;
  try {
    const manifest = await getJson(new URL("agent-manifest.json", base).href, fetchImpl);
    const entry = name ? manifest?.networks?.find((n) => n?.name === name) : manifest?.networks?.[0];
    if (!entry?.name || !entry?.hocon) {
      return { trusted: false, origin, network_url, error: name ? `${origin} publishes no network named ${name} in agent-manifest.json` : `${origin} publishes no agent network in agent-manifest.json` };
    }
    name = entry.name;
    network_url = new URL(encodeURIComponent(name), base).href;
    network = await getJson(new URL(entry.hocon, base).href, fetchImpl);
    network_sha256 = await canonicalHash(network);
  } catch (error) {
    return { trusted: false, origin, network_url, error: `Could not load ${origin}'s agent network: ${error.message}` };
  }

  // 1. Who published it: a signature by the network's own domain.
  let signature;
  try {
    const sig = await fetchSignature(signatureUrl(base, name), { fetchImpl });
    if (sig.status === "missing") signature = { ok: false, status: "unsigned", reason: sig.reason };
    else if (sig.status === "invalid") signature = { ok: false, status: "invalid", reason: sig.reason };
    else {
      const v = await verifyNetwork({ doc: sig.doc, network, name, networkOrigin: origin, jwks, fetchImpl });
      signature = v.ok
        ? { ok: true, status: "valid", by: v.statement.origin, kid: v.kid, issued_at: v.statement.issued_at }
        : { ok: false, status: "invalid", reason: v.reason };
    }
  } catch (error) {
    signature = { ok: false, status: "unsigned", reason: `no readable signature file (${error.message})` };
  }

  // 2. Does it behave: an attestation for exactly this network hash, meeting the policy.
  const attestation = await bestAttestation({ network_url, network_sha256, policy, fetchImpl, now });

  return { network_url, origin, network_sha256, trusted: signature.ok && attestation.ok, signature, attestation };
}

async function bestAttestation({ network_url, network_sha256, policy, fetchImpl, now }) {
  const problems = [];
  let shown = null; // a verified attestation that misses the policy, to show honestly
  for (const t of policy.testers || []) {
    let index;
    try {
      index = await getJson(new URL(t.index, t.origin).href, fetchImpl);
    } catch (error) {
      problems.push(`${t.origin}: ${error.message}`);
      continue;
    }
    for (const a of (index.attestations || []).filter((x) => x.sub === network_url)) {
      let signed;
      try {
        const resp = await fetchImpl(new URL(a.attestation ?? a.jws, `${t.origin}/`).href);
        if (!resp.ok) throw new Error(`${resp.url || a.attestation} answered ${resp.status}`);
        signed = (await resp.text()).trim();
      } catch (error) {
        problems.push(error.message);
        continue;
      }
      const v = await verifyAttestation(signed, { issuer: t.origin, fetchImpl, now, expect: { sub: network_url, network_sha256 } });
      if (!v.ok) {
        problems.push(v.reason);
        continue;
      }
      const s = v.statement;
      const results = Object.fromEntries(Object.entries(s.results || {}).map(([id, r]) => [id, r?.verdict ?? null]));
      const failed = Object.entries(results).filter(([, verdict]) => verdict === "fail").map(([id]) => id);
      const facts = { iss: s.iss, score: s.score, coverage: s.coverage ?? null, model: s.model?.name ?? null, exp: s.exp, test_version: s.test_version ?? null, failed, results };
      const misses = [];
      if (Number.isFinite(policy.minScore) && !(s.score >= policy.minScore)) misses.push(`score ${s.score} is below ${policy.minScore}`);
      if (Number.isFinite(policy.minCoverage) && !(s.coverage >= policy.minCoverage)) misses.push(`coverage ${s.coverage ?? "unknown"} is below ${policy.minCoverage}`);
      if (policy.noFailedTests !== false && failed.length) misses.push(`failed outright: ${failed.join(", ")} (score ${s.score})`);
      for (const id of policy.required || []) {
        if (results[id] !== "pass") misses.push(`required test ${id} did not pass (${results[id] ?? "missing"})`);
      }
      if (!misses.length) return { ok: true, ...facts };
      problems.push(misses.join("; "));
      shown ??= facts;
    }
  }
  return { ok: false, ...(shown ?? { failed: [], results: {} }), reason: problems.length ? problems.join("; ") : "no attestation found" };
}

const reports = new Map(); // siteNetworkUrl -> {at, body}; per process or isolate

/**
 * Serve peerTrustReport() as an HTTP response, recomputed at most every ttlMs. For a
 * server route at PEER_TRUST_PATH on the site's own origin.
 *
 * :param siteNetworkUrl: This site's own network URL.
 * :param opts: peerTrustReport() options, plus ttlMs (default 5 min).
 * :return: A Response with the report as JSON.
 */
export async function peerTrustResponse(siteNetworkUrl, { ttlMs = 5 * 60_000, ...opts } = {}) {
  const now = opts.now ?? Date.now();
  let hit = reports.get(siteNetworkUrl);
  if (!hit || now - hit.at >= ttlMs) {
    const fetchImpl = cachingFetch(opts.fetchImpl ?? globalThis.fetch, { ttlMs, now: () => now });
    hit = { at: now, body: JSON.stringify(await peerTrustReport(siteNetworkUrl, { ...opts, now, fetchImpl })) };
    reports.set(siteNetworkUrl, hit);
  }
  return new Response(hit.body, {
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": `public, max-age=${Math.floor(ttlMs / 1000)}` },
  });
}

/** Forget served reports (tests). */
export function clearPeerTrustCache() {
  reports.clear();
}

/**
 * Check every other site a published network can contact, for serving at
 * /.well-known/peer-trust.json on the publishing site's own origin.
 *
 * Peers are the cross-origin refs in the network's agents' `tools`: agent networks are
 * checked with checkNetwork(); MCP servers are listed as such (no signature or attestation
 * format exists for them yet). Partners a visitor links at runtime can't be known here.
 *
 * :param siteNetworkUrl: This site's own network URL.
 * :param opts: {policy, fetchImpl, now, network (the parsed network, to skip fetching it),
 *     jwks}.
 * :return: {typ: "peer-trust/v1", site, generated_at, policy, peers: [{host, url, kind,
 *     label?, ...checkNetwork() result}]}.
 */
export async function peerTrustReport(siteNetworkUrl, { policy = DEFAULT_TRUST_POLICY, fetchImpl = globalThis.fetch, now = Date.now(), network = null, jwks = null } = {}) {
  const site = new URL(siteNetworkUrl);
  const config = network ?? await (async () => {
    const parts = site.pathname.split("/").filter(Boolean);
    const name = decodeURIComponent(parts.pop() || "");
    const base = `${site.origin}/${parts.join("/")}${parts.length ? "/" : ""}`;
    const manifest = await getJson(new URL("agent-manifest.json", base).href, fetchImpl);
    const entry = manifest?.networks?.find((n) => n?.name === name);
    if (!entry) throw new Error(`No network named ${name} in ${base}agent-manifest.json`);
    return getJson(new URL(entry.hocon, base).href, fetchImpl);
  })();

  const refs = new Set();
  for (const agent of config?.tools || []) {
    for (const ref of agent?.tools || []) {
      const url = typeof ref === "string" ? ref : ref?.url;
      if (typeof url !== "string" || !/^https?:\/\//.test(url)) continue;
      if (new URL(url).origin === site.origin) continue;
      refs.add(JSON.stringify([url, isMcpRef(ref)]));
    }
  }
  const labels = config?.link_labels || {};
  const peers = [];
  for (const [url, mcp] of [...refs].map((r) => JSON.parse(r))) {
    const host = new URL(url).host;
    if (mcp) {
      peers.push({ host, url, kind: "mcp", trusted: false, note: "an MCP tool server: no signature or attestation format applies yet" });
      continue;
    }
    const r = await checkNetwork(url, { policy, fetchImpl, now, jwks });
    peers.push({ host, url, kind: "network", ...(labels[url] ? { label: labels[url] } : {}), ...r });
  }
  return {
    typ: PEER_TRUST_TYPE,
    site: siteNetworkUrl,
    generated_at: new Date(now).toISOString(),
    policy: { testers: (policy.testers || []).map((t) => t.origin), minScore: policy.minScore, minCoverage: policy.minCoverage, noFailedTests: policy.noFailedTests !== false },
    peers,
  };
}
