// Declaring which model ran a site's agent, in a signed JSON-RPC request (MCP _meta).
// Trust is network × model: a receiver checks the attestation for the declared model
// (src/admit.js). The declaration is the caller's claim, covered by its request signature.

/** Where a caller declares its model: MCP's `_meta` on a signed JSON-RPC call. */
export const MODEL_META = "agent-trust-kit/model";

/**
 * The model a JSON-RPC body declares, or null.
 *
 * :param bodyText: The request body as received.
 */
export function declaredModel(bodyText) {
  try {
    const m = JSON.parse(bodyText)?.params?._meta?.[MODEL_META];
    return typeof m === "string" && m.trim() && m.length <= 200 ? m.trim() : null;
  } catch {
    return null;
  }
}

/**
 * Put the model that ran this site's agent into a JSON-RPC body (params._meta). Sign the
 * result: the signature's content digest then covers the model too.
 *
 * :param bodyText: A JSON-RPC request body.
 * :param model: The model name, as testers name it (e.g. "openai/gpt-oss-20b").
 * :return: The new body text.
 * :raises TypeError: When the body is not a JSON object.
 */
export function declareModel(bodyText, model) {
  const body = JSON.parse(bodyText);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new TypeError("declareModel needs a JSON-RPC object body.");
  if (typeof model !== "string" || !model.trim()) return bodyText;
  body.params = { ...(body.params || {}), _meta: { ...(body.params?._meta || {}), [MODEL_META]: model.trim() } };
  return JSON.stringify(body);
}

/** Where a caller declares which of its networks made the request (its network URL). */
export const NETWORK_META = "agent-trust-kit/network";

/** The network URL a JSON-RPC body declares, or null. */
export function declaredNetwork(bodyText) {
  try {
    const n = JSON.parse(bodyText)?.params?._meta?.[NETWORK_META];
    if (typeof n !== "string" || n.length > 500) return null;
    const u = new URL(n);
    return u.protocol === "https:" || u.hostname === "localhost" ? u.href : null;
  } catch {
    return null;
  }
}

/**
 * Put the URL of the network that made this request into a JSON-RPC body (params._meta), so a
 * receiver checks that network's attestation and not just the first one on the domain.
 */
export function declareNetwork(bodyText, networkUrl) {
  const body = JSON.parse(bodyText);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new TypeError("declareNetwork needs a JSON-RPC object body.");
  if (typeof networkUrl !== "string" || !networkUrl.trim()) return bodyText;
  body.params = { ...(body.params || {}), _meta: { ...(body.params?._meta || {}), [NETWORK_META]: new URL(networkUrl).href } };
  return JSON.stringify(body);
}
