// Canonical JSON (RFC 8785, JCS) and hashing. Two copies of the same data, with keys in
// any order and any whitespace, give the same text and so the same hash.
import canonicalize from "canonicalize";

/**
 * Canonical JSON text of a value (RFC 8785).
 *
 * :param value: Any JSON value.
 * :return: The canonical string.
 * :raises TypeError: For values JSON cannot represent (undefined at top level, NaN, ...).
 */
export function canonicalJson(value) {
  const text = canonicalize(value);
  if (typeof text !== "string") throw new TypeError("Value cannot be canonicalized as JSON.");
  return text;
}

/** Hex SHA-256 of a string (UTF-8). */
export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Hex SHA-256 of the canonical JSON of a value. */
export async function canonicalHash(value) {
  return sha256Hex(canonicalJson(value));
}

/** Base64 (standard, padded) of bytes. */
export function base64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}
