/*
 * Form action host checks shared by the content script and the rules playground.
 * Match the credential destination by hostname. A path, query, or fragment that
 * merely contains "login.microsoftonline.com" is not a Microsoft endpoint.
 */

/**
 * @param {string} actionValue Raw or absolute form action. Empty submits to baseUrl.
 * @param {string} requiredHost Hostname that must receive the credentials.
 * @param {string} baseUrl Document URL used to resolve relative actions.
 * @returns {boolean} True when the action posts to requiredHost or a subdomain of it.
 *   True when requiredHost is empty (no constraint). False when the action cannot be parsed.
 */
export function formActionTargetsHost(actionValue, requiredHost, baseUrl) {
  const expected = String(requiredHost || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
  if (!expected) return true;

  const base = baseUrl || "https://invalid.invalid/";
  const raw = actionValue == null ? "" : String(actionValue).trim();
  let resolved;
  try {
    resolved = new URL(raw || base, base);
  } catch (e) {
    return false;
  }

  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
    return false;
  }

  const host = resolved.hostname.toLowerCase().replace(/\.$/, "");
  return host === expected || host.endsWith("." + expected);
}

/**
 * A worker result is usable only after a completed scan.
 * `{ threats: [], score: 0 }` is also what a failed worker returns, so score alone
 * cannot distinguish "nothing found" from "scan did not run".
 * @param {{ success?: boolean } | null | undefined} result
 * @returns {boolean}
 */
export function indicatorScanSucceeded(result) {
  return !!(result && result.success === true);
}

/**
 * Legitimacy points on an already-untrusted origin come from markup a phishing
 * page can copy. Only the fail-closed low-score path may skip indicators.
 * @param {number} score
 * @returns {boolean}
 */
export function shouldScanPhishingIndicators(score) {
  if (typeof score === "number" && score <= 25) return false;
  return true;
}
