/* Privacy-respecting analytics abstraction.
   - Honours Do Not Track: if the browser signals DNT, nothing is recorded.
   - Only a strict allowlist of NON-SENSITIVE, primitive props is ever forwarded
     (plan, source, tier, cadence). Free-text form contents, emails, org names,
     messages and any PII are dropped by construction.
   - No third-party tracker is loaded. The default sink is a no-op (with an
     optional dev console echo); a first-party sink can be plugged in later
     without changing call sites. */

const ALLOWED_PROPS = new Set(["plan", "source", "tier", "cadence", "prompt"]);

// A small set of known event names so a typo never silently disappears in review.
export const EVENTS = {
  PRICING_VIEWED: "pricing_viewed",
  PLAN_SELECTED: "plan_selected",
  WAITLIST_SUBMITTED: "waitlist_submitted",
  BUSINESS_ENQUIRY_SUBMITTED: "business_enquiry_submitted",
  UPGRADE_PROMPT_SHOWN: "upgrade_prompt_shown",
  UPGRADE_PROMPT_SELECTED: "upgrade_prompt_selected",
};

export function doNotTrack() {
  try {
    const w = typeof window !== "undefined" ? window : {};
    const n = typeof navigator !== "undefined" ? navigator : {};
    const v = n.doNotTrack || w.doNotTrack || n.msDoNotTrack;
    return v === "1" || v === "yes" || v === true;
  } catch {
    return false;
  }
}

// Keep only allowlisted, primitive props. This is the privacy guarantee: even if
// a caller passes an email or message, it is stripped here.
export function sanitizeProps(props = {}) {
  const out = {};
  for (const [k, v] of Object.entries(props || {})) {
    if (!ALLOWED_PROPS.has(k)) continue;
    if (v == null) continue;
    if (typeof v === "string") out[k] = v.slice(0, 40);
    else if (typeof v === "number" || typeof v === "boolean") out[k] = v;
  }
  return out;
}

// Pluggable sink. Default is a no-op (no third-party tracker). Swap via
// setAnalyticsSink to send to a first-party endpoint if/when one exists.
let sink = null;
export function setAnalyticsSink(fn) {
  sink = typeof fn === "function" ? fn : null;
}

export function track(event, props = {}) {
  if (!event || typeof event !== "string") return false;
  if (doNotTrack()) return false;
  const payload = { event, props: sanitizeProps(props), ts: Date.now() };
  try {
    if (sink) sink(payload);
    else if (typeof window !== "undefined" && import.meta && import.meta.env && import.meta.env.DEV) {
      // Dev-only visibility; production default is a genuine no-op.
      // eslint-disable-next-line no-console
      console.debug("[analytics]", payload.event, payload.props);
    }
  } catch {
    /* analytics must never break the app */
  }
  return true;
}
