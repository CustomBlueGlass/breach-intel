// Vercel serverless function: demand capture for the paid plans (Pro waitlist,
// Business access request, Enterprise/sales contact). Monetisation Phase 1.
//
// Security model:
//   - POST only (+ OPTIONS). A valid Supabase session (Bearer access token) is
//     required, so the email is verified and we never trust a client-supplied
//     email or user id.
//   - Input is strictly validated and length-bounded.
//   - Rate limiting is DURABLE and shared across serverless instances: it is
//     enforced in Postgres via rl_hit() (a private counter table), keyed by
//     client IP (pre-auth) and by verified user (post-auth). A stateless
//     serverless function has no reliable in-process memory, so the limiter must
//     live in shared state, not the instance.
//   - The limiter FAILS CLOSED. If rl_hit errors, times out or returns a
//     non-boolean, the request is rejected with a generic 503 and never reaches
//     authentication or the insert. A limiter that fails open is not a limiter.
//   - Client IP is taken from the platform proxy header the deployment controls
//     (x-vercel-forwarded-for / x-real-ip on Vercel), never from an
//     attacker-suppliable first X-Forwarded-For value. The bucket stores a keyed
//     hash of the IP, so raw addresses are never written to rate_limits.
//   - Rows are written with the server-side SERVICE ROLE key into the fully
//     private plan_enquiries table (RLS on, no anon/authenticated grants), so the
//     submissions are never exposed through the anonymous/authenticated Data API.
//   - Success is reported ONLY when the insert actually persisted (201).
//   - No secret is ever sent to the browser; the service-role key is read from
//     the server environment only. See docs / PR for the required variables.

import { createHmac } from "node:crypto";

const PLANS = new Set(["pro", "business", "enterprise"]);
const SOURCES = new Set(["pricing_page", "dashboard", "workspace", "other"]);
const LIMITS = { organisation: 200, role_use_case: 200, message: 2000, source: 60 };
const UPSTREAM_TIMEOUT_MS = 8000;
// Durable rate-limit windows (enforced in Postgres, shared across instances).
const IP_MAX = 30, IP_WINDOW_SECS = 60;          // per client IP, per minute
const USER_MAX = 10, USER_WINDOW_SECS = 3600;    // per verified user, per hour

// Normalise a single address: strip an IPv6 zone id, unwrap [v6] brackets, drop a
// trailing :port on IPv4 or bracketed IPv6, and lower-case. Bare IPv6 (which is
// full of colons) is preserved. Returns "" for empty input.
export function normalizeIp(raw) {
  let s = String(raw == null ? "" : raw).trim();
  if (!s) return "";
  if (s[0] === "[") {                       // [v6] or [v6]:port
    const end = s.indexOf("]");
    if (end !== -1) return s.slice(1, end).replace(/%.*$/, "").toLowerCase();
  }
  const colons = (s.match(/:/g) || []).length;
  if (colons === 1) s = s.split(":")[0];    // v4:port
  else if (colons > 1) return s.replace(/%.*$/, "").toLowerCase(); // bare v6
  return s.replace(/%.*$/, "").toLowerCase();
}
function firstIp(v) {
  if (!v) return "";
  return normalizeIp(String(v).split(",")[0]);
}

// Trusted client IP. On Vercel the platform overwrites x-vercel-forwarded-for and
// x-real-ip at the edge, so those cannot be forged by the client; x-forwarded-for
// can be, and its FIRST entry is attacker-controlled, so it is only a last resort
// and we take the LAST hop (added by the nearest trusted proxy), not the first.
export function clientIp(req) {
  const h = (req && req.headers) || {};
  const vercel = firstIp(h["x-vercel-forwarded-for"]);
  if (vercel) return vercel;
  const real = firstIp(h["x-real-ip"]);
  if (real) return real;
  const xff = h["x-forwarded-for"];
  if (xff) {
    const parts = String(xff).split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length) return normalizeIp(parts[parts.length - 1]);
  }
  return normalizeIp((req && req.socket && req.socket.remoteAddress) || "") || "unknown";
}
function bearerToken(req) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers["authorization"] || "");
  return m ? m[1] : null;
}

// Keyed hash of the bucket identity so rate_limits never stores a raw IP or user
// id. The service-role key (server-side only, always present here) is the HMAC
// key, so the mapping is not brute-forceable from the stored value.
function bucketId(service, kind, value) {
  const mac = createHmac("sha256", service).update(`${kind}:${value}`).digest("hex").slice(0, 32);
  return `enq:${kind}:${mac}`;
}

// Durable, cross-instance rate check via the rl_hit() RPC. Returns one of
// "allow" | "deny" | "error". FAILS CLOSED: a transport failure, timeout, non-2xx
// response or non-boolean body all resolve to "error", which the handler turns
// into a generic 503 with no further processing.
async function rlCheck(url, service, bucket, limit, windowSecs) {
  try {
    const r = await fetchT(`${url}/rest/v1/rpc/rl_hit`, {
      method: "POST",
      headers: {
        apikey: service,
        Authorization: `Bearer ${service}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_bucket: bucket, p_limit: limit, p_window_secs: windowSecs }),
    });
    if (!r.ok) return "error";
    const val = await r.json();
    if (typeof val !== "boolean") return "error";
    return val ? "allow" : "deny";
  } catch {
    return "error";
  }
}
async function fetchT(url, opts = {}) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), UPSTREAM_TIMEOUT_MS);
  try { return await fetch(url, { ...opts, signal: c.signal }); }
  finally { clearTimeout(t); }
}
function cfg() {
  return {
    url: process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || "",
    anon: process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || "",
    service: process.env.SUPABASE_SERVICE_ROLE_KEY || "",
  };
}

// Verify the caller's Supabase session token and return the verified {id, email}.
async function verifySession(token, url, anon) {
  if (!token) return null;
  try {
    const r = await fetchT(`${url}/auth/v1/user`, {
      headers: { Authorization: `Bearer ${token}`, apikey: anon },
    });
    if (!r.ok) return null;
    const u = await r.json();
    if (!u || !u.id || !u.email) return null;
    return { id: u.id, email: u.email };
  } catch {
    return null;
  }
}

// Validate + normalise the client-supplied fields (never email/user_id).
export function validateEnquiry(body = {}) {
  const errors = [];
  const plan = typeof body.plan === "string" ? body.plan.trim().toLowerCase() : "";
  if (!PLANS.has(plan)) errors.push("plan");
  const str = (v, max) => {
    if (v == null) return null;
    if (typeof v !== "string") { errors.push("type"); return null; }
    const t = v.trim();
    if (t.length > max) { errors.push("length"); return null; }
    return t || null;
  };
  const organisation = str(body.organisation, LIMITS.organisation);
  const role_use_case = str(body.role_use_case, LIMITS.role_use_case);
  const message = str(body.message, LIMITS.message);
  let source = typeof body.source === "string" ? body.source.trim().toLowerCase() : "";
  if (!SOURCES.has(source)) source = "other";
  return { ok: errors.length === 0, errors, value: { plan, organisation, role_use_case, message, source } };
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "authorization, content-type");
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "method not allowed" });

  const { url, anon, service } = cfg();
  if (!url || !anon || !service) {
    // Not configured on this deployment: report cleanly, never pretend success.
    return res.status(503).json({ configured: false, error: "Enquiries are not enabled on this host yet." });
  }

  // A request with no bearer token is rejected cheaply, before any upstream call,
  // so the endpoint cannot be used as an unauthenticated amplifier.
  const token = bearerToken(req);
  if (!token) {
    return res.status(401).json({ authRequired: true, error: "Please sign in to submit this request." });
  }

  // Durable per-IP limit (shared across instances) before spending an auth call.
  // Fail closed: if the limiter is unavailable we do not authenticate or insert.
  const ipCheck = await rlCheck(url, service, bucketId(service, "ip", clientIp(req)), IP_MAX, IP_WINDOW_SECS);
  if (ipCheck === "error") {
    res.setHeader("Retry-After", "30");
    return res.status(503).json({ error: "Service temporarily unavailable. Please try again shortly." });
  }
  if (ipCheck === "deny") {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many requests. Please try again shortly." });
  }

  const user = await verifySession(token, url, anon);
  if (!user) {
    return res.status(401).json({ authRequired: true, error: "Please sign in to submit this request." });
  }

  // Durable per-user limit: caps how many enquiries one verified account can file.
  const userCheck = await rlCheck(url, service, bucketId(service, "user", user.id), USER_MAX, USER_WINDOW_SECS);
  if (userCheck === "error") {
    res.setHeader("Retry-After", "30");
    return res.status(503).json({ error: "Service temporarily unavailable. Please try again shortly." });
  }
  if (userCheck === "deny") {
    res.setHeader("Retry-After", "3600");
    return res.status(429).json({ error: "Too many requests. Please try again later." });
  }

  const body = typeof req.body === "object" && req.body ? req.body : safeParse(req.body);
  const v = validateEnquiry(body);
  if (!v.ok) {
    return res.status(400).json({ error: "Please check the form and try again." });
  }

  // Persist with the service role (bypasses RLS); email + user_id come from the
  // verified session, never from the client body.
  try {
    const r = await fetchT(`${url}/rest/v1/plan_enquiries`, {
      method: "POST",
      headers: {
        apikey: service,
        Authorization: `Bearer ${service}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        user_id: user.id,
        email: user.email,
        plan: v.value.plan,
        organisation: v.value.organisation,
        role_use_case: v.value.role_use_case,
        message: v.value.message,
        source: v.value.source,
      }),
    });
    if (r.status !== 201 && r.status !== 200 && r.status !== 204) {
      console.error("enquiry insert failed:", r.status);
      return res.status(502).json({ error: "Could not save your request. Please try again." });
    }
    return res.status(201).json({ ok: true });
  } catch (e) {
    console.error("enquiry insert error:", (e && e.message) || e);
    return res.status(502).json({ error: "Could not save your request. Please try again." });
  }
}

function safeParse(x) {
  if (typeof x !== "string") return {};
  try { return JSON.parse(x); } catch { return {}; }
}
