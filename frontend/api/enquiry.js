// Vercel serverless function: demand capture for the paid plans (Pro waitlist,
// Business access request, Enterprise/sales contact). Monetisation Phase 1.
//
// Security model:
//   - POST only (+ OPTIONS). A valid Supabase session (Bearer access token) is
//     required, so the email is verified and we never trust a client-supplied
//     email or user id.
//   - Input is strictly validated and length-bounded; per-instance rate limited.
//   - Rows are written with the server-side SERVICE ROLE key into the fully
//     private plan_enquiries table (RLS on, no anon/authenticated grants), so the
//     submissions are never exposed through the anonymous/authenticated Data API.
//   - Success is reported ONLY when the insert actually persisted (201).
//   - No secret is ever sent to the browser; the service-role key is read from
//     the server environment only. See docs / PR for the required variables.

const PLANS = new Set(["pro", "business", "enterprise"]);
const SOURCES = new Set(["pricing_page", "dashboard", "workspace", "other"]);
const LIMITS = { organisation: 200, role_use_case: 200, message: 2000, source: 60 };
const UPSTREAM_TIMEOUT_MS = 8000;
const RATE_LIMIT = 8; // submissions per window per client
const RATE_WINDOW_MS = 60000;

const HITS = new Map();
function rateLimited(key) {
  const now = Date.now();
  const arr = (HITS.get(key) || []).filter((t) => now - t < RATE_WINDOW_MS);
  arr.push(now);
  HITS.set(key, arr);
  if (HITS.size > 5000) {
    for (const [k, v] of HITS) if (!v.some((t) => now - t < RATE_WINDOW_MS)) HITS.delete(k);
  }
  return arr.length > RATE_LIMIT;
}
function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "unknown";
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

// Verify the caller's Supabase session and return the verified {id, email}.
async function verifySession(req, url, anon) {
  const auth = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return null;
  try {
    const r = await fetchT(`${url}/auth/v1/user`, {
      headers: { Authorization: `Bearer ${m[1]}`, apikey: anon },
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

  if (rateLimited(clientIp(req))) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many requests. Please try again shortly." });
  }

  const user = await verifySession(req, url, anon);
  if (!user) {
    return res.status(401).json({ authRequired: true, error: "Please sign in to submit this request." });
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
