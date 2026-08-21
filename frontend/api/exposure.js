// Vercel serverless function: on-demand, metadata-only credential-exposure
// lookup for a COMPANY DOMAIN. It returns breach NAMES and match COUNTS only,
// and NEVER a credential field (email, password, hash). API keys are server-side
// environment variables and are never exposed to the browser.
//
// Abuse controls (WP-002): this endpoint can consume PAID provider quotas
// (BreachDirectory / DeHashed), so anonymous automated consumption is blocked.
// A valid Supabase session (Bearer access token) is required before any paid
// provider is called; there is also a strict per-instance rate limit, bounded
// input, upstream timeouts and generic upstream errors. GET/OPTIONS only.
// See docs/security/public-data-contract.md and docs/security/secret-inventory.md.

const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const MAX_DOMAIN_LEN = 100;
const UPSTREAM_TIMEOUT_MS = 8000;
const RATE_LIMIT = 10;         // paid-provider lookups per window per client
const RATE_WINDOW_MS = 60000;

const HITS = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (HITS.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  arr.push(now);
  HITS.set(ip, arr);
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
  try {
    return await fetch(url, { ...opts, signal: c.signal });
  } finally {
    clearTimeout(t);
  }
}

// Verify the caller holds a valid Supabase session by exchanging the bearer
// access token at the Auth API. No new infrastructure and no service-role key:
// uses the same public URL + anon key the site already ships.
async function hasValidSession(req) {
  const auth = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return false;
  const url = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
  const anon = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
  if (!url || !anon) return false;
  try {
    const r = await fetchT(`${url}/auth/v1/user`, {
      headers: { Authorization: `Bearer ${m[1]}`, apikey: anon },
    });
    return r.ok;
  } catch {
    return false;
  }
}

async function viaBreachDirectory(domain, key) {
  const url =
    "https://breachdirectory.p.rapidapi.com/?func=auto&term=" + encodeURIComponent(domain);
  const r = await fetchT(url, {
    headers: { "X-RapidAPI-Key": key, "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com" },
  });
  if (!r.ok) throw new Error("BreachDirectory unavailable");
  const body = await r.json();
  const names = new Set();
  for (const entry of body.result || []) {
    for (const s of entry.sources || []) {
      if (typeof s === "string") names.add(s);
      else if (s && s.name) names.add(s.name);
    }
  }
  return { source: "BreachDirectory", matches: (body.result || []).length, breaches: [...names].sort() };
}

async function viaDeHashed(domain, key) {
  const url = "https://api.dehashed.com/search?query=" + encodeURIComponent("domain:" + domain);
  const r = await fetchT(url, {
    headers: { Authorization: "Bearer " + key, Accept: "application/json" },
  });
  if (!r.ok) throw new Error("DeHashed unavailable");
  const body = await r.json();
  // Keep ONLY the breach/database name; discard every per-record credential field.
  const counts = {};
  for (const e of body.entries || []) {
    const n = e.database_name;
    if (n) counts[n] = (counts[n] || 0) + 1;
  }
  return { source: "DeHashed", matches: (body.entries || []).length, breaches: Object.keys(counts).sort() };
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ error: "method not allowed" });

  const keys = {
    breachdirectory: process.env.BREACHDIRECTORY_API_KEY,
    dehashed: process.env.DEHASHED_API_KEY,
  };
  const configured = Boolean(keys.breachdirectory || keys.dehashed);
  if (!configured) {
    return res.status(200).json({ configured: false });
  }

  // Bound abuse before any work: per-instance rate limit, then a valid session.
  if (rateLimited(clientIp(req))) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ configured: true, error: "rate limit exceeded, try again shortly" });
  }
  if (!(await hasValidSession(req))) {
    return res
      .status(401)
      .json({ configured: true, authRequired: true, error: "Sign in to run a credential-exposure check." });
  }

  const domain = String((req.query && req.query.domain) || "").trim().toLowerCase();
  if (domain.length > MAX_DOMAIN_LEN || !DOMAIN_RE.test(domain)) {
    return res.status(400).json({ configured: true, error: "Enter a valid domain, e.g. example.com" });
  }

  const tasks = [];
  if (keys.breachdirectory) tasks.push(viaBreachDirectory(domain, keys.breachdirectory));
  if (keys.dehashed) tasks.push(viaDeHashed(domain, keys.dehashed));

  const settled = await Promise.allSettled(tasks);
  const results = [];
  const errors = [];
  for (const s of settled) {
    if (s.status === "fulfilled") results.push(s.value);
    else errors.push(String(s.reason && s.reason.message ? s.reason.message : "provider unavailable"));
  }

  return res.status(200).json({ configured: true, domain, results, errors });
}
