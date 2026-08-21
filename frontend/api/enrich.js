// Vercel serverless function: keyless-first indicator enrichment. Detects the
// indicator type and enriches it from free, no-key sources by default:
//   - IPv4    -> Shodan InternetDB (ports, tags, CVEs, hostnames); + AbuseIPDB if keyed
//   - domain  -> Google DNS-over-HTTPS (A/AAAA), then InternetDB on the first IP
//   - hash    -> CIRCL hashlookup (is this a known file? trust + source)
//   - CVE     -> FIRST EPSS (exploit-prediction score + percentile)
// ESM + global fetch, zero dependencies.
//
// Abuse controls (WP-002): GET/OPTIONS only; strict, length-bounded input
// validated before any upstream call; private/reserved IP targets rejected
// (SSRF/internal-recon hardening); bounded upstream timeouts; a best-effort
// per-instance rate limit; generic upstream errors. See docs/security/.

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const CVE = /^cve-\d{4}-\d{4,7}$/i;
const HASHES = { sha256: /^[a-f0-9]{64}$/i, sha1: /^[a-f0-9]{40}$/i, md5: /^[a-f0-9]{32}$/i };

const MAX_INDICATOR_LEN = 100;   // longest valid indicator (sha256=64, domains<=100)
const UPSTREAM_TIMEOUT_MS = 6000;
const RATE_LIMIT = 60;           // requests per window per client (best-effort)
const RATE_WINDOW_MS = 60000;

// Reject private, loopback, link-local, CGNAT, multicast and reserved IPv4 so
// the enrichment providers are never used to probe internal/edge addresses.
function isPublicIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 169 && b === 254) return false;            // link-local
  if (a === 172 && b >= 16 && b <= 31) return false;   // 172.16/12
  if (a === 192 && b === 168) return false;            // 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return false;  // CGNAT 100.64/10
  if (a === 192 && b === 0) return false;              // 192.0.0/24 etc.
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a >= 224) return false;                          // multicast + reserved + 255.*
  return true;
}

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

async function internetdb(ip) {
  const r = await fetchT("https://internetdb.shodan.io/" + ip, { headers: { Accept: "application/json" } });
  if (r.status === 404) return { ip, found: false, ports: [], vulns: [], tags: [], hostnames: [], cpes: [] };
  if (!r.ok) throw new Error("InternetDB unavailable");
  const b = await r.json();
  return { ip, found: true, ports: b.ports || [], vulns: b.vulns || [], tags: b.tags || [], hostnames: b.hostnames || [], cpes: b.cpes || [] };
}

async function resolve(name, type) {
  const r = await fetchT("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type, { headers: { Accept: "application/dns-json" } });
  if (!r.ok) throw new Error("DNS unavailable");
  const b = await r.json();
  const want = type === "A" ? 1 : 28;
  return (b.Answer || []).filter((a) => a.type === want).map((a) => a.data);
}

async function abuseipdb(ip, key) {
  const r = await fetchT("https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + ip, { headers: { Key: key, Accept: "application/json" } });
  if (!r.ok) throw new Error("AbuseIPDB unavailable");
  const d = (await r.json()).data || {};
  return { abuseConfidenceScore: d.abuseConfidenceScore, countryCode: d.countryCode, isp: d.isp, domain: d.domain, totalReports: d.totalReports };
}

async function circlHash(algo, hash) {
  const r = await fetchT("https://hashlookup.circl.lu/lookup/" + algo + "/" + hash, { headers: { Accept: "application/json" } });
  if (r.status === 404) return { found: false };
  if (!r.ok) throw new Error("hashlookup unavailable");
  const b = await r.json();
  return {
    found: true,
    fileName: b.FileName || null,
    source: b.source || null,
    trust: b["hashlookup:trust"] != null ? b["hashlookup:trust"] : null,
    knownMalicious: Boolean(b.KnownMalicious),
  };
}

async function epss(cve) {
  const r = await fetchT("https://api.first.org/data/v1/epss?cve=" + encodeURIComponent(cve.toUpperCase()), { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error("EPSS unavailable");
  const row = ((await r.json()).data || [])[0];
  return row ? { epss: Number(row.epss), percentile: Number(row.percentile), date: row.date } : null;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ error: "method not allowed" });

  if (rateLimited(clientIp(req))) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "rate limit exceeded, try again shortly" });
  }

  const raw = String((req.query && req.query.indicator) || "").trim();
  if (!raw || raw.length > MAX_INDICATOR_LEN) {
    return res.status(400).json({ error: "Enter an IPv4, domain, file hash (MD5/SHA1/SHA256), or CVE id." });
  }
  const q = raw.toLowerCase();

  let type = null;
  if (IPV4.test(q)) type = "ip";
  else if (CVE.test(q)) type = "cve";
  else if (HASHES.sha256.test(q)) type = "sha256";
  else if (HASHES.sha1.test(q)) type = "sha1";
  else if (HASHES.md5.test(q)) type = "md5";
  else if (DOMAIN.test(q)) type = "domain";
  if (!type) {
    return res.status(400).json({ error: "Enter an IPv4, domain, file hash (MD5/SHA1/SHA256), or CVE id." });
  }
  if (type === "ip" && !isPublicIPv4(q)) {
    return res.status(400).json({ error: "Private, loopback or reserved addresses are not supported." });
  }

  const isHash = type === "md5" || type === "sha1" || type === "sha256";
  const out = { indicator: q, type: isHash ? "hash" : type };
  const errors = [];
  const fail = (e) => { errors.push(String(e && e.message ? e.message : e)); return null; };

  if (type === "ip") {
    out.internetdb = await internetdb(q).catch(fail);
    if (process.env.ABUSEIPDB_API_KEY) out.abuseipdb = await abuseipdb(q, process.env.ABUSEIPDB_API_KEY).catch(fail);
  } else if (type === "domain") {
    const [a, aaaa] = await Promise.all([resolve(q, "A").catch(() => []), resolve(q, "AAAA").catch(() => [])]);
    out.dns = { a, aaaa };
    // Only enrich a resolved address if it is a public one (SSRF/internal recon guard).
    if (a[0] && isPublicIPv4(a[0])) out.internetdb = await internetdb(a[0]).catch(fail);
  } else if (isHash) {
    out.algo = type;
    out.hashlookup = await circlHash(type, q).catch(fail);
  } else if (type === "cve") {
    out.epss = await epss(q).catch(fail);
  }

  out.errors = errors;
  res.setHeader("Cache-Control", "public, max-age=300");
  return res.status(200).json(out);
}
