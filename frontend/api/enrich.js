// Vercel serverless function: keyless-first indicator enrichment. Detects the
// indicator type and enriches it from free, no-key sources by default:
//   - IPv4    -> Shodan InternetDB (ports, tags, CVEs, hostnames); + AbuseIPDB if keyed
//   - domain  -> Google DNS-over-HTTPS (A/AAAA), then InternetDB on the first IP
//   - hash    -> CIRCL hashlookup (is this a known file? trust + source)
//   - CVE     -> FIRST EPSS (exploit-prediction score + percentile)
// ESM + global fetch, zero dependencies. This is the server side of the
// roadmap's Enrichment API (P3).

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const CVE = /^cve-\d{4}-\d{4,7}$/i;
const HASHES = { sha256: /^[a-f0-9]{64}$/i, sha1: /^[a-f0-9]{40}$/i, md5: /^[a-f0-9]{32}$/i };

async function internetdb(ip) {
  const r = await fetch("https://internetdb.shodan.io/" + ip, { headers: { Accept: "application/json" } });
  if (r.status === 404) return { ip, found: false, ports: [], vulns: [], tags: [], hostnames: [], cpes: [] };
  if (!r.ok) throw new Error("InternetDB HTTP " + r.status);
  const b = await r.json();
  return { ip, found: true, ports: b.ports || [], vulns: b.vulns || [], tags: b.tags || [], hostnames: b.hostnames || [], cpes: b.cpes || [] };
}

async function resolve(name, type) {
  const r = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type, { headers: { Accept: "application/dns-json" } });
  if (!r.ok) throw new Error("DNS HTTP " + r.status);
  const b = await r.json();
  const want = type === "A" ? 1 : 28;
  return (b.Answer || []).filter((a) => a.type === want).map((a) => a.data);
}

async function abuseipdb(ip, key) {
  const r = await fetch("https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + ip, { headers: { Key: key, Accept: "application/json" } });
  if (!r.ok) throw new Error("AbuseIPDB HTTP " + r.status);
  const d = (await r.json()).data || {};
  return { abuseConfidenceScore: d.abuseConfidenceScore, countryCode: d.countryCode, isp: d.isp, domain: d.domain, totalReports: d.totalReports };
}

async function circlHash(algo, hash) {
  const r = await fetch("https://hashlookup.circl.lu/lookup/" + algo + "/" + hash, { headers: { Accept: "application/json" } });
  if (r.status === 404) return { found: false };
  if (!r.ok) throw new Error("hashlookup HTTP " + r.status);
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
  const r = await fetch("https://api.first.org/data/v1/epss?cve=" + encodeURIComponent(cve.toUpperCase()), { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error("EPSS HTTP " + r.status);
  const row = ((await r.json()).data || [])[0];
  return row ? { epss: Number(row.epss), percentile: Number(row.percentile), date: row.date } : null;
}

export default async function handler(req, res) {
  const q = String((req.query && req.query.indicator) || "").trim().toLowerCase();
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
    if (a[0]) out.internetdb = await internetdb(a[0]).catch(fail);
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
