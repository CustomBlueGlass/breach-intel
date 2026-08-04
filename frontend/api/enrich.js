// Vercel serverless function: keyless-first indicator enrichment for an IPv4
// address or a domain. Uses only free, no-key sources by default:
//   - Shodan InternetDB (https://internetdb.shodan.io/<ip>): open ports, tags,
//     CVEs, hostnames, CPEs for an IP. No key.
//   - Google DNS-over-HTTPS (https://dns.google/resolve): A / AAAA records. No key.
// Optionally boosted when ABUSEIPDB_API_KEY is set (IP abuse score). ESM +
// global fetch, zero dependencies. This is the server side of the roadmap's
// Enrichment API (P3); the dossier's launchpad still handles keyless deep-links.

const IPV4 =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const DOMAIN =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

async function internetdb(ip) {
  const r = await fetch("https://internetdb.shodan.io/" + ip, {
    headers: { Accept: "application/json" },
  });
  if (r.status === 404) {
    return { ip, found: false, ports: [], vulns: [], tags: [], hostnames: [], cpes: [] };
  }
  if (!r.ok) throw new Error("InternetDB HTTP " + r.status);
  const b = await r.json();
  return {
    ip,
    found: true,
    ports: b.ports || [],
    vulns: b.vulns || [],
    tags: b.tags || [],
    hostnames: b.hostnames || [],
    cpes: b.cpes || [],
  };
}

async function resolve(name, type) {
  const r = await fetch(
    "https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type,
    { headers: { Accept: "application/dns-json" } }
  );
  if (!r.ok) throw new Error("DNS HTTP " + r.status);
  const b = await r.json();
  const want = type === "A" ? 1 : 28;
  return (b.Answer || []).filter((a) => a.type === want).map((a) => a.data);
}

async function abuseipdb(ip, key) {
  const r = await fetch(
    "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + ip,
    { headers: { Key: key, Accept: "application/json" } }
  );
  if (!r.ok) throw new Error("AbuseIPDB HTTP " + r.status);
  const d = (await r.json()).data || {};
  return {
    abuseConfidenceScore: d.abuseConfidenceScore,
    countryCode: d.countryCode,
    isp: d.isp,
    domain: d.domain,
    totalReports: d.totalReports,
  };
}

export default async function handler(req, res) {
  const q = String((req.query && req.query.indicator) || "").trim().toLowerCase();
  const isIp = IPV4.test(q);
  const isDomain = !isIp && DOMAIN.test(q);
  if (!isIp && !isDomain) {
    return res.status(400).json({ error: "Enter an IPv4 address or a domain." });
  }

  const out = { indicator: q, type: isIp ? "ip" : "domain" };
  const errors = [];
  const fail = (e) => {
    errors.push(String(e && e.message ? e.message : e));
    return null;
  };

  if (isIp) {
    out.internetdb = await internetdb(q).catch(fail);
    if (process.env.ABUSEIPDB_API_KEY) {
      out.abuseipdb = await abuseipdb(q, process.env.ABUSEIPDB_API_KEY).catch(fail);
    }
  } else {
    const [a, aaaa] = await Promise.all([
      resolve(q, "A").catch(() => []),
      resolve(q, "AAAA").catch(() => []),
    ]);
    out.dns = { a, aaaa };
    if (a[0]) out.internetdb = await internetdb(a[0]).catch(fail);
  }

  out.errors = errors;
  res.setHeader("Cache-Control", "public, max-age=300");
  return res.status(200).json(out);
}
