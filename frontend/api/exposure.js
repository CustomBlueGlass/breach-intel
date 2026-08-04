// Vercel serverless function: on-demand, metadata-only credential-exposure
// lookup for a COMPANY DOMAIN. It returns breach NAMES and match COUNTS only,
// and NEVER a credential field (email, password, hash). API keys are server-side
// environment variables and are never exposed to the browser.
//
// Enable by setting one or both of these in the Vercel project's Environment
// Variables (Production): BREACHDIRECTORY_API_KEY (RapidAPI), DEHASHED_API_KEY.
// With no key set the endpoint reports { configured: false } and the UI explains
// how to turn it on. ESM (the frontend is "type":"module") + global fetch, so it
// runs on Vercel's Node runtime with zero dependencies.

const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

async function viaBreachDirectory(domain, key) {
  const url =
    "https://breachdirectory.p.rapidapi.com/?func=auto&term=" +
    encodeURIComponent(domain);
  const r = await fetch(url, {
    headers: {
      "X-RapidAPI-Key": key,
      "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
    },
  });
  if (!r.ok) throw new Error("BreachDirectory HTTP " + r.status);
  const body = await r.json();
  const names = new Set();
  for (const entry of body.result || []) {
    for (const s of entry.sources || []) {
      if (typeof s === "string") names.add(s);
      else if (s && s.name) names.add(s.name);
    }
  }
  return {
    source: "BreachDirectory",
    matches: (body.result || []).length,
    breaches: [...names].sort(),
  };
}

async function viaDeHashed(domain, key) {
  const url =
    "https://api.dehashed.com/search?query=" +
    encodeURIComponent("domain:" + domain);
  const r = await fetch(url, {
    headers: { Authorization: "Bearer " + key, Accept: "application/json" },
  });
  if (!r.ok) throw new Error("DeHashed HTTP " + r.status);
  const body = await r.json();
  // Keep ONLY the breach/database name; discard every per-record credential field.
  const counts = {};
  for (const e of body.entries || []) {
    const n = e.database_name;
    if (n) counts[n] = (counts[n] || 0) + 1;
  }
  return {
    source: "DeHashed",
    matches: (body.entries || []).length,
    breaches: Object.keys(counts).sort(),
  };
}

export default async function handler(req, res) {
  const keys = {
    breachdirectory: process.env.BREACHDIRECTORY_API_KEY,
    dehashed: process.env.DEHASHED_API_KEY,
  };
  const configured = Boolean(keys.breachdirectory || keys.dehashed);
  if (!configured) {
    return res.status(200).json({ configured: false });
  }

  const domain = String((req.query && req.query.domain) || "")
    .trim()
    .toLowerCase();
  if (!DOMAIN_RE.test(domain)) {
    return res
      .status(400)
      .json({ configured: true, error: "Enter a valid domain, e.g. example.com" });
  }

  const tasks = [];
  if (keys.breachdirectory)
    tasks.push(viaBreachDirectory(domain, keys.breachdirectory));
  if (keys.dehashed) tasks.push(viaDeHashed(domain, keys.dehashed));

  const settled = await Promise.allSettled(tasks);
  const results = [];
  const errors = [];
  for (const s of settled) {
    if (s.status === "fulfilled") results.push(s.value);
    else errors.push(String(s.reason && s.reason.message ? s.reason.message : s.reason));
  }

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ configured: true, domain, results, errors });
}
