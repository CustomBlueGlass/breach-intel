/* STIX 2.1 feed of the breach ledger, for pulling the data straight into a TIP
   (OpenCTI, MISP, Anomali, a TAXII client). Read-only, keyless, served from the
   public ledger view via the same anon key the site uses.

   Each breach becomes a STIX identity (the victim organisation), with the
   incident facts carried on x_ custom properties, plus a deduped intrusion-set
   per named threat actor and a "targets" relationship dated to the incident.
   Unknown x_ properties are ignored by any conformant tool, so the bundle stays
   importable while still carrying the extra breach metadata.

   Query params:
     limit=<n>     max breaches (default 500, capped 2000)
     group=<name>  filter to one ransomware group (case-insensitive)
     industry=<x>  filter to one industry
     since=<date>  only breaches disclosed on/after YYYY-MM-DD

   The response is a single STIX bundle. A TAXII 2.1 collection wrapper can sit
   in front of this later; a plain bundle already imports into every major TIP. */

const SUPABASE_URL = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;

const uuid = () =>
  (globalThis.crypto && globalThis.crypto.randomUUID)
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

// PostgREST query against the public ledger view, mirroring the site's filters.
async function fetchLedger({ limit, group, industry, since }) {
  const params = new URLSearchParams();
  params.set(
    "select",
    "id,canonical_name,industry,country,region_state,ransomware_group," +
      "incident_date,disclosed_date,records_affected_est,severity,source_count,data_flags"
  );
  params.set("order", "disclosed_date.desc.nullslast");
  params.set("limit", String(limit));
  if (group) params.append("ransomware_group", `ilike.${group}`);
  if (industry) params.append("industry", `eq.${industry}`);
  if (since) params.append("disclosed_date", `gte.${since}`);

  const url = `${SUPABASE_URL}/rest/v1/mv_breach_ledger?${params.toString()}`;
  const r = await fetch(url, {
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${ANON_KEY}`, Accept: "application/json" },
  });
  if (!r.ok) throw new Error(`ledger query failed: ${r.status}`);
  return r.json();
}

function buildBundle(rows) {
  const now = new Date().toISOString();
  const objects = [];

  // TLP:CLEAR: the ledger is built from public sources, so the feed is open.
  const tlp = {
    type: "marking-definition",
    spec_version: "2.1",
    id: "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    created: "2022-10-01T00:00:00.000Z",
    name: "TLP:CLEAR",
    definition_type: "tlp",
    definition: { tlp: "clear" },
  };
  objects.push(tlp);
  const marking = [tlp.id];

  const actorIds = new Map(); // group(lower) -> intrusion-set id, deduped

  for (const b of rows) {
    const identId = `identity--${uuid()}`;
    const descBits = [];
    if (b.records_affected_est != null) descBits.push(`~${b.records_affected_est} records`);
    if (b.disclosed_date) descBits.push(`disclosed ${b.disclosed_date}`);
    if (b.severity) descBits.push(`severity ${b.severity}`);

    objects.push({
      type: "identity",
      spec_version: "2.1",
      id: identId,
      created: now,
      modified: now,
      name: b.canonical_name,
      description: descBits.length ? `Data breach: ${descBits.join(", ")}.` : "Recorded data breach.",
      identity_class: "organization",
      sectors: b.industry ? [b.industry] : undefined,
      object_marking_refs: marking,
      // Breach facts as custom properties (conformant tools ignore unknown x_).
      x_breach_id: b.id,
      x_incident_date: b.incident_date || undefined,
      x_disclosed_date: b.disclosed_date || undefined,
      x_records_affected_est: b.records_affected_est ?? undefined,
      x_severity: b.severity || undefined,
      x_source_count: b.source_count ?? undefined,
      x_country: b.country || undefined,
      x_region: b.region_state || undefined,
    });

    if (b.ransomware_group) {
      const key = b.ransomware_group.toLowerCase();
      let actorId = actorIds.get(key);
      if (!actorId) {
        actorId = `intrusion-set--${uuid()}`;
        actorIds.set(key, actorId);
        objects.push({
          type: "intrusion-set",
          spec_version: "2.1",
          id: actorId,
          created: now,
          modified: now,
          name: b.ransomware_group,
          resource_level: "group",
          primary_motivation: "financial-gain",
          object_marking_refs: marking,
        });
      }
      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: `relationship--${uuid()}`,
        created: now,
        modified: now,
        relationship_type: "targets",
        source_ref: actorId,
        target_ref: identId,
        start_time: b.incident_date ? `${b.incident_date}T00:00:00Z` : undefined,
        object_marking_refs: marking,
      });
    }
  }

  return { type: "bundle", id: `bundle--${uuid()}`, objects };
}

export default async function handler(req, res) {
  // CORS + cache so a TIP or TAXII client can pull it directly.
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ error: "method not allowed" });

  if (!SUPABASE_URL || !ANON_KEY) {
    return res.status(500).json({ error: "feed not configured: missing Supabase env vars" });
  }

  const q = req.query || {};
  const limit = Math.min(Math.max(parseInt(q.limit, 10) || 500, 1), 2000);
  const group = typeof q.group === "string" ? q.group.trim() : "";
  const industry = typeof q.industry === "string" ? q.industry.trim() : "";
  const since = typeof q.since === "string" && /^\d{4}-\d{2}-\d{2}$/.test(q.since) ? q.since : "";

  try {
    const rows = await fetchLedger({ limit, group, industry, since });
    const bundle = buildBundle(rows);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=1800, s-maxage=1800");
    res.setHeader("Content-Disposition", 'inline; filename="breach-ledger.stix.json"');
    return res.status(200).json(bundle);
  } catch (e) {
    return res.status(502).json({ error: String((e && e.message) || e) });
  }
}
