import { supabase } from './supabaseClient';

const PAGE_SIZE = 25; // spec: 25–50 records per page, never the full dataset

export async function fetchStats() {
  const { data, error } = await supabase.from('public_platform_stats').select('*').single();
  if (error) throw error;
  return data;
}

export async function fetchRecentIntake(limit = 6) {
  const { data, error } = await supabase
    .from('public_breach_ledger')
    .select('id, canonical_name, disclosed_date')
    .order('disclosed_date', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data;
}

export async function fetchRansomwareGroupOptions() {
  const { data, error } = await supabase
    .from('public_top_ransomware_groups')
    .select('ransomware_group')
    .order('ransomware_group');
  if (error) throw error;
  return data.map((r) => r.ransomware_group);
}

/**
 * Server-side filtered/sorted/paginated breach list — this is the one query
 * that matters for "never load the full dataset into the browser". Postgrest
 * .range() maps to SQL LIMIT/OFFSET; { count: 'exact' } gets the total
 * without a second round-trip.
 */
// PostgREST parses the .or() string itself, so commas, parentheses and stars
// in a raw search term would break out of the ilike into other filter syntax.
// Strip those metacharacters (same guard as searchLedger) before interpolating.
function sanitizeTerm(q) {
  return String(q).trim().replace(/[,()*]/g, ' ');
}

function applyLedgerFilters(query, filters) {
  if (filters.q) {
    const term = sanitizeTerm(filters.q);
    query = query.or(`canonical_name.ilike.%${term}%,ransomware_group.ilike.%${term}%`);
  }
  if (filters.industry) query = query.eq('industry', filters.industry);
  // ilike without wildcards = case-insensitive exact match, so a dropdown
  // value of "LockBit" still matches rows stored as "lockbit" across sources.
  if (filters.group) query = query.ilike('ransomware_group', filters.group);
  // Attribution replaces the old confirmed/disputed status filter, which never
  // changed results (every breach is 'confirmed'). This segments the data that
  // actually varies: ransomware-attributed victims vs regulator/HIBP entries.
  if (filters.attribution === 'attributed') query = query.not('ransomware_group', 'is', null);
  else if (filters.attribution === 'unattributed') query = query.is('ransomware_group', null);
  else if (filters.attribution === 'disputed') query = query.eq('status', 'disputed');
  if (filters.dateFrom) query = query.gte('disclosed_date', filters.dateFrom);
  if (filters.dateTo) query = query.lte('disclosed_date', filters.dateTo);
  return query;
}

export async function fetchBreaches({ filters, sortBy, sortDir, page, pageSize = PAGE_SIZE }) {
  let query = supabase.from('public_breach_ledger').select('*', { count: 'exact' });
  query = applyLedgerFilters(query, filters);

  const from = (page - 1) * pageSize;
  const to = from + pageSize - 1;

  const { data, error, count } = await query
    .order(sortBy, { ascending: sortDir === 'asc', nullsFirst: false })
    .range(from, to);

  if (error) throw error;
  return { items: data, total: count ?? 0 };
}

// Export tool: same filters as the on-screen ledger, capped at 1000 rows so
// a researcher can pull the current view into CSV/JSON for their own tooling.
export async function fetchBreachesForExport({ filters, sortBy, sortDir, max = 1000 }) {
  let query = supabase.from('public_breach_ledger').select('*');
  query = applyLedgerFilters(query, filters);
  const { data, error } = await query
    .order(sortBy, { ascending: sortDir === 'asc', nullsFirst: false })
    .limit(max);
  if (error) throw error;
  return data || [];
}

// Command-palette search: a few company/actor hits for jump-to navigation.
export async function searchLedger(q, limit = 8) {
  if (!q || !q.trim()) return [];
  const term = q.trim().replace(/[,()*]/g, ' ');
  const { data, error } = await supabase
    .from('public_breach_ledger')
    .select('id, canonical_name, ransomware_group, industry, disclosed_date, incident_date')
    .or(`canonical_name.ilike.%${term}%,ransomware_group.ilike.%${term}%`)
    .limit(limit);
  if (error) throw error;
  return data || [];
}

// Field-level provenance and conflict surfacing. Every breach field is derived
// from the linked source records, and each source row keeps its own asserted
// value, so we can show — read-time, no extra storage — which independent
// sources set a field and where they disagree. The ledger value stays the
// platform's reconciled figure (earliest date, largest verified count, union
// of data types); this just exposes the underlying agreement.
function buildProvenance(breach, sources) {
  const rows = sources || [];
  const clean = (v) => (v === null || v === undefined || v === '' ? null : v);
  const meta = (s) => ({
    name: s.source_name || 'source',
    category: s.source_category || null,
    url: s.source_record_url || null,
    published_at: s.source_published_at || null,
  });
  const out = [];

  const field = (id, label, current, getVal, opts = {}) => {
    const getKey = opts.key || ((v) => String(v).trim().toLowerCase());
    const entries = [];
    for (const s of rows) {
      const v = clean(getVal(s));
      if (v === null || (Array.isArray(v) && v.length === 0)) continue;
      entries.push({ ...meta(s), value: v, key: getKey(v) });
    }
    if (entries.length === 0) return;
    const conflict = opts.conflict
      ? opts.conflict(entries)
      : new Set(entries.map((e) => e.key)).size > 1;
    out.push({ id, label, current, conflict, sources: entries });
  };

  field('ransomware_group', 'Threat actor', breach.ransomware_group,
    (s) => s.ransomware_group_raw || s.ransomware_group_norm,
    { key: (v) => String(v).trim().toLowerCase() });

  field('records_affected_est', 'Records affected', breach.records_affected_est,
    (s) => s.records_affected_est, {
      // Only a material spread is a conflict; 4,999 vs 5,000 is not.
      conflict: (entries) => {
        const nums = entries.map((e) => Number(e.value)).filter((n) => !Number.isNaN(n) && n > 0);
        if (nums.length < 2) return false;
        const mn = Math.min(...nums), mx = Math.max(...nums);
        return mx >= mn * 1.5;
      },
    });

  field('incident_date', 'Incident date', breach.incident_date,
    (s) => (s.incident_date ? String(s.incident_date).slice(0, 10) : null), {
      // Dates outside the 45-day same-incident window count as disagreement.
      conflict: (entries) => {
        const t = entries.map((e) => Date.parse(e.value)).filter((n) => !Number.isNaN(n));
        return t.length >= 2 && (Math.max(...t) - Math.min(...t)) > 45 * 86400000;
      },
    });

  field('industry', 'Industry', breach.industry, (s) => s.industry);

  field('location', 'Location',
    [breach.region_state, breach.country].filter(Boolean).join(', ') || null,
    (s) => [s.region_state, s.country].filter(Boolean).join(', ') || null);

  return out;
}

export async function fetchBreachDetail(id) {
  const [{ data: breach, error: breachErr }, { data: sources, error: sourcesErr }] = await Promise.all([
    supabase.from('breaches').select('*').eq('id', id).single(),
    // Curated public view: exposes only the fields the dossier needs plus two
    // distilled evidence URLs. The raw source payload, fingerprints and internal
    // identifiers stay private (see docs/security/public-data-contract.md).
    supabase
      .from('v_public_breach_sources')
      .select(
        'source_record_url, document_type, summary, source_published_at, match_confidence, ' +
        'records_affected_est, data_types_exposed, ransomware_group_norm, ransomware_group_raw, ' +
        'incident_date, industry, region_state, country, ' +
        'source_name, source_category, disclosure_url, screenshot_url'
      )
      .eq('matched_breach_id', id)
      .order('source_published_at', { ascending: false }),
  ]);
  if (breachErr) throw breachErr;
  if (sourcesErr) throw sourcesErr;

  // Official disclosure / screenshot evidence, when a source carries it
  // (e.g. HIBP's DisclosureUrl, ransomware.live's screenshot). Pulled from
  // raw_payload so it can be surfaced as evidence without new columns.
  const evidence = [];
  for (const s of sources || []) {
    if (s.disclosure_url) evidence.push({ kind: 'disclosure', url: s.disclosure_url, source: s.source_name });
    let shot = s.screenshot_url;
    // Older ransomware.live rows stored a path relative to the image host.
    if (shot && !/^https?:\/\//.test(shot)) {
      shot = `https://images.ransomware.live/${String(shot).replace(/^\/+/, '')}`;
    }
    if (shot) {
      evidence.push({
        kind: 'screenshot', url: shot, source: s.source_name,
        post: s.source_record_url,
      });
    }
  }

  // Related news coverage: headlines the daily news-watch job correlated to
  // this breach by company name (title + URL only, never article content).
  // Best-effort — an older database without the news_watch table just yields
  // an empty list rather than failing the whole panel.
  let related_news = [];
  try {
    const { data: news } = await supabase
      .from('v_public_news')
      .select('title, url, source_name, published_at, similarity')
      .eq('matched_breach_id', id)
      .order('published_at', { ascending: false, nullsFirst: false })
      .limit(25);
    related_news = news || [];
  } catch {
    related_news = [];
  }

  // Enhancement history: what the maintenance re-enrichment loop improved on
  // this breach over time (records, data types, actor, dates), newest first.
  // Best-effort — an older database without the log table yields an empty list.
  let enhancements = [];
  try {
    const { data: log } = await supabase
      .from('breach_enrichment_log')
      .select('changed, enriched_at')
      .eq('breach_id', id)
      .order('enriched_at', { ascending: false })
      .limit(50);
    enhancements = log || [];
  } catch {
    enhancements = [];
  }

  // Post-incident developments: regulatory fines, litigation and settlements
  // detected on this breach after disclosure, newest first. Best-effort — an
  // older database without the table yields an empty list.
  let developments = [];
  try {
    const { data: dev } = await supabase
      .from('breach_developments')
      .select('kind, title, detail, url, source_name, occurred_at')
      .eq('breach_id', id)
      .order('occurred_at', { ascending: false, nullsFirst: false })
      .limit(50);
    developments = dev || [];
  } catch {
    developments = [];
  }

  // Related breaches: other victims of the same threat actor, and other
  // incidents at the same company (repeat victims). Best-effort; excludes the
  // current breach.
  let related = { sameActor: [], sameCompany: [] };
  if (breach) {
    try {
      const cols = 'id, canonical_name, disclosed_date, incident_date, industry, ransomware_group, severity';
      const actorQ = breach.ransomware_group
        ? supabase.from('public_breach_ledger').select(cols)
            .ilike('ransomware_group', breach.ransomware_group).neq('id', id)
            .order('disclosed_date', { ascending: false, nullsFirst: false }).limit(6)
        : Promise.resolve({ data: [] });
      const companyQ = supabase.from('public_breach_ledger').select(cols)
        .ilike('canonical_name', breach.canonical_name).neq('id', id)
        .order('disclosed_date', { ascending: false, nullsFirst: false }).limit(5);
      const [{ data: byActor }, { data: byCompany }] = await Promise.all([actorQ, companyQ]);
      related = { sameActor: byActor || [], sameCompany: byCompany || [] };
    } catch {
      related = { sameActor: [], sameCompany: [] };
    }
  }

  return {
    breach,
    evidence,
    related_news,
    enhancements,
    developments,
    provenance: breach ? buildProvenance(breach, sources) : [],
    related,
    linked_sources: (sources || []).map((s) => ({
      source_name: s.source_name,
      source_category: s.source_category,
      document_type: s.document_type,
      published_at: s.source_published_at,
      confidence: s.match_confidence,
      url: s.source_record_url,
      summary: s.summary,
    })),
  };
}

// Live "Threat Radar" ticker: fresh signals (latest ransomware victims, newly
// exploited CVEs, optional OTX/URLhaus) written server-side by app.threat_radar.
// Best-effort — a database without the table just yields an empty ticker.
export async function fetchThreatRadar(limit = 40) {
  try {
    const { data } = await supabase
      .from('threat_radar')
      .select('kind, source_name, title, subtitle, url, published_at')
      .order('published_at', { ascending: false, nullsFirst: false })
      .limit(limit);
    return data || [];
  } catch {
    return [];
  }
}

// Threat-actor profile: every ledger victim attributed to this group, plus
// the raw name variants seen across sources ("also reported as"). Victim-level
// stats (timeline, industries, first/last seen) are derived in the component.
export async function fetchActorProfile(group) {
  const [{ data: victims, error: vErr }, { data: rawRows }] = await Promise.all([
    supabase
      .from('public_breach_ledger')
      .select('id, canonical_name, industry, country, region_state, incident_date, disclosed_date, records_affected_est, severity')
      .ilike('ransomware_group', group)
      .order('disclosed_date', { ascending: false, nullsFirst: false })
      .limit(500),
    supabase
      .from('v_public_breach_sources')
      .select('ransomware_group_raw')
      .ilike('ransomware_group_norm', group)
      .not('ransomware_group_raw', 'is', null)
      .limit(300),
  ]);
  if (vErr) throw vErr;

  const seen = new Set();
  const aliases = [];
  for (const r of rawRows || []) {
    const a = (r.ransomware_group_raw || '').trim();
    const key = a.toLowerCase();
    if (a && key !== group.toLowerCase() && !seen.has(key)) {
      seen.add(key);
      aliases.push(a);
    }
  }
  return { group, victims: victims || [], aliases };
}

export async function fetchTrends() {
  const { data, error } = await supabase
    .from('public_breach_trends')
    .select('week_start, industry, breach_count')
    .order('week_start');
  if (error) throw error;
  return data;
}

export async function fetchTopGroups(limit = 8) {
  const { data, error } = await supabase
    .from('public_top_ransomware_groups')
    .select('ransomware_group, victim_count')
    .order('victim_count', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data.map((r) => ({ group: r.ransomware_group, count: r.victim_count }));
}

// The match queue holds internal correlation review state (candidate matches,
// reviewer, reasons) and is no longer exposed to the anonymous Data API
// (WP-002). This resolves to an empty list for the public site; queue review is
// an internal, authenticated-only concern. Best-effort so a 403 never throws.
export async function fetchMatchQueue() {
  return [];
}
