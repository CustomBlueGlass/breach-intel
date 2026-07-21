import { supabase } from './supabaseClient';

const PAGE_SIZE = 25; // spec: 25–50 records per page, never the full dataset

export async function fetchStats() {
  const { data, error } = await supabase.from('mv_platform_stats').select('*').single();
  if (error) throw error;
  return data;
}

export async function fetchRecentIntake(limit = 6) {
  const { data, error } = await supabase
    .from('mv_breach_ledger')
    .select('id, canonical_name, disclosed_date')
    .order('disclosed_date', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data;
}

export async function fetchRansomwareGroupOptions() {
  const { data, error } = await supabase
    .from('mv_top_ransomware_groups')
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
function applyLedgerFilters(query, filters) {
  if (filters.q) {
    query = query.or(`canonical_name.ilike.%${filters.q}%,ransomware_group.ilike.%${filters.q}%`);
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
  let query = supabase.from('mv_breach_ledger').select('*', { count: 'exact' });
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
  let query = supabase.from('mv_breach_ledger').select('*');
  query = applyLedgerFilters(query, filters);
  const { data, error } = await query
    .order(sortBy, { ascending: sortDir === 'asc', nullsFirst: false })
    .limit(max);
  if (error) throw error;
  return data || [];
}

export async function fetchBreachDetail(id) {
  const [{ data: breach, error: breachErr }, { data: sources, error: sourcesErr }] = await Promise.all([
    supabase.from('breaches').select('*').eq('id', id).single(),
    supabase
      .from('breach_source_records')
      .select(
        'id, source_record_url, document_type, summary, source_published_at, match_confidence, ' +
        'raw_payload, breach_data_sources ( name, category )'
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
    const p = s.raw_payload || {};
    const disc = p.DisclosureUrl || p.disclosure_url;
    if (disc) evidence.push({ kind: 'disclosure', url: disc, source: s.breach_data_sources?.name });
    const shot = p.screenshot || p.screen || p.image;
    if (shot) evidence.push({ kind: 'screenshot', url: shot, source: s.breach_data_sources?.name });
  }

  return {
    breach,
    evidence,
    linked_sources: (sources || []).map((s) => ({
      source_name: s.breach_data_sources?.name,
      source_category: s.breach_data_sources?.category,
      document_type: s.document_type,
      published_at: s.source_published_at,
      confidence: s.match_confidence,
      url: s.source_record_url,
      summary: s.summary,
    })),
  };
}

export async function fetchTrends() {
  const { data, error } = await supabase
    .from('mv_breach_trends')
    .select('week_start, industry, breach_count')
    .order('week_start');
  if (error) throw error;
  return data;
}

export async function fetchTopGroups(limit = 8) {
  const { data, error } = await supabase
    .from('mv_top_ransomware_groups')
    .select('ransomware_group, victim_count')
    .order('victim_count', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data.map((r) => ({ group: r.ransomware_group, count: r.victim_count }));
}

export async function fetchMatchQueue() {
  const { data, error } = await supabase
    .from('breach_match_queue')
    .select(
      'id, confidence, match_reasons, created_at, ' +
      'breach_source_records ( company_name_raw ), ' +
      'breaches ( canonical_name )'
    )
    .eq('status', 'pending')
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data.map((q) => ({
    id: q.id,
    record_name: q.breach_source_records?.company_name_raw,
    candidate_name: q.breaches?.canonical_name,
    confidence: Math.round(Number(q.confidence) * 100),
    reasons: q.match_reasons || {},
  }));
}
