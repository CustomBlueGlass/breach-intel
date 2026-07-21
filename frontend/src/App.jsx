import React, { useState, useEffect, useCallback } from 'react';
import { useGoogleFonts, COLORS } from './constants';
import {
  TopBar, Hero, FilterBar, LedgerTable, BreachDetailDrawer,
  AnalyticsView, MatchQueueView, Footer,
} from './components';
import { ToolsView } from './tools';
import {
  fetchStats, fetchRecentIntake, fetchRansomwareGroupOptions, fetchBreaches,
  fetchBreachesForExport, fetchBreachDetail, fetchTrends, fetchTopGroups, fetchMatchQueue,
} from './lib/api';

const PAGE_SIZE = 25;

function downloadBlob(content, filename, mime) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function toCsv(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const esc = (v) => {
    if (v == null) return '';
    const s = Array.isArray(v) ? v.join(';') : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
}

export default function App() {
  useGoogleFonts();

  const [tab, setTab] = useState('ledger');
  const [filters, setFilters] = useState({ q: '', industry: '', group: '', status: '', dateFrom: '', dateTo: '' });
  const [sortBy, setSortBy] = useState('disclosed_date');
  const [sortDir, setSortDir] = useState('desc');
  const [page, setPage] = useState(1);

  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [groupOptions, setGroupOptions] = useState([]);

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState(null);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  const [trends, setTrends] = useState([]);
  const [topGroups, setTopGroups] = useState([]);
  const [queueItems, setQueueItems] = useState([]);

  // One-time data: hero stats, intake ticker, filter dropdown options.
  useEffect(() => {
    fetchStats().then(setStats).catch((e) => console.error('fetchStats', e));
    fetchRecentIntake(6).then(setRecent).catch((e) => console.error('fetchRecentIntake', e));
    fetchRansomwareGroupOptions()
      .then((groups) => setGroupOptions(groups.map((g) => ({ value: g, label: g }))))
      .catch((e) => console.error('fetchRansomwareGroupOptions', e));
  }, []);

  // Ledger list: refetch whenever filters/sort/page change. This is the
  // query that keeps "never load the full dataset" true — only ever
  // PAGE_SIZE rows cross the wire.
  const loadLedger = useCallback(() => {
    setLoadingList(true);
    setListError(null);
    fetchBreaches({ filters, sortBy, sortDir, page, pageSize: PAGE_SIZE })
      .then(({ items, total }) => { setRows(items); setTotal(total); })
      .catch((e) => { console.error('fetchBreaches', e); setListError(e.message || String(e)); })
      .finally(() => setLoadingList(false));
  }, [filters, sortBy, sortDir, page]);

  useEffect(() => { loadLedger(); }, [loadLedger]);
  useEffect(() => { setPage(1); }, [filters, sortBy, sortDir]);

  // Analytics tab: load lazily, once, when first opened.
  useEffect(() => {
    if (tab !== 'analytics' || trends.length) return;
    fetchTrends().then(setTrends).catch((e) => console.error('fetchTrends', e));
    fetchTopGroups(8).then(setTopGroups).catch((e) => console.error('fetchTopGroups', e));
  }, [tab, trends.length]);

  // Match queue tab: load lazily, once, when first opened.
  useEffect(() => {
    if (tab !== 'queue') return;
    fetchMatchQueue().then(setQueueItems).catch((e) => console.error('fetchMatchQueue', e));
  }, [tab]);

  function openBreach(b) {
    setDrawerOpen(true);
    setDetailLoading(true);
    setDetail(null);
    setDetailError(null);
    window.history.replaceState(null, '', `#breach=${b.id}`);
    fetchBreachDetail(b.id)
      .then(({ breach, linked_sources, evidence }) => setDetail({ ...breach, linked_sources, evidence }))
      .catch((e) => {
        console.error('fetchBreachDetail', e);
        setDetailError(e?.message || String(e));
      })
      .finally(() => setDetailLoading(false));
  }

  function closeDrawer() {
    setDrawerOpen(false);
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }

  // Permalink support: #breach=<id> opens that company's details directly,
  // so researchers can share a link straight to a case.
  useEffect(() => {
    const m = window.location.hash.match(/^#breach=([0-9a-f-]{36})$/i);
    if (m) openBreach({ id: m[1] });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Export tool: current filters/sort, capped at 1000 rows.
  function exportLedger(format) {
    fetchBreachesForExport({ filters, sortBy, sortDir })
      .then((rows) => {
        const stamp = new Date().toISOString().slice(0, 10);
        if (format === 'csv') {
          downloadBlob(toCsv(rows), `breaches-${stamp}.csv`, 'text/csv');
        } else {
          downloadBlob(JSON.stringify(rows, null, 2), `breaches-${stamp}.json`, 'application/json');
        }
      })
      .catch((e) => console.error('export', e));
  }

  function sortByColumn(key) {
    if (sortBy === key) {
      setSortDir(sortDir === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(key);
      setSortDir('desc');
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div style={{ backgroundColor: COLORS.ink, minHeight: '100vh', fontFamily: "'Inter', sans-serif" }}>
      <style>{`
        @media (prefers-reduced-motion: reduce) { .motion-safe-pulse { animation: none !important; } }
        .motion-safe-pulse { animation: ping 1.8s cubic-bezier(0,0,0.2,1) infinite; }
        @keyframes ping { 75%, 100% { transform: scale(2); opacity: 0; } }
        select option { background-color: ${COLORS.panel}; }
        ::selection { background-color: ${COLORS.amber}; color: ${COLORS.ink}; }
      `}</style>

      <TopBar tab={tab} setTab={setTab} pendingCount={queueItems.length} />

      {tab === 'ledger' && (
        <>
          <Hero
            recent={recent}
            totalSources={stats?.total_sources ?? '—'}
            totalBreaches={stats?.total_breaches ?? '—'}
          />
          <FilterBar
            filters={filters} setFilters={setFilters}
            sortBy={sortBy} setSortBy={setSortBy} sortDir={sortDir} setSortDir={setSortDir}
            resultCount={total}
            groupOptions={groupOptions}
            onExport={exportLedger}
          />
          {listError ? (
            <div className="px-6 py-10 text-sm" style={{ color: COLORS.red, fontFamily: 'monospace' }}>
              Couldn't load breaches: {listError}
              <div style={{ color: COLORS.boneFaint, marginTop: 8 }}>
                Check that VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY are set and that
                db/supabase_grants.sql has been run.
              </div>
            </div>
          ) : (
            <LedgerTable
              rows={loadingList ? [] : rows}
              onOpen={openBreach}
              onActorClick={(group) => setFilters({ ...filters, group })}
              page={page} totalPages={totalPages} setPage={setPage}
              total={total} pageSize={PAGE_SIZE}
              sortBy={sortBy} sortDir={sortDir} onSort={sortByColumn}
            />
          )}
        </>
      )}

      {tab === 'analytics' && (
        <>
          <div className="px-6 pt-6 flex items-center gap-6">
            <div>
              <div style={{ fontFamily: 'monospace', color: COLORS.bone, fontSize: 20 }}>
                {stats?.avg_confidence != null ? Math.round(Number(stats.avg_confidence) * 100) + '%' : '—'}
              </div>
              <div className="text-xs" style={{ color: COLORS.boneFaint }}>avg. correlation confidence</div>
            </div>
            <div>
              <div style={{ fontFamily: 'monospace', color: COLORS.bone, fontSize: 20 }}>
                {stats?.pending_review ?? '—'}
              </div>
              <div className="text-xs" style={{ color: COLORS.boneFaint }}>pending manual review</div>
            </div>
          </div>
          <AnalyticsView trends={trends} topGroups={topGroups} />
        </>
      )}

      {tab === 'tools' && <ToolsView />}

      {tab === 'queue' && <MatchQueueView items={queueItems} />}

      <Footer />
      <BreachDetailDrawer
        breach={detail}
        isOpen={drawerOpen}
        loading={detailLoading}
        error={detailError}
        onClose={closeDrawer}
      />
    </div>
  );
}
