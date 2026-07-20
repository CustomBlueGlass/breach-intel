import React, { useState, useEffect, useCallback } from 'react';
import { useGoogleFonts, COLORS } from './constants';
import {
  TopBar, Hero, FilterBar, LedgerTable, BreachDetailDrawer,
  AnalyticsView, MatchQueueView, Footer,
} from './components';
import {
  fetchStats, fetchRecentIntake, fetchRansomwareGroupOptions, fetchBreaches,
  fetchBreachDetail, fetchTrends, fetchTopGroups, fetchMatchQueue,
} from './lib/api';

const PAGE_SIZE = 25;

export default function App() {
  useGoogleFonts();

  const [tab, setTab] = useState('ledger');
  const [filters, setFilters] = useState({ q: '', industry: '', group: '', status: '' });
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
    fetchBreachDetail(b.id)
      .then(({ breach, linked_sources }) => setDetail({ ...breach, linked_sources }))
      .catch((e) => {
        console.error('fetchBreachDetail', e);
        setDetailError(e?.message || String(e));
      })
      .finally(() => setDetailLoading(false));
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
              page={page} totalPages={totalPages} setPage={setPage}
              total={total} pageSize={PAGE_SIZE}
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

      {tab === 'queue' && <MatchQueueView items={queueItems} />}

      <Footer />
      <BreachDetailDrawer
        breach={detail}
        isOpen={drawerOpen}
        loading={detailLoading}
        error={detailError}
        onClose={() => setDrawerOpen(false)}
      />
    </div>
  );
}
