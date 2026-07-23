import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useGoogleFonts, COLORS } from './constants';
import {
  TopBar, Hero, FilterBar, LedgerTable, TableToolbar, BreachDetailDrawer,
  AnalyticsView, MatchQueueView, Footer,
} from './components';
import { ToolsView } from './tools';
import { CommandPalette } from './palette';
import { ThreatRadar } from './ticker';
import { ThreatActorDrawer, actorStixBundle } from './actor';
import { WorkspaceView } from './workspace';
import { AboutView } from './about';
import {
  fetchStats, fetchRecentIntake, fetchRansomwareGroupOptions, fetchBreaches,
  fetchBreachesForExport, fetchBreachDetail, fetchTrends, fetchTopGroups, fetchMatchQueue,
  fetchThreatRadar, fetchActorProfile,
} from './lib/api';

const PAGE_SIZE = 25;

// State that should survive reloads (table layout + saved views), backed by
// localStorage. Falls back to the initial value if storage is unavailable.
function usePersisted(key, initial) {
  const [v, setV] = useState(() => {
    try { const s = localStorage.getItem(key); return s != null ? JSON.parse(s) : initial; } catch { return initial; }
  });
  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ } }, [key, v]);
  return [v, setV];
}

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
  const [filters, setFilters] = useState({ q: '', industry: '', group: '', attribution: '', dateFrom: '', dateTo: '' });
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
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [radar, setRadar] = useState([]);

  const [actorOpen, setActorOpen] = useState(false);
  const [actorGroup, setActorGroup] = useState(null);
  const [actorProfile, setActorProfile] = useState(null);
  const [actorLoading, setActorLoading] = useState(false);
  const [actorError, setActorError] = useState(null);

  // Table layout + saved views (persisted).
  const [hiddenCols, setHiddenCols] = usePersisted('bi.hiddenCols', []);
  const [density, setDensity] = usePersisted('bi.density', 'comfortable');
  const [savedViews, setSavedViews] = usePersisted('bi.views', []);

  // Analyst workspace: watchlist + recently-viewed (persisted, browser-local).
  const [watchlist, setWatchlist] = usePersisted('bi.watchlist', { breaches: [], actors: [] });
  const [recentViewed, setRecentViewed] = usePersisted('bi.recentViewed', { breaches: [], actors: [] });

  const isWatchedBreach = (id) => (watchlist.breaches || []).some((x) => x.id === id);
  const isWatchedActor = (g) => (watchlist.actors || []).includes(g);
  function toggleWatchBreach(b) {
    setWatchlist((w) => {
      const has = (w.breaches || []).some((x) => x.id === b.id);
      return { ...w, breaches: has ? w.breaches.filter((x) => x.id !== b.id) : [{ id: b.id, canonical_name: b.canonical_name }, ...(w.breaches || [])] };
    });
  }
  function toggleWatchActor(g) {
    setWatchlist((w) => {
      const has = (w.actors || []).includes(g);
      return { ...w, actors: has ? w.actors.filter((x) => x !== g) : [g, ...(w.actors || [])] };
    });
  }
  function pushRecentBreach(b) {
    if (!b?.id) return;
    setRecentViewed((r) => ({ ...r, breaches: [{ id: b.id, canonical_name: b.canonical_name }, ...(r.breaches || []).filter((x) => x.id !== b.id)].slice(0, 20) }));
  }
  function pushRecentActor(g) {
    setRecentViewed((r) => ({ ...r, actors: [g, ...(r.actors || []).filter((x) => x !== g)].slice(0, 12) }));
  }
  const watchCount = (watchlist.breaches?.length || 0) + (watchlist.actors?.length || 0);

  function saveView() {
    const name = (window.prompt('Name this view (filters, sort, columns, density):') || '').trim();
    if (!name) return;
    const view = { name, filters, sortBy, sortDir, hiddenCols, density };
    setSavedViews([...savedViews.filter((v) => v.name !== name), view]);
  }
  function applyView(v) {
    if (v.filters) setFilters(v.filters);
    if (v.sortBy) setSortBy(v.sortBy);
    if (v.sortDir) setSortDir(v.sortDir);
    setHiddenCols(v.hiddenCols || []);
    if (v.density) setDensity(v.density);
  }
  function deleteView(name) { setSavedViews(savedViews.filter((v) => v.name !== name)); }

  // Anchor at the top of the results so paging can scroll back up to it,
  // instead of leaving the user stranded at the bottom where the pager is.
  const resultsTopRef = useRef(null);
  const firstLedgerRender = useRef(true);

  // One-time data: hero stats, intake ticker, filter dropdown options.
  useEffect(() => {
    fetchStats().then(setStats).catch((e) => console.error('fetchStats', e));
    fetchRecentIntake(6).then(setRecent).catch((e) => console.error('fetchRecentIntake', e));
    fetchRansomwareGroupOptions()
      .then((groups) => setGroupOptions(groups.map((g) => ({ value: g, label: g }))))
      .catch((e) => console.error('fetchRansomwareGroupOptions', e));
    fetchThreatRadar().then(setRadar).catch((e) => console.error('fetchThreatRadar', e));
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

  // On a page change (Next/Prev), scroll back to the top of the results so the
  // new page starts at the top rather than wherever the pager sits. Skips the
  // initial mount so we don't yank a freshly loaded page around.
  useEffect(() => {
    if (firstLedgerRender.current) { firstLedgerRender.current = false; return; }
    resultsTopRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [page]);

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
      .then(({ breach, linked_sources, evidence, related_news, related }) => {
        setDetail({ ...breach, linked_sources, evidence, related_news, related });
        pushRecentBreach(breach);
      })
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

  function openActor(group) {
    if (!group) return;
    setActorOpen(true);
    setActorLoading(true);
    setActorProfile(null);
    setActorError(null);
    setActorGroup(group);
    pushRecentActor(group);
    window.history.replaceState(null, '', `#actor=${encodeURIComponent(group)}`);
    fetchActorProfile(group)
      .then(setActorProfile)
      .catch((e) => { console.error('fetchActorProfile', e); setActorError(e?.message || String(e)); })
      .finally(() => setActorLoading(false));
  }

  function closeActor() {
    setActorOpen(false);
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }

  // Export an actor's attributed victims: CSV, JSON, or a STIX 2.1 bundle
  // (intrusion-set + victim identities + targets relationships) for a TIP.
  function exportActor(format) {
    const g = actorGroup || 'actor';
    const victims = actorProfile?.victims || [];
    const aliases = actorProfile?.aliases || [];
    const stamp = new Date().toISOString().slice(0, 10);
    const safe = g.replace(/[^a-z0-9]+/gi, '-').toLowerCase();
    if (format === 'csv') {
      downloadBlob(toCsv(victims), `${safe}-victims-${stamp}.csv`, 'text/csv');
    } else if (format === 'stix') {
      downloadBlob(JSON.stringify(actorStixBundle(g, victims, aliases), null, 2), `${safe}-stix-${stamp}.json`, 'application/json');
    } else {
      downloadBlob(JSON.stringify({ actor: g, aliases, victims }, null, 2), `${safe}-${stamp}.json`, 'application/json');
    }
  }

  // Permalink support: #breach=<id> opens a case; #actor=<name> opens an actor
  // profile — so researchers can share a link straight to either.
  useEffect(() => {
    const hb = window.location.hash.match(/^#breach=([0-9a-f-]{36})$/i);
    if (hb) { openBreach({ id: hb[1] }); return; }
    const ha = window.location.hash.match(/^#actor=(.+)$/);
    if (ha) { try { openActor(decodeURIComponent(ha[1])); } catch { /* ignore */ } }
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

      <TopBar tab={tab} setTab={setTab} pendingCount={queueItems.length} watchCount={watchCount} />
      <ThreatRadar items={radar} />

      {tab === 'ledger' && (
        <>
          <Hero
            recent={recent}
            totalSources={stats?.total_sources ?? '-'}
            totalBreaches={stats?.total_breaches ?? '-'}
          />
          <div ref={resultsTopRef} style={{ scrollMarginTop: 64 }} />
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
            <>
              <TableToolbar
                density={density} setDensity={setDensity}
                hiddenCols={hiddenCols} setHiddenCols={setHiddenCols}
                rows={loadingList ? [] : rows}
                views={savedViews} onSaveView={saveView} onApplyView={applyView} onDeleteView={deleteView}
              />
              <LedgerTable
                rows={loadingList ? [] : rows}
                onOpen={openBreach}
                onActorClick={openActor}
                page={page} totalPages={totalPages} setPage={setPage}
                total={total} pageSize={PAGE_SIZE}
                sortBy={sortBy} sortDir={sortDir} onSort={sortByColumn}
                hiddenCols={hiddenCols} density={density}
              />
            </>
          )}
        </>
      )}

      {tab === 'analytics' && (
        <>
          <div className="px-6 pt-6 flex items-center gap-6">
            <div>
              <div style={{ fontFamily: 'monospace', color: COLORS.bone, fontSize: 20 }}>
                {stats?.avg_confidence != null ? Math.round(Number(stats.avg_confidence) * 100) + '%' : '-'}
              </div>
              <div className="text-xs" style={{ color: COLORS.boneFaint }}>avg. correlation confidence</div>
            </div>
            <div>
              <div style={{ fontFamily: 'monospace', color: COLORS.bone, fontSize: 20 }}>
                {stats?.pending_review ?? '-'}
              </div>
              <div className="text-xs" style={{ color: COLORS.boneFaint }}>pending manual review</div>
            </div>
          </div>
          <AnalyticsView trends={trends} topGroups={topGroups} onOpenActor={openActor} />
        </>
      )}

      {tab === 'workspace' && (
        <WorkspaceView
          watchlist={watchlist}
          recent={recentViewed}
          onOpenBreach={(row) => { setTab('ledger'); openBreach(row); }}
          onOpenActor={(g) => { setTab('ledger'); openActor(g); }}
          onRemoveWatchBreach={(id) => setWatchlist((w) => ({ ...w, breaches: (w.breaches || []).filter((x) => x.id !== id) }))}
          onRemoveWatchActor={(g) => toggleWatchActor(g)}
          onClearRecent={() => setRecentViewed({ breaches: [], actors: [] })}
        />
      )}

      {tab === 'tools' && <ToolsView />}

      {tab === 'about' && <AboutView />}

      {tab === 'queue' && <MatchQueueView items={queueItems} />}

      <Footer onAbout={() => setTab('about')} />
      <CommandPalette
        open={paletteOpen}
        setOpen={setPaletteOpen}
        onOpenBreach={(row) => { setTab('ledger'); openBreach(row); }}
        onFilterActor={(group) => { setTab('ledger'); setFilters({ ...filters, group }); }}
        onSetTab={setTab}
      />
      <BreachDetailDrawer
        breach={detail}
        isOpen={drawerOpen}
        loading={detailLoading}
        error={detailError}
        onClose={closeDrawer}
        onOpenActor={(g) => { closeDrawer(); openActor(g); }}
        onOpenRelated={(row) => openBreach(row)}
        isWatched={detail ? isWatchedBreach(detail.id) : false}
        onToggleWatch={(b) => toggleWatchBreach(b)}
      />
      <ThreatActorDrawer
        group={actorGroup}
        profile={actorProfile}
        isOpen={actorOpen}
        loading={actorLoading}
        error={actorError}
        onClose={closeActor}
        onOpenBreach={(row) => { closeActor(); setTab('ledger'); openBreach(row); }}
        onFilterLedger={(g) => { closeActor(); setTab('ledger'); setFilters({ ...filters, group: g }); }}
        onExport={exportActor}
        isWatched={actorGroup ? isWatchedActor(actorGroup) : false}
        onToggleWatch={(g) => toggleWatchActor(g)}
      />
    </div>
  );
}
