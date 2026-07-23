import React, { useMemo } from 'react';
import {
  Search, ArrowUpDown, ChevronLeft, ChevronRight, ChevronDown,
  ShieldAlert, X, Inbox, ListChecks, CheckCircle2, Lock,
  FileText, ExternalLink, Download, Copy, Link2, Check, Archive, ShieldCheck,
  Newspaper, SlidersHorizontal, Save, Trash2, Star,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area,
} from 'recharts';
import {
  COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO,
  INDUSTRY_LABELS, SOURCE_CATEGORY_META, SEVERITY_META,
  fmtNumber, fmtDate, fmtDateTime, relativeTime,
} from './constants';

/* ------------------------- small shared atoms ------------------------- */

export function Tag({ children, style, className = '' }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${className}`}
      style={{ fontFamily: FONT_BODY, ...style }}
    >
      {children}
    </span>
  );
}

export function SeverityTag({ severity }) {
  const m = SEVERITY_META[severity] || SEVERITY_META.unrated;
  return <Tag style={{ color: m.text, backgroundColor: m.bg }}>{m.label}</Tag>;
}

export function SourceCategoryChip({ category, sourceName, docType, dateStr, confidence, url, summary, isLast }) {
  const meta = SOURCE_CATEGORY_META[category] || { label: category || 'Source', Icon: FileText };
  const Icon = meta.Icon;
  return (
    <div
      className="relative flex items-start gap-3 pb-5 pl-1"
      style={{ borderLeft: isLast ? 'none' : `1px dashed ${COLORS.line}`, marginLeft: 13 }}
    >
      <div
        className="flex items-center justify-center rounded-full shrink-0"
        style={{
          width: 28, height: 28, marginLeft: -14,
          backgroundColor: COLORS.panelAlt, border: `1px solid ${COLORS.line}`,
        }}
      >
        <Icon size={14} color={COLORS.boneDim} />
      </div>
      <div className="flex-1 pt-0.5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-medium" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>
            {sourceName || meta.label}
          </span>
          {confidence != null && (
            <span
              className="text-xs px-1.5 py-0.5 rounded"
              style={{
                fontFamily: FONT_MONO, color: confidence >= 0.9 ? COLORS.teal : COLORS.boneDim,
                backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}`,
              }}
            >
              {Math.round(confidence * 100)}%
            </span>
          )}
        </div>
        <div className="text-xs mt-0.5" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
          {meta.label} · {(docType || '').replace(/_/g, ' ')} · {fmtDateTime(dateStr)}
        </div>
        {summary && (
          <p className="text-xs mt-1 leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
            {String(summary).slice(0, 220)}{String(summary).length > 220 ? '…' : ''}
          </p>
        )}
        {url && (
          <div className="mt-1 flex flex-col gap-0.5">
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs break-all hover:underline"
              style={{ color: COLORS.amberSoft, fontFamily: FONT_MONO }}
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink size={11} className="shrink-0" />
              {url.replace(/^https?:\/\//, '')}
            </a>
            {/* Link permanence: leak sites and AG pages rot. A one-click
                Archive.org snapshot lets an analyst cite a durable copy. */}
            <a
              href={`https://web.archive.org/web/2/${url}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs hover:underline"
              style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}
              onClick={(e) => e.stopPropagation()}
              title="Open the most recent Web Archive snapshot of this source"
            >
              <Archive size={11} className="shrink-0" /> archived copy
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------- top bar -------------------------------- */

export function TopBar({ tab, setTab, pendingCount, watchCount }) {
  const tabs = [
    { id: 'ledger', label: 'Ledger' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'workspace', label: 'Workspace', badge: watchCount },
    { id: 'tools', label: 'Tools' },
    { id: 'queue', label: 'Match queue', badge: pendingCount },
  ];
  return (
    <header
      className="sticky top-0 z-20 flex items-center gap-2 px-4 sm:px-6 py-3"
      style={{ backgroundColor: COLORS.ink, borderBottom: `1px solid ${COLORS.line}` }}
    >
      <div className="flex items-center gap-3 shrink-0">
        <div
          className="flex items-center justify-center rounded"
          style={{ width: 30, height: 30, backgroundColor: COLORS.amber }}
        >
          <ShieldAlert size={16} color={COLORS.ink} />
        </div>
        <span style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 19, letterSpacing: '0.01em' }}>
          Ledger<span style={{ color: COLORS.amber }}>//</span>Breach
        </span>
      </div>
      <nav className="no-scrollbar flex items-center gap-1 overflow-x-auto min-w-0 ml-auto">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className="shrink-0 whitespace-nowrap px-3 py-1.5 rounded-md text-sm font-medium flex items-center gap-2 transition-colors"
            style={{
              fontFamily: FONT_BODY,
              color: tab === t.id ? COLORS.ink : COLORS.boneDim,
              backgroundColor: tab === t.id ? COLORS.bone : 'transparent',
            }}
          >
            {t.label}
            {!!t.badge && (
              <span
                className="text-xs px-1.5 rounded-full"
                style={{
                  fontFamily: FONT_MONO,
                  backgroundColor: tab === t.id ? COLORS.red : 'rgba(192,71,58,0.25)',
                  color: tab === t.id ? COLORS.bone : COLORS.red,
                }}
              >
                {t.badge}
              </span>
            )}
          </button>
        ))}
      </nav>
    </header>
  );
}

/* --------------------------------- hero ---------------------------------- */

export function Hero({ recent, totalSources, totalBreaches }) {
  return (
    <div className="grid md:grid-cols-5 gap-0" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
      <div className="md:col-span-3 px-6 md:px-10 py-12">
        <div
          className="text-xs uppercase tracking-widest mb-4"
          style={{ fontFamily: FONT_MONO, color: COLORS.amber, letterSpacing: '0.18em' }}
        >
          Unified breach intelligence ledger
        </div>
        <h1
          style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 'clamp(28px,4vw,44px)', lineHeight: 1.1, fontWeight: 600 }}
        >
          Every leak claim, every notice,
          <br />every filing. One record.
        </h1>
        <p className="mt-5 max-w-md text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
          {totalSources} sources: ransomware leak sites, state AG portals, federal regulators, and security press.
          Deduplicated and combined into one detailed record per company breach.
        </p>
        <div className="flex items-center gap-6 mt-7">
          <div>
            <div style={{ fontFamily: FONT_MONO, color: COLORS.bone, fontSize: 22 }}>{totalBreaches}</div>
            <div className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>breaches correlated</div>
          </div>
          <div style={{ width: 1, height: 32, backgroundColor: COLORS.line }} />
          <div>
            <div style={{ fontFamily: FONT_MONO, color: COLORS.bone, fontSize: 22 }}>{totalSources}</div>
            <div className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>sources tracked</div>
          </div>
        </div>
      </div>
      <div
        className="md:col-span-2 px-6 py-8"
        style={{ backgroundColor: COLORS.panel, borderLeft: `1px solid ${COLORS.line}` }}
      >
        <div className="flex items-center gap-2 mb-4">
          <span className="relative flex h-2 w-2">
            <span
              className="motion-safe-pulse absolute inline-flex h-full w-full rounded-full opacity-60"
              style={{ backgroundColor: COLORS.teal }}
            />
            <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: COLORS.teal }} />
          </span>
          <span className="text-xs uppercase tracking-widest" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.14em' }}>
            Recent intake
          </span>
        </div>
        <div className="space-y-3">
          {recent.map((r) => (
            <div key={r.id} className="flex items-center justify-between gap-3 text-sm">
              <span style={{ color: COLORS.bone, fontFamily: FONT_BODY }} className="truncate">{r.canonical_name}</span>
              <span style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 11, whiteSpace: 'nowrap' }}>
                {relativeTime(r.disclosed_date)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ filter bar ------------------------------- */

export function Select({ value, onChange, options, placeholder }) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none text-sm rounded-md pl-3 pr-8 py-1.5 outline-none"
        style={{
          fontFamily: FONT_BODY, backgroundColor: COLORS.panelAlt, color: COLORS.bone,
          border: `1px solid ${COLORS.line}`,
        }}
      >
        <option value="">{placeholder}</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      <ChevronDown size={14} color={COLORS.boneFaint} className="absolute right-2 top-2 pointer-events-none" />
    </div>
  );
}

function DateInput({ value, onChange, label }) {
  return (
    <input
      type="date"
      value={value || ''}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label}
      title={label}
      className="text-sm rounded-md px-2 py-1.5 outline-none"
      style={{
        fontFamily: FONT_MONO, backgroundColor: COLORS.panelAlt, color: value ? COLORS.bone : COLORS.boneFaint,
        border: `1px solid ${COLORS.line}`, colorScheme: 'dark',
      }}
    />
  );
}

export function FilterBar({ filters, setFilters, sortBy, setSortBy, sortDir, setSortDir, resultCount, groupOptions = [], onExport }) {
  return (
    <div className="flex flex-wrap items-center gap-2 px-6 py-4" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
      <div className="relative flex-1 min-w-[200px] max-w-sm">
        <Search size={15} color={COLORS.boneFaint} className="absolute left-2.5 top-2.5" />
        <input
          value={filters.q}
          onChange={(e) => setFilters({ ...filters, q: e.target.value })}
          placeholder="Search company or threat actor…"
          className="w-full text-sm rounded-md pl-8 pr-3 py-1.5 outline-none"
          style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.panelAlt, color: COLORS.bone, border: `1px solid ${COLORS.line}` }}
        />
      </div>
      <Select
        value={filters.industry}
        onChange={(v) => setFilters({ ...filters, industry: v })}
        placeholder="All industries"
        options={Object.entries(INDUSTRY_LABELS).map(([value, label]) => ({ value, label }))}
      />
      <Select
        value={filters.group}
        onChange={(v) => setFilters({ ...filters, group: v })}
        placeholder="All threat actors"
        options={groupOptions}
      />
      <Select
        value={filters.attribution}
        onChange={(v) => setFilters({ ...filters, attribution: v })}
        placeholder="Any attribution"
        options={[
          { value: 'attributed', label: 'Attributed to a group' },
          { value: 'unattributed', label: 'Unattributed' },
          { value: 'disputed', label: 'Disputed' },
        ]}
      />
      <div className="flex items-center gap-1">
        <DateInput label="Disclosed from" value={filters.dateFrom} onChange={(v) => setFilters({ ...filters, dateFrom: v })} />
        <span className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>→</span>
        <DateInput label="Disclosed to" value={filters.dateTo} onChange={(v) => setFilters({ ...filters, dateTo: v })} />
      </div>
      <button
        onClick={() => setSortDir(sortDir === 'desc' ? 'asc' : 'desc')}
        className="flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-md"
        style={{ fontFamily: FONT_BODY, color: COLORS.boneDim, border: `1px solid ${COLORS.line}` }}
        title="Toggle sort direction"
      >
        <ArrowUpDown size={13} /> {sortDir === 'desc' ? 'Newest' : 'Oldest'}
      </button>
      <Select
        value={sortBy}
        onChange={setSortBy}
        placeholder="Sort: Disclosed date"
        options={[
          { value: 'disclosed_date', label: 'Sort: Disclosed date' },
          { value: 'incident_date', label: 'Sort: Incident date' },
          { value: 'records_affected_est', label: 'Sort: Records affected' },
          { value: 'source_count', label: 'Sort: Source count' },
          { value: 'confidence_avg', label: 'Sort: Confidence' },
        ]}
      />
      <span className="ml-auto text-xs" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint }}>
        {resultCount} match{resultCount === 1 ? '' : 'es'}
      </span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onExport?.('csv')}
          className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md"
          title="Download the current filtered view as CSV (up to 1000 rows)"
          style={{ fontFamily: FONT_MONO, color: COLORS.boneDim, border: `1px solid ${COLORS.line}` }}
        >
          <Download size={12} /> CSV
        </button>
        <button
          onClick={() => onExport?.('json')}
          className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md"
          title="Download the current filtered view as JSON (up to 1000 rows)"
          style={{ fontFamily: FONT_MONO, color: COLORS.boneDim, border: `1px solid ${COLORS.line}` }}
        >
          <Download size={12} /> JSON
        </button>
      </div>
    </div>
  );
}

/* -------------------------------- ledger table --------------------------- */

// Column registry — the single source of truth for the header, each row,
// column show/hide, copy-row, and copy-page. `cell` renders the table cell;
// `text` is the plain value used for copy/TSV.
export const LEDGER_COLUMNS = [
  {
    key: 'company', label: 'Company', locked: true, align: 'left',
    text: (b) => b.canonical_name || '',
    cell: (b) => (
      <>
        <div style={{ color: COLORS.bone, fontFamily: FONT_BODY, fontWeight: 500 }} className="group-hover:underline">
          {b.canonical_name}
        </div>
        <div style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 11 }}>
          {[INDUSTRY_LABELS[b.industry] || b.industry, [b.region_state, b.country].filter(Boolean).join(', ')].filter(Boolean).join(' · ') || '-'}
        </div>
      </>
    ),
  },
  {
    key: 'actor', label: 'Threat actor', align: 'left',
    text: (b) => b.ransomware_group || 'Unattributed',
    cell: (b, { onActorClick }) => (b.ransomware_group ? (
      <button onClick={(e) => { e.stopPropagation(); onActorClick?.(b.ransomware_group); }} className="hover:underline"
        title={`View ${b.ransomware_group} threat-actor profile`} style={{ color: COLORS.red, fontFamily: FONT_BODY }}>
        {b.ransomware_group}
      </button>
    ) : <span style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>Unattributed</span>),
  },
  {
    key: 'incident', label: 'Incident', sortKey: 'incident_date', align: 'left',
    text: (b) => (b.incident_date ? fmtDate(b.incident_date) : ''),
    cell: (b) => <span style={{ color: COLORS.boneDim, fontFamily: FONT_MONO }}>{fmtDate(b.incident_date)}</span>,
  },
  {
    key: 'disclosed', label: 'Disclosed', sortKey: 'disclosed_date', align: 'left',
    text: (b) => (b.disclosed_date ? fmtDate(b.disclosed_date) : (b.incident_date ? `~${fmtDate(b.incident_date)}` : '')),
    cell: (b) => (b.disclosed_date
      ? <span style={{ color: COLORS.boneDim, fontFamily: FONT_MONO }}>{fmtDate(b.disclosed_date)}</span>
      : b.incident_date
        ? <span title="No separate disclosure date on record; showing incident date" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>~{fmtDate(b.incident_date)}</span>
        : <span style={{ color: COLORS.boneDim, fontFamily: FONT_MONO }}>-</span>),
  },
  {
    key: 'records', label: 'Records', sortKey: 'records_affected_est', align: 'right',
    text: (b) => (b.records_affected_est != null ? String(b.records_affected_est) : ''),
    cell: (b) => (b.records_affected_est != null
      ? <span style={{ color: COLORS.bone, fontFamily: FONT_MONO }}>{fmtNumber(b.records_affected_est)}</span>
      : <span style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 12 }}>undisclosed</span>),
  },
  {
    key: 'sources', label: 'Sources', sortKey: 'source_count', align: 'center',
    text: (b) => String(b.source_count ?? ''),
    cell: (b) => <span className="text-xs px-2 py-0.5 rounded-full" style={{ fontFamily: FONT_MONO, backgroundColor: COLORS.panelAlt, color: COLORS.boneDim, border: `1px solid ${COLORS.line}` }}>{b.source_count}</span>,
  },
  {
    key: 'severity', label: 'Severity', align: 'left',
    text: (b) => b.severity || 'unrated',
    cell: (b) => <SeverityTag severity={b.severity} />,
  },
];

const alignClass = (a) => (a === 'right' ? 'text-right' : a === 'center' ? 'text-center' : 'text-left');

export function visibleColumns(hiddenCols = []) {
  return LEDGER_COLUMNS.filter((c) => c.locked || !hiddenCols.includes(c.key));
}
export function rowToTsv(b, cols) { return cols.map((c) => c.text(b)).join('\t'); }

export function LedgerRow({ b, cols, pad, onOpen, onActorClick }) {
  const [copied, setCopied] = React.useState(false);
  const copy = (e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(rowToTsv(b, cols)).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1000); });
  };
  return (
    <tr onClick={() => onOpen(b)} className="cursor-pointer transition-colors group hover:bg-white/[0.03]" style={{ borderBottom: `1px solid ${COLORS.lineFaint}` }}>
      {cols.map((c, i) => (
        <td key={c.key}
          className={`${pad} text-sm ${alignClass(c.align)} ${c.align !== 'left' || c.key === 'incident' || c.key === 'disclosed' ? 'whitespace-nowrap' : ''}`}
          style={{ paddingLeft: i === 0 ? 24 : undefined }}>
          {c.cell(b, { onActorClick })}
        </td>
      ))}
      <td className={`${pad} text-right whitespace-nowrap`} style={{ paddingRight: 24 }}>
        <span className="inline-flex items-center gap-2 justify-end">
          <button onClick={copy} title="Copy row (tab-separated)" aria-label="Copy row"
            className="opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: copied ? COLORS.teal : COLORS.boneFaint }}>
            {copied ? <Check size={13} /> : <Copy size={13} />}
          </button>
          {b.status === 'disputed'
            ? <Tag style={{ color: COLORS.amber, backgroundColor: 'rgba(217,142,51,0.12)' }}>Disputed</Tag>
            : <ChevronRight size={15} color={COLORS.boneFaint} className="inline-block" />}
        </span>
      </td>
    </tr>
  );
}

export function LedgerCard({ b, onOpen, onActorClick }) {
  return (
    <button
      onClick={() => onOpen(b)}
      className="w-full text-left px-4 py-3 active:bg-white/[0.04]"
      style={{ borderBottom: `1px solid ${COLORS.lineFaint}` }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-medium truncate" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{b.canonical_name}</div>
          <div className="text-xs truncate" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
            {[INDUSTRY_LABELS[b.industry] || b.industry, [b.region_state, b.country].filter(Boolean).join(', ')].filter(Boolean).join(' · ') || '-'}
          </div>
        </div>
        <SeverityTag severity={b.severity} />
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs" style={{ fontFamily: FONT_MONO, color: COLORS.boneDim }}>
        {b.ransomware_group ? (
          <span
            role="button"
            onClick={(e) => { e.stopPropagation(); onActorClick?.(b.ransomware_group); }}
            title={`View ${b.ransomware_group} threat-actor profile`}
            style={{ color: COLORS.red }}
          >
            {b.ransomware_group}
          </span>
        ) : <span style={{ color: COLORS.boneFaint }}>Unattributed</span>}
        <span>{b.disclosed_date ? fmtDate(b.disclosed_date) : (b.incident_date ? `~${fmtDate(b.incident_date)}` : '-')}</span>
        <span>{b.records_affected_est != null ? `${fmtNumber(b.records_affected_est)} recs` : 'undisclosed'}</span>
        <span style={{ color: COLORS.boneFaint }}>{b.source_count} src</span>
      </div>
    </button>
  );
}

export function LedgerTable({ rows, onOpen, onActorClick, page, totalPages, setPage, total, pageSize, sortBy, sortDir, onSort, hiddenCols = [], density = 'comfortable' }) {
  const cols = visibleColumns(hiddenCols);
  const pad = density === 'compact' ? 'px-4 py-1.5' : 'px-4 py-3';
  const startIdx = (page - 1) * pageSize + 1;
  const endIdx = Math.min(page * pageSize, total);

  return (
    <div>
      {/* Desktop: full sortable table. Hidden below md, where a multi-column
          table is unusable — a card list renders instead. */}
      <div className="overflow-x-auto hidden md:block">
        <table className="w-full" style={{ borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${COLORS.line}` }}>
              {cols.map((c, i) => (
                <th
                  key={c.key}
                  className={`px-4 py-2 text-xs uppercase font-medium whitespace-nowrap ${alignClass(c.align)}`}
                  style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.06em', ...(i === 0 ? { paddingLeft: 24 } : {}) }}
                >
                  {c.sortKey ? (
                    <button
                      onClick={() => onSort?.(c.sortKey)}
                      className="uppercase hover:underline inline-flex items-center gap-1"
                      title={`Sort by ${c.label.toLowerCase()}`}
                      style={{
                        fontFamily: FONT_MONO, letterSpacing: '0.06em',
                        color: sortBy === c.sortKey ? COLORS.amber : COLORS.boneFaint,
                      }}
                    >
                      {c.label}{sortBy === c.sortKey ? (sortDir === 'desc' ? ' ↓' : ' ↑') : ''}
                    </button>
                  ) : c.label}
                </th>
              ))}
              <th className="px-6 py-2" />
            </tr>
          </thead>
          <tbody>
            {rows.map((b) => <LedgerRow key={b.id} b={b} cols={cols} pad={pad} onOpen={onOpen} onActorClick={onActorClick} />)}
          </tbody>
        </table>
      </div>

      {/* Mobile: one card per breach. */}
      <div className="md:hidden">
        {rows.map((b) => <LedgerCard key={b.id} b={b} onOpen={onOpen} onActorClick={onActorClick} />)}
      </div>

      {rows.length === 0 && (
        <div className="flex flex-col items-center py-16 gap-2">
          <Inbox size={28} color={COLORS.boneFaint} />
          <p style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }} className="text-sm">
            No breaches match these filters. Try widening the date range or clearing a filter.
          </p>
        </div>
      )}
      <div className="flex items-center justify-between px-6 py-4" style={{ borderTop: `1px solid ${COLORS.line}` }}>
        <span className="text-xs" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint }}>
          Showing {total === 0 ? 0 : startIdx} to {endIdx} of {total} · never the full dataset
        </span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPage(Math.max(1, page - 1))}
            disabled={page === 1}
            className="p-1.5 rounded disabled:opacity-30"
            style={{ border: `1px solid ${COLORS.line}` }}
          >
            <ChevronLeft size={14} color={COLORS.boneDim} />
          </button>
          <span className="text-xs px-2" style={{ fontFamily: FONT_MONO, color: COLORS.boneDim }}>
            Page {page} of {totalPages || 1}
          </span>
          <button
            onClick={() => setPage(Math.min(totalPages, page + 1))}
            disabled={page >= totalPages}
            className="p-1.5 rounded disabled:opacity-30"
            style={{ border: `1px solid ${COLORS.line}` }}
          >
            <ChevronRight size={14} color={COLORS.boneDim} />
          </button>
        </div>
      </div>
    </div>
  );
}

// Desktop table controls: row density, column show/hide, copy-page, and named
// saved views (filters + sort + columns + density persisted in localStorage).
export function TableToolbar({ density, setDensity, hiddenCols, setHiddenCols, rows, views, onSaveView, onApplyView, onDeleteView }) {
  const [menu, setMenu] = React.useState(null);
  const [copied, setCopied] = React.useState(false);
  const cols = visibleColumns(hiddenCols);
  const toggleCol = (key) =>
    setHiddenCols(hiddenCols.includes(key) ? hiddenCols.filter((k) => k !== key) : [...hiddenCols, key]);
  const copyPage = () => {
    const header = cols.map((c) => c.label).join('\t');
    const body = (rows || []).map((b) => rowToTsv(b, cols)).join('\n');
    navigator.clipboard?.writeText([header, body].filter(Boolean).join('\n'))
      .then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); });
  };
  const chip = { fontFamily: FONT_MONO, color: COLORS.boneDim, border: `1px solid ${COLORS.line}` };

  return (
    <div className="hidden md:flex items-center gap-2 px-6 py-2 relative" style={{ borderBottom: `1px solid ${COLORS.lineFaint}` }}>
      <div className="inline-flex rounded-md overflow-hidden" style={{ border: `1px solid ${COLORS.line}` }} title="Row density">
        {['comfortable', 'compact'].map((d) => (
          <button key={d} onClick={() => setDensity(d)} className="text-xs px-2 py-1"
            style={{ fontFamily: FONT_MONO, color: density === d ? COLORS.ink : COLORS.boneDim, backgroundColor: density === d ? COLORS.amber : 'transparent' }}>
            {d === 'comfortable' ? 'Comfortable' : 'Compact'}
          </button>
        ))}
      </div>

      <div className="relative">
        <button onClick={() => setMenu(menu === 'cols' ? null : 'cols')} className="inline-flex items-center gap-1 rounded-md text-xs px-2 py-1" style={chip}>
          <SlidersHorizontal size={12} /> Columns <ChevronDown size={11} />
        </button>
        {menu === 'cols' && (
          <div className="absolute z-30 mt-1 rounded-md p-1" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}`, minWidth: 180 }}>
            {LEDGER_COLUMNS.map((c) => {
              const shown = c.locked || !hiddenCols.includes(c.key);
              return (
                <button key={c.key} disabled={c.locked} onClick={() => toggleCol(c.key)}
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-xs rounded hover:bg-white/[0.04] disabled:opacity-50"
                  style={{ fontFamily: FONT_BODY, color: COLORS.bone }}>
                  <span style={{ width: 12, display: 'inline-flex' }}>{shown ? <Check size={12} color={COLORS.teal} /> : null}</span>
                  {c.label}{c.locked ? ' · locked' : ''}
                </button>
              );
            })}
          </div>
        )}
      </div>

      <button onClick={copyPage} title="Copy this page as tab-separated values (with header)"
        className="inline-flex items-center gap-1 rounded-md text-xs px-2 py-1" style={{ ...chip, color: copied ? COLORS.teal : COLORS.boneDim }}>
        {copied ? <Check size={12} /> : <Copy size={12} />} Copy page
      </button>

      <div className="relative ml-auto">
        <button onClick={() => setMenu(menu === 'views' ? null : 'views')} className="inline-flex items-center gap-1 rounded-md text-xs px-2 py-1" style={chip}>
          <Save size={12} /> Views <ChevronDown size={11} />
        </button>
        {menu === 'views' && (
          <div className="absolute right-0 z-30 mt-1 rounded-md p-1" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}`, minWidth: 220 }}>
            <button onClick={() => { setMenu(null); onSaveView(); }} className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-xs rounded hover:bg-white/[0.04]" style={{ fontFamily: FONT_BODY, color: COLORS.teal }}>
              <Save size={12} /> Save current view…
            </button>
            {(views || []).length > 0 && <div style={{ borderTop: `1px solid ${COLORS.lineFaint}`, margin: '4px 0' }} />}
            {(views || []).map((v) => (
              <div key={v.name} className="flex items-center gap-1">
                <button onClick={() => { setMenu(null); onApplyView(v); }} className="flex-1 text-left text-xs px-2 py-1.5 rounded truncate hover:bg-white/[0.04]" style={{ fontFamily: FONT_BODY, color: COLORS.bone }} title="Apply this view">
                  {v.name}
                </button>
                <button onClick={() => onDeleteView(v.name)} title="Delete view" className="px-1.5 py-1 rounded" style={{ color: COLORS.boneFaint }}>
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
            {(views || []).length === 0 && <div className="px-2 py-1.5 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>No saved views yet.</div>}
          </div>
        )}
      </div>
    </div>
  );
}

/* ----------------------------- detail drawer ------------------------------ */

function disclosureLag(incident, disclosed) {
  if (!incident || !disclosed) return '-';
  const days = Math.round((new Date(disclosed + 'T00:00:00') - new Date(incident + 'T00:00:00')) / 86400000);
  if (Number.isNaN(days)) return '-';
  if (days <= 0) return 'same day';
  return `${days} day${days === 1 ? '' : 's'}`;
}

// Researcher tool: one-click plain-text case summary for notes / reports.
function breachReportText(breach) {
  const lines = [
    `# ${breach.canonical_name}: breach summary`,
    '',
    `Incident date:      ${breach.incident_date || 'unknown'}`,
    `Publicly disclosed: ${breach.disclosed_date || 'unknown'}`,
    `Threat actor:       ${breach.ransomware_group || 'unattributed'}`,
    `Records affected:   ${breach.records_affected_est ?? 'undisclosed'}`,
    `Industry:           ${breach.industry || 'unknown'}`,
    `Location:           ${[breach.region_state, breach.country].filter(Boolean).join(', ') || 'unknown'}`,
    `Severity:           ${breach.severity || 'unrated'}`,
    `Status:             ${breach.status || 'confirmed'}`,
    `Data exposed:       ${(breach.data_types_exposed || []).join(', ') || 'unknown'}`,
  ];
  if (breach.summary) lines.push('', `Summary: ${breach.summary}`);
  const sources = breach.linked_sources || [];
  if (sources.length) {
    lines.push('', 'Sources:');
    for (const s of sources) {
      lines.push(`  - [${(s.document_type || 'source').replace(/_/g, ' ')}] ${s.source_name || ''} ${s.published_at ? `(${s.published_at})` : ''}`.trimEnd());
      if (s.url) lines.push(`    ${s.url}`);
    }
  }
  lines.push('', `Case ID: ${breach.id}`);
  return lines.join('\n');
}

function CopyButton({ getText, label, Icon = Copy }) {
  const [done, setDone] = React.useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(getText()).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
      className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md"
      style={{ fontFamily: FONT_MONO, color: done ? COLORS.teal : COLORS.boneDim, border: `1px solid ${COLORS.line}` }}
    >
      {done ? <Check size={12} /> : <Icon size={12} />} {done ? 'Copied' : label}
    </button>
  );
}

// A chronological timeline for the dossier, assembled from the incident and
// disclosure dates plus every dated source and news mention. Deduped by
// date+label and sorted oldest-first.
const TIMELINE_KIND = {
  incident: COLORS.amber,
  disclosed: COLORS.teal,
  source: COLORS.boneDim,
  news: COLORS.boneFaint,
};
function buildTimeline(breach) {
  const events = [];
  const add = (date, label, kind) => {
    if (!date) return;
    const d = String(date).slice(0, 10);
    if (d && d !== 'null') events.push({ date: d, label, kind });
  };
  add(breach.incident_date, 'Incident date', 'incident');
  add(breach.disclosed_date, 'Publicly disclosed', 'disclosed');
  for (const s of breach.linked_sources || []) add(s.published_at, `Reported · ${s.source_name || s.source_category || 'source'}`, 'source');
  for (const n of breach.related_news || []) add(n.published_at, `News · ${n.source_name || 'press'}`, 'news');
  const seen = new Set();
  return events
    .sort((a, b) => a.date.localeCompare(b.date))
    .filter((e) => { const k = e.date + '|' + e.label; if (seen.has(k)) return false; seen.add(k); return true; });
}

function RelatedRow({ b, onOpen }) {
  const sev = SEVERITY_META[b.severity] || SEVERITY_META.unrated;
  return (
    <button onClick={() => onOpen({ id: b.id })} className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-left hover:underline" style={{ border: `1px solid ${COLORS.lineFaint}` }}>
      <span className="inline-block rounded-full shrink-0" style={{ width: 6, height: 6, backgroundColor: sev.text }} />
      <span className="min-w-0 flex-1 truncate text-sm" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{b.canonical_name}</span>
      {b.ransomware_group && <span className="text-xs shrink-0" style={{ color: COLORS.red, fontFamily: FONT_MONO }}>{b.ransomware_group}</span>}
      <span className="text-xs shrink-0" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{fmtDate(b.disclosed_date || b.incident_date)}</span>
    </button>
  );
}

export function BreachDetailDrawer({ breach, onClose, isOpen, loading, error, onOpenActor, onOpenRelated, isWatched, onToggleWatch }) {
  if (!isOpen) return null;
  if (loading || !breach) {
    return (
      <div className="fixed inset-0 z-30 flex justify-end" role="dialog" aria-modal="true">
        <div className="absolute inset-0" style={{ backgroundColor: 'rgba(0,0,0,0.55)' }} onClick={onClose} />
        <div className="relative w-full max-w-md h-full flex flex-col items-center justify-center gap-3 px-8 text-center" style={{ backgroundColor: COLORS.panel, borderLeft: `1px solid ${COLORS.line}` }}>
          {error ? (
            <>
              <span style={{ color: COLORS.red, fontFamily: FONT_MONO, fontSize: 13 }}>
                Couldn't load breach details: {error}
              </span>
              <span style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY, fontSize: 12 }}>
                If this keeps happening, the database's public read access may be missing.
                It is re-applied automatically on the next ingestion run, or run
                db/supabase_grants.sql manually.
              </span>
              <button onClick={onClose} className="mt-2 px-3 py-1.5 rounded-md text-sm" style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneDim, fontFamily: FONT_BODY }}>
                Close
              </button>
            </>
          ) : (
            <span style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 13 }}>Loading breach details…</span>
          )}
        </div>
      </div>
    );
  }
  return (
    <div className="fixed inset-0 z-30 flex justify-end" role="dialog" aria-modal="true">
      <div
        className="absolute inset-0"
        style={{ backgroundColor: 'rgba(0,0,0,0.55)' }}
        onClick={onClose}
      />
      <div
        className="relative w-full max-w-md h-full overflow-y-auto"
        style={{ backgroundColor: COLORS.panel, borderLeft: `1px solid ${COLORS.line}` }}
      >
        <div className="flex items-start justify-between px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
          <div>
            <div className="text-xs uppercase tracking-widest mb-2" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
              Breach details · #{breach.id.slice(0, 8)}
            </div>
            <h2 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 22, fontWeight: 600 }}>
              {breach.canonical_name}
            </h2>
            {/* Corroboration: the single most trust-building signal — how many
                independent sources assert this incident. */}
            {(() => {
              const n = breach.source_count || (breach.linked_sources || []).length || 0;
              const multi = n >= 2;
              return (
                <div className="mt-1.5 inline-flex items-center gap-1.5 text-xs" style={{ fontFamily: FONT_MONO, color: multi ? COLORS.teal : COLORS.boneFaint }}>
                  <ShieldCheck size={12} />
                  {multi ? `Corroborated by ${n} independent sources` : 'Single-source, awaiting corroboration'}
                </div>
              );
            })()}
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md" style={{ border: `1px solid ${COLORS.line}` }}>
            <X size={15} color={COLORS.boneDim} />
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 px-6 py-4" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
          <SeverityTag severity={breach.severity} />
          {breach.severity && (
            <span className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }} title="Severity is estimated from record volume, data sensitivity, and threat-actor attribution, not analyst-assigned.">
              (estimated)
            </span>
          )}
          {breach.industry && (
            <Tag style={{ color: COLORS.bone, backgroundColor: COLORS.panelAlt }}>
              {INDUSTRY_LABELS[breach.industry] || breach.industry}
            </Tag>
          )}
          {breach.ransomware_group && (
            <button
              onClick={() => onOpenActor?.(breach.ransomware_group)}
              title={`View ${breach.ransomware_group} threat-actor profile`}
              className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs hover:underline"
              style={{ color: COLORS.red, backgroundColor: 'rgba(192,71,58,0.12)', fontFamily: FONT_MONO }}
            >
              <ShieldAlert size={11} /> {breach.ransomware_group}
            </button>
          )}
          {breach.status === 'disputed' && (
            <Tag style={{ color: COLORS.amber, backgroundColor: 'rgba(217,142,51,0.12)' }}>Disputed</Tag>
          )}
          <div className="ml-auto flex items-center gap-1">
            <button
              onClick={() => onToggleWatch?.(breach)}
              title={isWatched ? 'Remove from watchlist' : 'Add to watchlist'}
              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs"
              style={{ fontFamily: FONT_MONO, color: isWatched ? COLORS.amber : COLORS.boneDim, border: `1px solid ${COLORS.line}` }}
            >
              <Star size={12} fill={isWatched ? COLORS.amber : 'none'} /> {isWatched ? 'Watching' : 'Watch'}
            </button>
            <CopyButton label="Copy report" getText={() => breachReportText(breach)} />
            <CopyButton
              label="Copy link"
              Icon={Link2}
              getText={() => `${window.location.origin}${window.location.pathname}#breach=${breach.id}`}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
          {[
            ['Incident date', fmtDate(breach.incident_date)],
            ['Publicly disclosed', fmtDate(breach.disclosed_date)],
            ['Time to disclosure', disclosureLag(breach.incident_date, breach.disclosed_date)],
            ['Threat actor', breach.ransomware_group || 'Unattributed'],
            ['Records affected (est.)', fmtNumber(breach.records_affected_est)],
            ['Location', [breach.region_state, breach.country].filter(Boolean).join(', ') || '-'],
            ['Status', (breach.status || 'confirmed').replace(/^./, (c) => c.toUpperCase())],
            ['Correlated sources', breach.source_count],
            ['Avg. match confidence', breach.confidence_avg != null ? `${Math.round(breach.confidence_avg * 100)}%` : '-'],
          ].map(([label, val]) => (
            <div key={label}>
              <div className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{label}</div>
              <div className="text-sm mt-0.5" style={{ color: COLORS.bone, fontFamily: FONT_MONO }}>{val}</div>
            </div>
          ))}
        </div>

        {(() => {
          const events = buildTimeline(breach);
          if (events.length < 2) return null;
          return (
            <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
              <div className="text-xs uppercase tracking-widest mb-3" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
                Timeline
              </div>
              <div className="relative pl-4">
                <div className="absolute top-1 bottom-1" style={{ left: 3, width: 1, backgroundColor: COLORS.line }} />
                {events.map((e, i) => (
                  <div key={i} className="relative flex items-baseline gap-3 pb-2.5 last:pb-0">
                    <span className="absolute rounded-full" style={{ left: -13, top: 5, width: 7, height: 7, backgroundColor: TIMELINE_KIND[e.kind] || COLORS.boneFaint }} />
                    <span className="text-xs shrink-0" style={{ color: COLORS.boneDim, fontFamily: FONT_MONO, width: 96 }}>{fmtDate(e.date)}</span>
                    <span className="text-sm" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{e.label}</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })()}

        {(breach.data_types_exposed || []).length > 0 && (
          <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
            <div className="text-xs uppercase tracking-widest mb-2" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
              Data exposed
            </div>
            <div className="flex flex-wrap gap-1.5">
              {breach.data_types_exposed.map((t) => (
                <Tag key={t} style={{ color: COLORS.amberSoft, backgroundColor: 'rgba(201,154,82,0.10)', border: `1px solid ${COLORS.line}` }}>
                  {String(t).replace(/_/g, ' ')}
                </Tag>
              ))}
            </div>
          </div>
        )}

        {breach.summary && (
          <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
            <div className="text-xs uppercase tracking-widest mb-2" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
              Incident summary
            </div>
            <p className="text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
              {breach.summary}
            </p>
          </div>
        )}

        {(breach.evidence || []).length > 0 && (
          <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
            <div className="text-xs uppercase tracking-widest mb-3" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
              Evidence
            </div>
            <div className="flex flex-wrap gap-3">
              {breach.evidence.map((ev, i) => (
                ev.kind === 'screenshot' ? (
                  <a key={i} href={ev.post || ev.url} target="_blank" rel="noopener noreferrer"
                     className="block rounded-md overflow-hidden" style={{ border: `1px solid ${COLORS.line}`, width: 168 }}
                     title="Open the leak-site post (opens the source in a new tab)">
                    <img
                      src={ev.url} alt="Leak-site post screenshot" loading="lazy" referrerPolicy="no-referrer"
                      className="block w-full" style={{ height: 104, objectFit: 'cover', objectPosition: 'top', backgroundColor: COLORS.ink }}
                      onError={(e) => { e.currentTarget.parentElement.style.display = 'none'; }}
                    />
                    <div className="px-2 py-1 text-xs flex items-center gap-1" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, backgroundColor: COLORS.panelAlt }}>
                      <Archive size={10} /> screenshot{ev.source ? ` · ${ev.source}` : ''}
                    </div>
                  </a>
                ) : (
                  <a key={i} href={ev.url} target="_blank" rel="noopener noreferrer"
                     className="inline-flex items-center gap-1.5 text-sm hover:underline self-start"
                     style={{ color: COLORS.teal, fontFamily: FONT_BODY }}>
                    <ShieldCheck size={13} /> Official disclosure
                    {ev.source ? <span style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 11 }}>· via {ev.source}</span> : null}
                  </a>
                )
              ))}
            </div>
            <div className="mt-2 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
              Screenshots are hotlinked from the source tracker (not re-hosted) as evidence of the leak-site claim.
            </div>
          </div>
        )}

        {(breach.related_news || []).length > 0 && (
          <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
            <div className="flex items-center gap-2 mb-3">
              <Newspaper size={14} color={COLORS.boneFaint} />
              <span className="text-xs uppercase tracking-widest" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
                Related news coverage
              </span>
            </div>
            <div className="flex flex-col gap-2">
              {breach.related_news.map((n, i) => (
                <a key={i} href={n.url} target="_blank" rel="noopener noreferrer"
                   className="group flex items-start gap-2.5 rounded-md px-2.5 py-2 hover:underline"
                   style={{ border: `1px solid ${COLORS.line}` }}
                   title="Opens the outlet's article in a new tab">
                  <ExternalLink size={13} color={COLORS.boneFaint} className="mt-0.5 shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>
                      {n.title}
                    </span>
                    <span className="block text-xs mt-0.5" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
                      {[n.source_name, n.published_at ? fmtDate(n.published_at) : null,
                        n.similarity != null ? `${Math.round(n.similarity * 100)}% name match` : null]
                        .filter(Boolean).join(' · ')}
                    </span>
                  </span>
                </a>
              ))}
            </div>
            <div className="mt-2 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
              Headlines auto-correlated to this company by name within a 7-day window. Links out to the
              outlet, not evidence of the breach itself.
            </div>
          </div>
        )}

        <div className="px-6 py-5">
          <div className="flex items-center gap-2 mb-4">
            <ListChecks size={14} color={COLORS.boneFaint} />
            <span className="text-xs uppercase tracking-widest" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
              Sources &amp; links
            </span>
          </div>
          {(breach.linked_sources || []).length === 0 && (
            <p className="text-sm" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
              No source records linked yet.
            </p>
          )}
          {(breach.linked_sources || []).map((s, i) => (
            <SourceCategoryChip
              key={i}
              category={s.source_category}
              sourceName={s.source_name}
              docType={s.document_type}
              dateStr={s.published_at}
              confidence={s.confidence}
              url={s.url}
              summary={s.summary}
              isLast={i === breach.linked_sources.length - 1}
            />
          ))}
        </div>

        {(() => {
          const rel = breach.related || {};
          const actor = rel.sameActor || [];
          const company = rel.sameCompany || [];
          if (actor.length === 0 && company.length === 0) return null;
          return (
            <div className="px-6 py-5" style={{ borderTop: `1px solid ${COLORS.line}` }}>
              <div className="text-xs uppercase tracking-widest mb-3" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
                Related breaches
              </div>
              {company.length > 0 && (
                <div className="mb-3">
                  <div className="text-xs mb-1.5" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>Other incidents at {breach.canonical_name}</div>
                  <div className="space-y-1">{company.map((b) => <RelatedRow key={b.id} b={b} onOpen={onOpenRelated} />)}</div>
                </div>
              )}
              {actor.length > 0 && (
                <div>
                  <div className="text-xs mb-1.5" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>Other victims of {breach.ransomware_group}</div>
                  <div className="space-y-1">{actor.map((b) => <RelatedRow key={b.id} b={b} onOpen={onOpenRelated} />)}</div>
                </div>
              )}
            </div>
          );
        })()}

        <div className="px-6 pb-6 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
          First seen {fmtDateTime(breach.first_seen_at)} · last updated {fmtDateTime(breach.last_updated_at)}
        </div>
      </div>
    </div>
  );
}

/* -------------------------------- analytics -------------------------------- */

export function ChartCard({ title, children, height = 240 }) {
  return (
    <div className="rounded-lg p-5" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}>
      <div className="text-xs uppercase tracking-widest mb-4" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.1em' }}>
        {title}
      </div>
      <div style={{ width: '100%', height }}>{children}</div>
    </div>
  );
}

export function AnalyticsView({ trends, topGroups, onOpenActor }) {
  const trend = useMemo(() => {
    const byWeek = {};
    (trends || []).forEach((row) => {
      const key = row.week_start;
      byWeek[key] = (byWeek[key] || 0) + Number(row.breach_count);
    });
    return Object.entries(byWeek).sort(([a], [b]) => a.localeCompare(b)).map(([week, count]) => ({
      week: new Date(week + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      count,
    }));
  }, [trends]);

  const byGroup = topGroups || [];

  const byIndustry = useMemo(() => {
    const counts = {};
    (trends || []).forEach((row) => {
      if (!row.industry) return;
      counts[row.industry] = (counts[row.industry] || 0) + Number(row.breach_count);
    });
    return Object.entries(counts).sort(([, a], [, b]) => b - a).map(([industry, count]) => ({
      industry: INDUSTRY_LABELS[industry] || industry, count,
    }));
  }, [trends]);

  const axisStyle = { fontFamily: FONT_MONO, fontSize: 11, fill: COLORS.boneFaint };

  return (
    <div className="grid md:grid-cols-2 gap-5 p-6">
      <div className="md:col-span-2">
        <ChartCard title="Disclosures per week">
          <ResponsiveContainer>
            <AreaChart data={trend}>
              <defs>
                <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={COLORS.amber} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={COLORS.amber} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke={COLORS.lineFaint} vertical={false} />
              <XAxis dataKey="week" tick={axisStyle} axisLine={{ stroke: COLORS.line }} tickLine={false} />
              <YAxis tick={axisStyle} axisLine={false} tickLine={false} width={28} />
              <Tooltip
                contentStyle={{ backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}`, fontFamily: FONT_BODY, fontSize: 12 }}
                labelStyle={{ color: COLORS.bone }}
              />
              <Area type="monotone" dataKey="count" stroke={COLORS.amber} fill="url(#areaFill)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <ChartCard title="Top ransomware groups by victim count (click to open profile)">
        <ResponsiveContainer>
          <BarChart data={byGroup} layout="vertical" margin={{ left: 10 }}>
            <CartesianGrid stroke={COLORS.lineFaint} horizontal={false} />
            <XAxis type="number" tick={axisStyle} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="group" tick={axisStyle} axisLine={false} tickLine={false} width={120} />
            <Tooltip contentStyle={{ backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}`, fontFamily: FONT_BODY, fontSize: 12 }} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="count" fill={COLORS.red} radius={[0, 3, 3, 0]} cursor="pointer"
              onClick={(d) => { const g = d && (d.group ?? d.payload?.group); if (g) onOpenActor?.(g); }} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Breaches by industry">
        <ResponsiveContainer>
          <BarChart data={byIndustry} layout="vertical" margin={{ left: 10 }}>
            <CartesianGrid stroke={COLORS.lineFaint} horizontal={false} />
            <XAxis type="number" tick={axisStyle} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="industry" tick={axisStyle} axisLine={false} tickLine={false} width={120} />
            <Tooltip contentStyle={{ backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}`, fontFamily: FONT_BODY, fontSize: 12 }} />
            <Bar dataKey="count" fill={COLORS.teal} radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
    </div>
  );
}

/* ------------------------------- match queue -------------------------------- */

export function MatchQueueView({ items }) {
  return (
    <div className="p-6">
      <p className="text-sm mb-5" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
        These source records scored below the auto-merge threshold against their closest candidate breach.
        This public view is read-only; an authenticated analyst session is required to approve or reject a match.
      </p>
      {items.length === 0 && (
        <div className="flex flex-col items-center py-16 gap-2">
          <CheckCircle2 size={28} color={COLORS.teal} />
          <p style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }} className="text-sm">Queue is empty. Nothing pending review.</p>
        </div>
      )}
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item.id} className="rounded-lg p-4 flex items-start justify-between gap-4" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span style={{ fontFamily: FONT_BODY, color: COLORS.bone, fontWeight: 500 }}>{item.record_name}</span>
                <span style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLORS.boneFaint }}>vs.</span>
                <span style={{ fontFamily: FONT_BODY, color: COLORS.boneDim }}>{item.candidate_name}</span>
              </div>
              <div className="flex flex-wrap gap-3 text-xs" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint }}>
                <span>name match {item.reasons.name_score}%</span>
                <span>±{item.reasons.date_delta_days}d</span>
                <span>{item.reasons.industry_match ? 'industry ✓' : 'industry ✗'}</span>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span
                className="text-xs px-2 py-1 rounded-full"
                style={{ fontFamily: FONT_MONO, backgroundColor: 'rgba(217,142,51,0.14)', color: COLORS.amber }}
              >
                {item.confidence}% confidence
              </span>
              <span title="This is a public, read-only view. Review actions require an authenticated analyst session." className="p-1.5 rounded-md flex items-center gap-1" style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneFaint }}>
                <Lock size={13} />
                <span className="text-xs" style={{ fontFamily: FONT_MONO }}>read-only</span>
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* --------------------------------- footer ----------------------------------- */

export function Footer({ onAbout }) {
  const categories = [...new Set(Object.keys(SOURCE_CATEGORY_META))];
  return (
    <footer className="px-6 py-6" style={{ borderTop: `1px solid ${COLORS.line}` }}>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap gap-4">
          {categories.map((c) => {
            const { label, Icon } = SOURCE_CATEGORY_META[c];
            return (
              <span key={c} className="flex items-center gap-1.5 text-xs" style={{ fontFamily: FONT_BODY, color: COLORS.boneFaint }}>
                <Icon size={12} /> {label}
              </span>
            );
          })}
        </div>
        <div className="flex items-center gap-4">
          {onAbout && (
            <button onClick={onAbout} className="text-xs hover:underline" style={{ fontFamily: FONT_MONO, color: COLORS.boneDim }}>
              About
            </button>
          )}
        </div>
      </div>
    </footer>
  );
}

