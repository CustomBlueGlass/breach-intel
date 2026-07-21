import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Search, CornerDownLeft, Building2, ShieldAlert, Wrench, BarChart3, ListChecks } from 'lucide-react';
import { COLORS, FONT_BODY, FONT_MONO, INDUSTRY_LABELS, fmtDate } from './constants';
import { searchLedger } from './lib/api';

/* ============================================================================
   Command palette (Cmd/Ctrl-K) — jump to any company or threat actor, or run
   a quick action, without leaving the keyboard. The friction-killer for
   navigation.
   ========================================================================== */

const ACTIONS = [
  { id: 'go-ledger', label: 'Go to Ledger', tab: 'ledger', Icon: ListChecks },
  { id: 'go-analytics', label: 'Go to Analytics', tab: 'analytics', Icon: BarChart3 },
  { id: 'go-tools', label: 'Go to Analyst tools', tab: 'tools', Icon: Wrench },
];

export function CommandPalette({ open, setOpen, onOpenBreach, onFilterActor, onSetTab }) {
  const [q, setQ] = useState('');
  const [results, setResults] = useState([]);
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);

  // Global Cmd/Ctrl-K toggle + Esc close.
  useEffect(() => {
    function onKey(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === 'Escape') {
        setOpen(false);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [setOpen]);

  useEffect(() => {
    if (open) { setQ(''); setResults([]); setActive(0); setTimeout(() => inputRef.current?.focus(), 0); }
  }, [open]);

  // Debounced company/actor search.
  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => {
      if (!q.trim()) { setResults([]); return; }
      searchLedger(q, 8).then(setResults).catch(() => setResults([]));
    }, 180);
    return () => clearTimeout(t);
  }, [q, open]);

  // Build a flat, ordered item list: actions (when no query) + company hits.
  const actionItems = q.trim()
    ? ACTIONS.filter((a) => a.label.toLowerCase().includes(q.toLowerCase()))
    : ACTIONS;
  const companyItems = results.map((r) => ({ id: `b-${r.id}`, kind: 'company', row: r }));
  const items = [...actionItems.map((a) => ({ id: a.id, kind: 'action', action: a })), ...companyItems];

  useEffect(() => { setActive(0); }, [q, results.length]);

  const run = useCallback((item) => {
    if (!item) return;
    setOpen(false);
    if (item.kind === 'action') onSetTab(item.action.tab);
    else if (item.kind === 'company') onOpenBreach(item.row);
  }, [onOpenBreach, onSetTab, setOpen]);

  function onInputKey(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(i + 1, items.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); run(items[active]); }
  }

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="absolute inset-0" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }} onClick={() => setOpen(false)} />
      <div className="relative mt-24 w-full max-w-lg rounded-lg overflow-hidden"
           style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}`, boxShadow: '0 20px 60px rgba(0,0,0,0.5)' }}>
        <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
          <Search size={16} color={COLORS.boneFaint} />
          <input
            ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onInputKey}
            placeholder="Search companies, threat actors, or actions…"
            className="flex-1 bg-transparent outline-none text-sm"
            style={{ fontFamily: FONT_BODY, color: COLORS.bone }}
          />
          <kbd className="text-xs px-1.5 py-0.5 rounded" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, border: `1px solid ${COLORS.line}` }}>esc</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto py-1">
          {items.length === 0 && (
            <div className="px-4 py-6 text-sm text-center" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
              {q.trim() ? 'No matches' : 'Type to search the ledger'}
            </div>
          )}
          {items.map((item, i) => {
            const isActive = i === active;
            const base = {
              backgroundColor: isActive ? COLORS.panelAlt : 'transparent',
            };
            if (item.kind === 'action') {
              const A = item.action.Icon;
              return (
                <button key={item.id} onMouseEnter={() => setActive(i)} onClick={() => run(item)}
                        className="w-full flex items-center gap-3 px-4 py-2 text-left" style={base}>
                  <A size={15} color={COLORS.boneDim} />
                  <span className="text-sm" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{item.action.label}</span>
                  {isActive && <CornerDownLeft size={13} color={COLORS.boneFaint} className="ml-auto" />}
                </button>
              );
            }
            const r = item.row;
            return (
              <div key={item.id} style={base}>
                <button onMouseEnter={() => setActive(i)} onClick={() => run(item)}
                        className="w-full flex items-center gap-3 px-4 py-2 text-left">
                  <Building2 size={15} color={COLORS.boneDim} className="shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm truncate" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{r.canonical_name}</span>
                    <span className="block text-xs truncate" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
                      {[INDUSTRY_LABELS[r.industry] || r.industry, r.ransomware_group, fmtDate(r.disclosed_date || r.incident_date)].filter(Boolean).join(' · ')}
                    </span>
                  </span>
                  {r.ransomware_group && (
                    <button
                      onClick={(e) => { e.stopPropagation(); setOpen(false); onFilterActor(r.ransomware_group); }}
                      className="shrink-0 inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded hover:underline"
                      style={{ color: COLORS.red, fontFamily: FONT_MONO, border: `1px solid ${COLORS.line}` }}
                      title={`Filter ledger to ${r.ransomware_group}`}
                    >
                      <ShieldAlert size={10} /> {r.ransomware_group}
                    </button>
                  )}
                </button>
              </div>
            );
          })}
        </div>
        <div className="flex items-center gap-3 px-4 py-2 text-xs" style={{ borderTop: `1px solid ${COLORS.line}`, color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
          <span>↑↓ navigate</span><span>↵ open</span><span className="ml-auto">⌘K / Ctrl-K</span>
        </div>
      </div>
    </div>
  );
}
