import React from 'react';
import { Star, Clock, Building2, ShieldAlert, X, Trash2, Bookmark } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';

/* ============================================================================
   Analyst workspace — a personal, browser-local layer over the public ledger:
   a watchlist (starred companies + threat actors) and a recently-viewed trail.
   Everything lives in localStorage; nothing is sent anywhere.
   ========================================================================== */

function Section({ icon: Icon, title, action, children }) {
  return (
    <div className="rounded-lg" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}>
      <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
        <Icon size={14} color={COLORS.boneFaint} />
        <span className="text-xs uppercase tracking-widest" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>{title}</span>
        <div className="ml-auto">{action}</div>
      </div>
      <div className="p-2">{children}</div>
    </div>
  );
}

function Empty({ text }) {
  return <div className="px-2 py-6 text-sm text-center" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{text}</div>;
}

function Item({ icon: Icon, label, sub, color, onOpen, onRemove }) {
  return (
    <div className="group flex items-center gap-2 px-2 py-1.5 rounded" style={{ borderBottom: `1px solid ${COLORS.lineFaint}` }}>
      <Icon size={13} color={color || COLORS.boneDim} className="shrink-0" />
      <button onClick={onOpen} className="min-w-0 flex-1 text-left hover:underline">
        <span className="block text-sm truncate" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{label}</span>
        {sub && <span className="block text-xs truncate" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{sub}</span>}
      </button>
      {onRemove && (
        <button onClick={onRemove} title="Remove" className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: COLORS.boneFaint }}>
          <X size={13} />
        </button>
      )}
    </div>
  );
}

export function WorkspaceView({ watchlist, recent, onOpenBreach, onOpenActor, onRemoveWatchBreach, onRemoveWatchActor, onClearRecent }) {
  const wb = watchlist?.breaches || [];
  const wa = watchlist?.actors || [];
  const rb = recent?.breaches || [];
  const ra = recent?.actors || [];
  const recentEmpty = rb.length === 0 && ra.length === 0;

  return (
    <div className="px-6 py-6">
      <div className="flex items-center gap-2 mb-1">
        <Bookmark size={16} color={COLORS.amber} />
        <h2 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 22, fontWeight: 600 }}>Workspace</h2>
      </div>
      <p className="text-sm mb-5 max-w-2xl" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
        Your saved companies and threat actors, plus what you have looked at recently. Stored only in this browser.
      </p>

      <div className="grid gap-5 md:grid-cols-2">
        <Section icon={Star} title={`Watchlist · companies (${wb.length})`}>
          {wb.length === 0 ? <Empty text="Star a company from its details panel to pin it here." /> : wb.map((b) => (
            <Item key={b.id} icon={Building2} label={b.canonical_name || b.id}
              onOpen={() => onOpenBreach({ id: b.id, canonical_name: b.canonical_name })}
              onRemove={() => onRemoveWatchBreach(b.id)} />
          ))}
        </Section>

        <Section icon={Star} title={`Watchlist · threat actors (${wa.length})`}>
          {wa.length === 0 ? <Empty text="Star a threat actor from its profile to pin it here." /> : wa.map((g) => (
            <Item key={g} icon={ShieldAlert} color={COLORS.red} label={g}
              onOpen={() => onOpenActor(g)} onRemove={() => onRemoveWatchActor(g)} />
          ))}
        </Section>

        <Section
          icon={Clock}
          title="Recently viewed"
          action={!recentEmpty && (
            <button onClick={onClearRecent} title="Clear recently viewed" className="inline-flex items-center gap-1 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
              <Trash2 size={11} /> Clear
            </button>
          )}
        >
          {recentEmpty ? <Empty text="Companies and actors you open will show up here." /> : (
            <>
              {rb.map((b) => (
                <Item key={`b-${b.id}`} icon={Building2} label={b.canonical_name || b.id}
                  onOpen={() => onOpenBreach({ id: b.id, canonical_name: b.canonical_name })} />
              ))}
              {ra.map((g) => (
                <Item key={`a-${g}`} icon={ShieldAlert} color={COLORS.red} label={g} sub="threat actor"
                  onOpen={() => onOpenActor(g)} />
              ))}
            </>
          )}
        </Section>
      </div>
    </div>
  );
}
