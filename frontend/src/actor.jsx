import React, { useMemo } from 'react';
import {
  X, ShieldAlert, Filter, Download, Building2, Copy, Check, Star,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';
import {
  COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO,
  INDUSTRY_LABELS, SEVERITY_META, fmtDate, fmtNumber,
} from './constants';

/* ============================================================================
   Threat-actor profile drawer. Turns the ransomware_group column into a real
   actor page: every attributed victim from our ledger, a victim timeline,
   targeting patterns, curated aliases/context, and STIX/CSV/JSON export.
   Everything here is derived from data we already hold (no fabricated TTPs).
   ========================================================================== */

// Curated, widely-reported context for well-known groups. Aliases augment the
// data-derived "also reported as" list; notes are short and factual. Unknown
// groups simply fall back to victim-derived stats.
export const ACTOR_REFERENCE = {
  'LockBit': { aliases: ['LockBit 2.0', 'LockBit 3.0', 'LockBit Black'], note: 'Prolific ransomware-as-a-service run through affiliates; long one of the most active groups. Disrupted by law enforcement (Operation Cronos, 2024).' },
  'ALPHV/BlackCat': { aliases: ['ALPHV', 'BlackCat', 'Noberus'], note: 'Rust-based ransomware-as-a-service known for a searchable leak site; ran an apparent exit scam in early 2024.' },
  'Clop': { aliases: ['Cl0p', 'TA505-linked'], note: 'Data-theft extortion via mass exploitation of file-transfer software (MOVEit, GoAnywhere, Accellion).' },
  'Akira': { aliases: ['Akira'], note: 'Double-extortion group active since 2023, frequently hitting mid-market victims via VPN access.' },
  'Play': { aliases: ['PlayCrypt'], note: 'Double-extortion group known for intermittent-encryption tooling and custom exfiltration utilities.' },
  '8Base': { aliases: ['8Base'], note: 'Extortion group using a Phobos-based locker; heavy name-and-shame leak-site activity.' },
  'BlackBasta': { aliases: ['Black Basta'], note: 'RaaS with suspected Conti lineage; targets large enterprises with double extortion.' },
  'Medusa': { aliases: ['MedusaLocker'], note: 'RaaS with a public leak/blog site; distinct from the MedusaLocker family it is often confused with.' },
  'Royal': { aliases: ['Royal Ransomware'], note: 'Group with Conti ties; later reporting links it to the BlackSuit rebrand.' },
  'Rhysida': { aliases: ['Rhysida'], note: 'Emerged 2023; notable for attacks on healthcare and public-sector organisations.' },
  'Hunters International': { aliases: ['Hunters International'], note: 'RaaS widely assessed as a rebrand/successor of Hive.' },
  'RansomHub': { aliases: ['RansomHub'], note: 'RaaS that grew rapidly in 2024, absorbing affiliates from disrupted groups.' },
  'Qilin': { aliases: ['Agenda'], note: 'Rust/Go ransomware-as-a-service, also tracked as Agenda.' },
  'BianLian': { aliases: ['BianLian'], note: 'Shifted from encryption to data-theft-only extortion; frequent healthcare targeting.' },
};

const btn = {
  fontFamily: FONT_MONO, color: COLORS.boneDim, border: `1px solid ${COLORS.line}`,
};

function tally(values) {
  const m = {};
  for (const v of values) { if (v) m[v] = (m[v] || 0) + 1; }
  return Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ k, n }));
}

function monthsBetween(a, b) {
  if (!a || !b) return null;
  const d1 = new Date(a + 'T00:00:00'), d2 = new Date(b + 'T00:00:00');
  if (Number.isNaN(d1) || Number.isNaN(d2)) return null;
  return Math.max(0, Math.round((d2 - d1) / (86400000 * 30.4)));
}

function CopyBtn({ getText }) {
  const [done, setDone] = React.useState(false);
  return (
    <button onClick={() => navigator.clipboard?.writeText(getText()).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); })}
      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs" style={{ ...btn, color: done ? COLORS.teal : COLORS.boneDim }}>
      {done ? <Check size={11} /> : <Copy size={11} />} {done ? 'Copied' : 'Copy summary'}
    </button>
  );
}

function StatCell({ label, value }) {
  return (
    <div>
      <div className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{label}</div>
      <div className="text-sm mt-0.5" style={{ color: COLORS.bone, fontFamily: FONT_MONO }}>{value}</div>
    </div>
  );
}

export function actorSummaryText(group, stats, aliases) {
  return [
    `# ${group}: threat-actor profile`,
    '',
    `Victims (attributed):  ${stats.count}`,
    `First seen:            ${fmtDate(stats.firstSeen)}`,
    `Last seen:             ${fmtDate(stats.lastSeen)}`,
    `Top industry:          ${stats.industries[0] ? (INDUSTRY_LABELS[stats.industries[0].k] || stats.industries[0].k) : 'n/a'}`,
    aliases.length ? `Also reported as:      ${aliases.join(', ')}` : '',
    '',
    'Source: breach-intel ledger (attributed victims).',
  ].filter((l) => l !== '').join('\n');
}

export function ThreatActorDrawer({ group, profile, isOpen, loading, error, onClose, onOpenBreach, onFilterLedger, onExport, isWatched, onToggleWatch }) {
  const stats = useMemo(() => {
    const vs = profile?.victims || [];
    const dates = vs.map((v) => v.disclosed_date || v.incident_date).filter(Boolean).sort();
    const byMonthMap = {};
    for (const v of vs) {
      const d = v.disclosed_date || v.incident_date;
      if (d) { const m = String(d).slice(0, 7); byMonthMap[m] = (byMonthMap[m] || 0) + 1; }
    }
    const byMonth = Object.entries(byMonthMap).sort().slice(-24).map(([m, n]) => ({
      month: new Date(m + '-01T00:00:00').toLocaleDateString('en-US', { month: 'short', year: '2-digit' }),
      n,
    }));
    return {
      count: vs.length,
      firstSeen: dates[0] || null,
      lastSeen: dates[dates.length - 1] || null,
      byMonth,
      industries: tally(vs.map((v) => v.industry)),
      countries: tally(vs.map((v) => v.country)),
    };
  }, [profile]);

  const ref = ACTOR_REFERENCE[group] || {};
  const aliases = useMemo(() => {
    const set = new Map();
    for (const a of (ref.aliases || [])) set.set(a.toLowerCase(), a);
    for (const a of (profile?.aliases || [])) if (!set.has(a.toLowerCase())) set.set(a.toLowerCase(), a);
    return [...set.values()];
  }, [ref.aliases, profile]);
  const span = monthsBetween(stats.firstSeen, stats.lastSeen);

  // All hooks above run every render; only the output below is conditional.
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-30 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0" style={{ backgroundColor: 'rgba(0,0,0,0.55)' }} onClick={onClose} />
      <div className="relative w-full max-w-md h-full overflow-y-auto" style={{ backgroundColor: COLORS.panel, borderLeft: `1px solid ${COLORS.line}` }}>

        <div className="flex items-start justify-between px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
          <div>
            <div className="text-xs uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>
              <ShieldAlert size={12} color={COLORS.red} /> Threat-actor profile
            </div>
            <h2 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 22, fontWeight: 600 }}>{group}</h2>
            <div className="mt-1 text-xs" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint }}>Ransomware / extortion group</div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md" style={{ border: `1px solid ${COLORS.line}` }}>
            <X size={15} color={COLORS.boneDim} />
          </button>
        </div>

        {loading ? (
          <div className="px-6 py-10 text-sm text-center" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
            {error ? `Couldn't load actor: ${error}` : 'Loading actor profile…'}
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 px-6 py-4" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
              <button onClick={() => onToggleWatch?.(group)} title={isWatched ? 'Remove from watchlist' : 'Add to watchlist'}
                className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs" style={{ ...btn, color: isWatched ? COLORS.amber : COLORS.boneDim }}>
                <Star size={11} fill={isWatched ? COLORS.amber : 'none'} /> {isWatched ? 'Watching' : 'Watch'}
              </button>
              <button onClick={() => onFilterLedger(group)} className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs" style={btn}>
                <Filter size={11} /> Filter ledger
              </button>
              <button onClick={() => onExport('csv')} className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs" style={btn}>
                <Download size={11} /> CSV
              </button>
              <button onClick={() => onExport('json')} className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs" style={btn}>
                <Download size={11} /> JSON
              </button>
              <button onClick={() => onExport('stix')} className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs" style={btn} title="STIX 2.1 bundle (intrusion-set + victim identities + targets relationships)">
                <Download size={11} /> STIX
              </button>
              <div className="ml-auto"><CopyBtn getText={() => actorSummaryText(group, stats, aliases)} /></div>
            </div>

            {aliases.length > 0 && (
              <div className="px-6 py-4" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
                <div className="text-xs uppercase tracking-widest mb-2" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>Also reported as</div>
                <div className="flex flex-wrap gap-1.5">
                  {aliases.map((a) => (
                    <span key={a} className="text-xs px-2 py-0.5 rounded" style={{ fontFamily: FONT_MONO, color: COLORS.boneDim, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}` }}>{a}</span>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
              <StatCell label="Attributed victims" value={stats.count} />
              <StatCell label="Active span" value={span == null ? '-' : span < 1 ? '<1 mo' : `${span} mo`} />
              <StatCell label="First seen" value={fmtDate(stats.firstSeen)} />
              <StatCell label="Last seen" value={fmtDate(stats.lastSeen)} />
              <StatCell label="Top industry" value={stats.industries[0] ? (INDUSTRY_LABELS[stats.industries[0].k] || stats.industries[0].k) : '-'} />
              <StatCell label="Top country" value={stats.countries[0]?.k || '-'} />
            </div>

            {ref.note && (
              <div className="px-6 py-4" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
                <p className="text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>{ref.note}</p>
              </div>
            )}

            {stats.byMonth.length > 1 && (
              <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
                <div className="text-xs uppercase tracking-widest mb-3" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>Victim activity</div>
                <div style={{ width: '100%', height: 140 }}>
                  <ResponsiveContainer>
                    <BarChart data={stats.byMonth} margin={{ top: 4, right: 4, bottom: 0, left: -24 }}>
                      <XAxis dataKey="month" tick={{ fill: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 9 }} interval="preserveStartEnd" />
                      <YAxis allowDecimals={false} tick={{ fill: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 9 }} />
                      <Tooltip cursor={{ fill: 'rgba(255,255,255,0.04)' }} contentStyle={{ backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}`, fontFamily: FONT_MONO, fontSize: 12 }} labelStyle={{ color: COLORS.bone }} />
                      <Bar dataKey="n" fill={COLORS.red} radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {stats.industries.length > 0 && (
              <div className="px-6 py-5" style={{ borderBottom: `1px solid ${COLORS.line}` }}>
                <div className="text-xs uppercase tracking-widest mb-2" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>Targeting (top industries)</div>
                <div className="space-y-1.5">
                  {stats.industries.slice(0, 5).map(({ k, n }) => (
                    <div key={k} className="flex items-center gap-2">
                      <span className="text-xs w-32 shrink-0 truncate" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>{INDUSTRY_LABELS[k] || k}</span>
                      <div className="flex-1 h-2 rounded" style={{ backgroundColor: COLORS.ink }}>
                        <div className="h-2 rounded" style={{ width: `${Math.round((n / stats.count) * 100)}%`, backgroundColor: COLORS.amber }} />
                      </div>
                      <span className="text-xs w-6 text-right" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{n}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="px-6 py-5">
              <div className="flex items-center gap-2 mb-3">
                <Building2 size={14} color={COLORS.boneFaint} />
                <span className="text-xs uppercase tracking-widest" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>Victims ({stats.count})</span>
              </div>
              {stats.count === 0 && (
                <p className="text-sm" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>No attributed victims in the ledger yet.</p>
              )}
              <div className="space-y-1">
                {(profile?.victims || []).map((v) => {
                  const sev = SEVERITY_META[v.severity] || SEVERITY_META.unrated;
                  return (
                    <button key={v.id} onClick={() => onOpenBreach({ id: v.id })}
                      className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-left hover:underline"
                      style={{ border: `1px solid ${COLORS.lineFaint}` }}>
                      <span className="inline-block rounded-full shrink-0" style={{ width: 6, height: 6, backgroundColor: sev.text }} />
                      <span className="min-w-0 flex-1 truncate text-sm" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{v.canonical_name}</span>
                      {v.records_affected_est != null && (
                        <span className="text-xs shrink-0" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{fmtNumber(v.records_affected_est)}</span>
                      )}
                      <span className="text-xs shrink-0" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{fmtDate(v.disclosed_date || v.incident_date)}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="px-6 pb-6 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
              Profile is derived from attributed ledger victims plus curated public references. It is not an exhaustive
              actor dossier, and victim counts reflect only incidents tracked here.
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// STIX 2.1 bundle: an intrusion-set for the actor, an identity per victim, and
// a "targets" relationship from the actor to each victim. Lets analysts pull
// the attribution straight into OpenCTI / MISP / a TIP.
export function actorStixBundle(group, victims, aliases) {
  const now = new Date().toISOString();
  const uuid = () => (crypto?.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);
  const actorId = `intrusion-set--${uuid()}`;
  const objects = [{
    type: 'intrusion-set',
    spec_version: '2.1',
    id: actorId,
    created: now,
    modified: now,
    name: group,
    aliases: aliases && aliases.length ? aliases : undefined,
    resource_level: 'group',
    primary_motivation: 'financial-gain',
  }];
  for (const v of victims) {
    const idId = `identity--${uuid()}`;
    objects.push({
      type: 'identity', spec_version: '2.1', id: idId, created: now, modified: now,
      name: v.canonical_name, identity_class: 'organization',
      sectors: v.industry ? [v.industry] : undefined,
    });
    objects.push({
      type: 'relationship', spec_version: '2.1', id: `relationship--${uuid()}`,
      created: now, modified: now, relationship_type: 'targets',
      source_ref: actorId, target_ref: idId,
      start_time: v.incident_date ? `${v.incident_date}T00:00:00Z` : undefined,
    });
  }
  return { type: 'bundle', id: `bundle--${uuid()}`, objects };
}
