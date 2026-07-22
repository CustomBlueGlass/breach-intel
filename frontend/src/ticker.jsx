import React, { useState } from 'react';
import { Radar, ExternalLink, X } from 'lucide-react';
import { COLORS, FONT_MONO, FONT_BODY, relativeTime } from './constants';

/* ============================================================================
   Threat Radar — a live ticker of fresh threat signals (latest ransomware
   victims, newly exploited CVEs, and — when keys are configured — OTX pulses
   and URLhaus malware URLs). Data is written server-side by app.threat_radar
   and read here read-only. Pure decoration/orientation; never a breach source.
   ========================================================================== */

const KIND_META = {
  ransomware_victim: { color: COLORS.red, tag: 'RANSOMWARE' },
  kev_cve: { color: COLORS.amber, tag: 'EXPLOITED CVE' },
  otx_pulse: { color: COLORS.teal, tag: 'OTX PULSE' },
  malware_url: { color: COLORS.amberSoft, tag: 'MALWARE URL' },
};

const prefersReducedMotion =
  typeof window !== 'undefined' &&
  window.matchMedia &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function Item({ it }) {
  const meta = KIND_META[it.kind] || { color: COLORS.boneDim, tag: 'SIGNAL' };
  const inner = (
    <>
      <span className="inline-block rounded-full shrink-0" style={{ width: 6, height: 6, backgroundColor: meta.color }} />
      <span style={{ color: meta.color, fontFamily: FONT_MONO, fontSize: 10, letterSpacing: '0.06em' }}>{meta.tag}</span>
      <span style={{ color: COLORS.bone, fontFamily: FONT_BODY, fontSize: 13 }}>{it.title}</span>
      {it.subtitle && (
        <span style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 11 }}>{it.subtitle}</span>
      )}
      {it.published_at && (
        <span style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO, fontSize: 10 }}>· {relativeTime(it.published_at)}</span>
      )}
    </>
  );
  const cls = 'inline-flex items-center gap-2 px-4 whitespace-nowrap';
  const style = { borderRight: `1px solid ${COLORS.lineFaint}` };
  return it.url ? (
    <a href={it.url} target="_blank" rel="noopener noreferrer" className={`${cls} hover:opacity-100`} style={{ ...style, opacity: 0.92 }}>
      {inner}
      <ExternalLink size={10} color={COLORS.boneFaint} />
    </a>
  ) : (
    <span className={cls} style={style}>{inner}</span>
  );
}

export function ThreatRadar({ items }) {
  const [hidden, setHidden] = useState(false);
  if (hidden || !items || items.length === 0) return null;

  // Duplicate the sequence so the CSS translate loop is seamless. With
  // reduced motion we render a single, manually-scrollable copy instead.
  const loop = prefersReducedMotion ? items : [...items, ...items];
  // Scale duration to item count so density, not speed, changes with load.
  const durationS = Math.max(30, items.length * 3.5);

  return (
    <div className="w-full flex items-stretch" style={{ backgroundColor: COLORS.panel, borderBottom: `1px solid ${COLORS.line}` }}>
      <style>{`
        @keyframes radar-marquee { from { transform: translateX(0); } to { transform: translateX(-50%); } }
        .radar-track { animation: radar-marquee ${durationS}s linear infinite; }
        .radar-viewport:hover .radar-track { animation-play-state: paused; }
        @media (prefers-reduced-motion: reduce) { .radar-track { animation: none; } }
      `}</style>

      <div className="flex items-center gap-1.5 px-3 shrink-0" style={{ borderRight: `1px solid ${COLORS.line}`, backgroundColor: COLORS.panelAlt }}>
        <span className="relative flex items-center justify-center" style={{ width: 12, height: 12 }}>
          <span className="motion-safe-pulse absolute inline-flex rounded-full" style={{ width: 8, height: 8, backgroundColor: COLORS.red, opacity: 0.75 }} />
          <span className="relative inline-flex rounded-full" style={{ width: 6, height: 6, backgroundColor: COLORS.red }} />
        </span>
        <Radar size={13} color={COLORS.boneDim} />
        <span className="hidden sm:inline" style={{ color: COLORS.boneDim, fontFamily: FONT_MONO, fontSize: 10, letterSpacing: '0.1em' }}>THREAT&nbsp;RADAR</span>
      </div>

      <div className={`radar-viewport relative flex-1 overflow-hidden ${prefersReducedMotion ? 'overflow-x-auto' : ''}`}>
        <div className="radar-track flex items-center py-1.5" style={{ width: prefersReducedMotion ? 'auto' : 'max-content' }}>
          {loop.map((it, i) => <Item key={i} it={it} />)}
        </div>
      </div>

      <button
        onClick={() => setHidden(true)}
        className="flex items-center px-2 shrink-0"
        style={{ borderLeft: `1px solid ${COLORS.line}`, color: COLORS.boneFaint }}
        title="Hide the ticker"
        aria-label="Hide the threat radar ticker"
      >
        <X size={13} />
      </button>
    </div>
  );
}
