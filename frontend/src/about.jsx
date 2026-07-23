import React from 'react';
import { ShieldAlert, Check } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';

/* Concise About page: what the platform is and what it can do. */

const CAN_DO = [
  'Browse, filter, and sort a ledger of breached companies by industry, threat actor, attribution, and date.',
  'Open any company for a full dossier: incident and disclosure dates, threat actor, records affected, data types exposed, an incident timeline, leak-site evidence, all sources, and related news coverage.',
  'Explore threat-actor profiles: attributed victims, activity timeline, targeting, aliases, and STIX 2.1 export.',
  'Watch the live Threat Radar ticker: latest ransomware victims and newly exploited CVEs.',
  'Use free, browser-only analyst tools: IOC extractor, enrichment launchpad, CIDR calculator, hash identifier, URL dissector, CVSS, JWT, base64, hashing, entropy, and more.',
  'Keep a personal workspace: watchlist and recently-viewed, saved table views, adjustable columns and density.',
  'Export any view as CSV, JSON, or STIX 2.1.',
];

const HOW = [
  'Sources: ransomware leak-site trackers, US state AG breach notices, HHS reports, SEC filings, and security press, re-ingested every 6 hours.',
  'Correlation dedupes and merges reports of the same incident across sources; the corroboration count shows how many independent sources back each entry.',
  'Only authoritative documents create a ledger entry. News and advisories attach as supporting evidence, never as standalone entries. This is a list of breached companies, not a news feed.',
  'A daily news-watch correlates recent security headlines to breaches by company name and keeps them for seven days as "related coverage".',
];

const LIMITS = [
  'Built entirely on free, public sources. Coverage is best-effort and not exhaustive.',
  'Severity is estimated from record volume, data sensitivity, and attribution, not analyst-assigned.',
  'No personal data (emails, passwords, PII) is stored; only breach-level facts and links.',
  'Informational only, not legal advice or a definitive record.',
];

function List({ title, items, check }) {
  return (
    <div className="mb-7">
      <div className="text-xs uppercase tracking-widest mb-3" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>{title}</div>
      <ul className="space-y-2">
        {items.map((t, i) => (
          <li key={i} className="flex items-start gap-2 text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
            {check
              ? <Check size={15} color={COLORS.teal} className="mt-0.5 shrink-0" />
              : <span className="mt-2 shrink-0 rounded-full" style={{ width: 4, height: 4, backgroundColor: COLORS.boneFaint }} />}
            <span>{t}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function AboutView() {
  return (
    <div className="px-6 py-10 max-w-3xl">
      <div className="flex items-center gap-2 mb-3">
        <ShieldAlert size={18} color={COLORS.amber} />
        <h1 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 26, fontWeight: 600 }}>About this platform</h1>
      </div>
      <p className="text-sm leading-relaxed mb-8" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>
        A free breach-intelligence ledger for threat researchers. It tracks which companies have suffered a data
        breach, when it happened, who was behind it, and where it was reported, correlating multiple public sources
        into one record per incident.
      </p>

      <List title="What you can do" items={CAN_DO} check />
      <List title="How it works" items={HOW} />
      <List title="Sources & limitations" items={LIMITS} />
    </div>
  );
}
