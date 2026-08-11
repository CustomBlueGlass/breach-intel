import React from 'react';
import { ShieldAlert } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';

/* About page. Plain prose for context, a scannable capability list for what
   the platform does. Written to be read, not skimmed off a slide. */

const CAPABILITIES = [
  {
    title: 'Browse the breach ledger',
    summary: 'Filter and sort every recorded incident by industry, threat actor, date or attribution.',
  },
  {
    title: 'Open a company dossier',
    summary:
      'One record pulls together the incident and disclosure dates, the group responsible, the records affected, the data types exposed, a timeline, leak-site evidence and each source behind the entry.',
  },
  {
    title: 'Track threat actors',
    summary:
      'Dedicated profiles with the victims attributed to each group, an activity timeline, known aliases and a STIX 2.1 export.',
  },
  {
    title: 'Watch the live radar',
    summary: 'The latest ransomware victims and newly exploited CVEs, refreshed as the sources update.',
  },
  {
    title: 'Enrich an indicator in real time',
    summary:
      'Look up an IP, domain, file hash or CVE through the built-in keyless API, backed by Shodan InternetDB, DNS, CIRCL hashlookup and FIRST EPSS.',
  },
  {
    title: 'Check credential exposure',
    summary:
      'Where a key is configured, test a company domain against exposure sources. Results stay metadata only: which breaches matched and how many records, never the credentials themselves.',
  },
  {
    title: 'Run the analyst toolkit',
    summary:
      'Browser-only utilities for the small pivots: an IOC extractor, a URL dissector, hashing, CIDR maths, CVSS scoring, JWT and base64 decoders.',
  },
  {
    title: 'Export any view',
    summary: 'Take the full ledger, a filtered slice or an actor profile out as CSV, JSON or STIX 2.1.',
  },
];

function SectionLabel({ children }) {
  return (
    <div
      className="text-xs uppercase tracking-widest mb-3"
      style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}
    >
      {children}
    </div>
  );
}

function Prose({ label, children }) {
  return (
    <div className="mb-8">
      <SectionLabel>{label}</SectionLabel>
      <div className="space-y-3 text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
        {children}
      </div>
    </div>
  );
}

function Capability({ title, summary }) {
  return (
    <li className="flex items-start gap-3">
      <span className="mt-2 shrink-0 rounded-sm" style={{ width: 6, height: 6, backgroundColor: COLORS.amber }} />
      <div>
        <div className="text-sm font-semibold" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{title}</div>
        <div className="text-sm leading-relaxed mt-0.5" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>{summary}</div>
      </div>
    </li>
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
        This is a public record of company data breaches. One row for each real incident: who was hit, roughly
        when, who was behind it where that is known, what kind of data went out plus where it was reported. It is
        free to use. Every entry links back to the source it came from so you can check it for yourself.
      </p>

      <Prose label="Why it exists">
        <p>
          Breach news arrives in pieces. A ransomware crew posts a victim on their leak site. A US state attorney
          general files a notice about it months later. A regulator logs it somewhere else again. The trade press
          writes it up in between. Stitching all of that together by hand is slow work that is easy to get wrong.
        </p>
        <p>
          So the platform does the stitching. It reads those sources every few hours, works out when several of
          them describe the same event and keeps one clean record with all of them attached.
        </p>
      </Prose>

      <div className="mb-8">
        <SectionLabel>What you can do</SectionLabel>
        <ul className="space-y-4">
          {CAPABILITIES.map((c) => (
            <Capability key={c.title} title={c.title} summary={c.summary} />
          ))}
        </ul>
      </div>

      <Prose label="Where the data comes from">
        <p>
          The sources are ransomware leak-site trackers such as ransomware.live and RansomLook, US state attorney
          general breach notices, HHS reports, SEC filings plus the security press. They are re-read every four
          hours. When more than one source describes the same breach, the reports merge into a single record. A
          corroboration count tells you how many independent sources stand behind it.
        </p>
        <p>
          Only an authoritative document creates an entry: a regulator notice, a filing or a leak-site post. News
          stories and advisories never stand on their own here. They attach to an existing breach as related
          coverage, then drop off after a week. This is a list of companies that were breached, not a news feed.
        </p>
      </Prose>

      <Prose label="What it is not">
        <p>
          A few things worth being straight about. Everything here comes from free, public sources, so coverage is
          decent but not complete. It leans toward incidents that someone chose to disclose. Severity is our own
          estimate from record volume, data sensitivity plus who was involved, not a figure handed down by anyone
          official. None of this is legal advice or a definitive record. Treat it as a well-sourced place to start,
          then verify what matters through the links.
        </p>
      </Prose>

      <Prose label="Made in the UK">
        <p>
          Built in the UK to stay on the right side of UK GDPR and the ICO. We hold breach-level facts only: the
          company, the dates, the data categories plus an estimate of how many records were involved. We do not
          collect, store or republish the leaked personal data itself. Because every entry points back to the
          public source it came from, none of it has to be taken on trust.
        </p>
      </Prose>

      <div
        className="mt-2 inline-flex items-center gap-2 rounded px-3 py-1.5"
        style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneDim, fontFamily: FONT_MONO, fontSize: 12 }}
      >
        Made in the UK · UK GDPR / ICO aligned · breach metadata only, never personal data
      </div>
    </div>
  );
}
