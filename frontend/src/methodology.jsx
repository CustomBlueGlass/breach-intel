import React from 'react';
import { Workflow } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';

/* Methodology page. A plain, concrete account of how a breach record is built:
   the sources, how records are matched and deduped, how each field's value is
   chosen, how provenance and conflicts are surfaced, plus what the platform
   deliberately does not do. Written to be checkable, not to impress. */

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

// A numbered pipeline step: the bold action plus a plain explanation.
function Step({ n, title, children }) {
  return (
    <li className="flex items-start gap-3">
      <span
        className="shrink-0 flex items-center justify-center rounded-full text-xs"
        style={{ width: 22, height: 22, marginTop: 1, fontFamily: FONT_MONO, color: COLORS.ink, backgroundColor: COLORS.amber }}
      >
        {n}
      </span>
      <div>
        <div className="text-sm font-semibold" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{title}</div>
        <div className="text-sm leading-relaxed mt-0.5" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>{children}</div>
      </div>
    </li>
  );
}

export function MethodologyView({ onAbout }) {
  return (
    <div className="px-6 py-10 max-w-3xl">
      <div className="flex items-center gap-2 mb-3">
        <Workflow size={18} color={COLORS.amber} />
        <h1 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 26, fontWeight: 600 }}>How the breach database is built</h1>
      </div>

      <p className="text-sm leading-relaxed mb-8" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>
        Every record here is assembled from public sources by an automated pipeline that runs around the clock.
        This page sets out exactly how that works: where the data comes from, how separate reports are matched into
        one incident, how each field's value is chosen, plus how disagreement between sources is shown rather than
        hidden. None of it has to be taken on trust. Every entry links back to the sources it was built from.
      </p>

      <Prose label="Where the data comes from">
        <p>
          The platform reads a fixed set of free, public feeds every four hours. Ransomware leak-site trackers such
          as ransomware.live plus RansomLook. US state attorney-general breach notices. HHS breach reports. SEC
          filings. Have I Been Pwned lookups. The security press through curated news feeds. A separate radar tracks
          fresh signals: newly exploited CVEs from the CISA KEV catalogue plus, where keys are configured, OTX
          pulses and URLhaus malware URLs.
        </p>
        <p>
          Only an authoritative document can create a new entry: a regulator notice, a filing or a leak-site post.
          News stories plus advisories never stand on their own. They attach to an existing breach as related
          coverage, then drop off after a week. That is what keeps the ledger a list of breached companies rather
          than a news feed.
        </p>
      </Prose>

      <div className="mb-8">
        <SectionLabel>How a record is assembled</SectionLabel>
        <ol className="space-y-4">
          <Step n="1" title="Normalise">
            Each incoming report is cleaned into a common shape. Company names are stripped of legal suffixes so
            "Acme Corp" plus "Acme Corporation" collapse together. Industries, locations plus threat-actor names are
            mapped to canonical values through alias tables.
          </Step>
          <Step n="2" title="Deduplicate">
            A content fingerprint drops a report already seen from the same source, so re-reading a feed never
            double-counts the same item.
          </Step>
          <Step n="3" title="Correlate">
            The normalised report is scored against existing breaches inside a 45-day date window using name
            similarity, dates, industry plus location. A strong match merges automatically. A weaker one is held in
            a review queue. An exact name inside the date window is treated as the same incident even when the other
            metadata is thin, which is the common case for regulator notices plus press.
          </Step>
          <Step n="4" title="Create or attach">
            With no good match, an authoritative document mints a new breach and sweeps up any earlier unlinked
            reports that clearly describe it. A non-authoritative document waits, stored but unlinked, until a
            regulator or filing confirms the incident.
          </Step>
        </ol>
      </div>

      <Prose label="How each field's value is chosen">
        <p>
          A single breach is often described by several sources that do not fully agree. The record keeps one
          reconciled value per field, chosen conservatively. The earliest plausible incident date. The earliest
          public disclosure date. The largest verified record count. The union of every data type any source named.
          The first known threat actor. Fields are only ever filled or improved, never quietly overwritten with
          something weaker.
        </p>
        <p>
          Severity is our own estimate, not a figure handed down by anyone official. It rises with scale plus the
          sensitivity of the exposed data: a critical rating needs tens of millions of records, a high rating needs
          around a million or a large exposure of sensitive categories such as health records, government IDs,
          passwords or financial data. Attribution to a ransomware group lifts a smaller incident as well.
        </p>
      </Prose>

      <Prose label="Provenance plus conflicts">
        <p>
          Because each source keeps its own asserted values, the dossier can show which independent sources set a
          given field. Where they line up, a record is corroborated. Where they diverge, the disagreement is
          flagged rather than smoothed over: a field whose sources name different threat actors, report record
          counts that differ by half or more, or place the incident more than a month apart is marked so you can see
          the split plus each source's figure.
        </p>
        <p>
          A corroboration count on every record tells you how many independent sources stand behind it. A single
          source is labelled as awaiting corroboration, not presented as settled fact.
        </p>
      </Prose>

      <Prose label="Records improve over time">
        <p>
          A breach is rarely fully understood on day one. The pipeline revisits existing records as new reports
          attach, recomputing the reconciled fields so a record improves on its own as more is disclosed. Each
          improvement is written to an enhancement history you can read on the dossier, so a jump in the record
          count or a newly named actor is dated plus attributable.
        </p>
        <p>
          The aftermath is tracked too. Regulatory fines, litigation plus settlements that follow a breach are
          detected in later reporting plus attached to the original record as developments, so the entry reflects
          the full arc of an incident rather than freezing at first disclosure.
        </p>
      </Prose>

      <Prose label="What it deliberately does not do">
        <p>
          The platform holds breach-level facts only: the company, the dates, the data categories plus an estimate
          of how many records were involved. It does not collect, store or republish the leaked personal data
          itself. Coverage is drawn from free, public sources, so it is broad but not complete plus it leans toward
          incidents someone chose to disclose. Nothing here is legal advice or a definitive record. Treat it as a
          well-sourced place to start, then verify what matters through the links.
        </p>
      </Prose>

      <div
        className="mt-2 inline-flex items-center gap-2 rounded px-3 py-1.5"
        style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneDim, fontFamily: FONT_MONO, fontSize: 12 }}
      >
        Every field traceable to a public source · breach metadata only, never personal data
      </div>

      {onAbout && (
        <div className="mt-8">
          <button onClick={onAbout} className="text-sm hover:underline" style={{ fontFamily: FONT_MONO, color: COLORS.amber }}>
            Read the plain-English overview →
          </button>
        </div>
      )}
    </div>
  );
}
