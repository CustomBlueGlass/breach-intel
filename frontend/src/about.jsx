import React from 'react';
import { ShieldAlert } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';

/* About page. Plain prose, written to be read, not skimmed off a slide. */

function Section({ label, children }) {
  return (
    <div className="mb-8">
      <div
        className="text-xs uppercase tracking-widest mb-3"
        style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}
      >
        {label}
      </div>
      <div className="space-y-3 text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
        {children}
      </div>
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
        This is a public record of company data breaches. One row for each real incident: who was hit, roughly
        when, who was behind it where that is known, what kind of data went out, and where it was reported. It is
        free to use, and every entry links back to the source it came from so you can check it for yourself.
      </p>

      <Section label="Why it exists">
        <p>
          Breach news arrives in pieces. A ransomware crew posts a victim on their leak site. A US state attorney
          general files a notice about it months later. A regulator logs it somewhere else again, and the trade
          press writes it up in between. Stitching all of that together by hand is slow and easy to get wrong.
        </p>
        <p>
          So the platform does the stitching. It reads those sources every few hours, works out when several of
          them are describing the same event, and keeps one clean record with all of them attached.
        </p>
      </Section>

      <Section label="What you can do">
        <p>
          Start on the ledger and filter it however you think: by industry, threat actor, date, or attribution.
          Open any company to get the whole picture, including the incident and disclosure dates, the group
          responsible, an estimate of how many records were affected, the categories of data exposed, a timeline,
          leak-site evidence, and the full list of sources. Threat actors get their own profiles too, with the
          victims attributed to them and a STIX 2.1 export if you want to take the data elsewhere. A live radar
          along the top shows the newest ransomware victims and freshly exploited CVEs.
        </p>
        <p>
          There is a set of analyst tools built in, so you are not opening five other tabs for the small jobs.
          Most of them run entirely in your browser and send nothing anywhere: an IOC extractor and defanger, a
          URL dissector, hashing and hash identification, CIDR maths, a CVSS calculator, JWT and base64 decoders,
          and more. One tool, the live enrichment lookup, does call our own server. Give it an IP, a domain, a
          file hash, or a CVE and it comes back with open ports and known vulnerabilities from Shodan's free
          InternetDB, DNS records, a CIRCL hashlookup verdict, or an EPSS exploitation score. No API key needed.
        </p>
        <p>
          Where a key is configured, you can also check a company's domain against credential-exposure sources.
          Even then we only show which breaches it turned up in and how many records matched, never the
          credentials themselves. Any view you build exports as CSV, JSON, or STIX 2.1.
        </p>
      </Section>

      <Section label="Where the data comes from">
        <p>
          The sources are ransomware leak-site trackers such as ransomware.live and RansomLook, US state attorney
          general breach notices, HHS reports, SEC filings, and the security press. They are re-read every four
          hours. When more than one source describes the same breach, the reports are merged into a single record,
          and a corroboration count tells you how many independent sources stand behind it.
        </p>
        <p>
          Only an authoritative document creates an entry: a regulator notice, a filing, or a leak-site post. News
          stories and advisories never stand on their own here. They attach to an existing breach as related
          coverage and drop off after a week. This is a list of companies that were breached, not a news feed.
        </p>
      </Section>

      <Section label="What it is not">
        <p>
          A few things worth being straight about. Everything here comes from free, public sources, so the
          coverage is decent but not complete, and it leans toward incidents that someone chose to disclose.
          Severity is our own estimate from record volume, how sensitive the data was, and who was involved, not a
          figure handed down by anyone official. And none of this is legal advice or a definitive record. Treat it
          as a well-sourced place to start, then verify what matters through the links.
        </p>
      </Section>

      <Section label="Made in the UK">
        <p>
          Built in the UK, and built to stay on the right side of UK GDPR and the ICO. We hold breach-level facts
          only: the company, the dates, the categories of data, and an estimate of how many records were involved.
          We do not collect, store, or republish the leaked personal data itself. Because every entry points back
          to the public source it came from, none of it has to be taken on trust.
        </p>
      </Section>

      <div
        className="mt-2 inline-flex items-center gap-2 rounded px-3 py-1.5"
        style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneDim, fontFamily: FONT_MONO, fontSize: 12 }}
      >
        Made in the UK · UK GDPR / ICO aligned · breach metadata only, never personal data
      </div>
    </div>
  );
}
