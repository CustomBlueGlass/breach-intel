import React from 'react';
import { Check, Tag } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';

/* Public pricing page. Presentation only for now: the checkout provider is
   not wired yet, so paid tiers show a "coming soon" state rather than a live
   payment flow. Tiers and feature split are informed by the market (HIBP at
   the cheap end, Flare / Hudson Rock around $200/mo, SOCRadar / Intel X in the
   thousands). Prices are indicative and in GBP. */

const PLANS = [
  {
    name: 'Free',
    price: '£0',
    cadence: 'forever',
    tagline: 'Browse the public ledger and the analyst tools.',
    cta: 'browse',
    features: [
      'Browse the breach ledger (recent window)',
      'Threat radar plus the analyst tools',
      'Keyless indicator enrichment (IP, domain, hash, CVE)',
      'Export a filtered view as CSV or JSON',
    ],
  },
  {
    name: 'Pro',
    price: '£19',
    cadence: 'per month',
    tagline: 'For the individual analyst who needs the full picture.',
    cta: 'soon',
    highlight: true,
    features: [
      'Everything in Free',
      'Full breach history plus every field',
      'Saved searches, watchlists plus boards',
      'Bulk export (CSV, JSON, STIX 2.1)',
      'Personal API key with a monthly quota',
      'Credential-exposure lookups (metadata only)',
    ],
  },
  {
    name: 'Business',
    price: '£149',
    cadence: 'per month',
    tagline: 'For a team that needs to watch its own exposure.',
    cta: 'soon',
    features: [
      'Everything in Pro',
      'Company and domain monitoring with alerts',
      'Alerts by email, webhook or Slack',
      'Higher API limits',
      'Up to 5 seats',
      'Threat-actor tracking plus STIX feeds',
    ],
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    cadence: 'talk to us',
    tagline: 'For security teams with scale, SSO plus compliance needs.',
    cta: 'soon',
    features: [
      'Everything in Business',
      'SSO plus role-based access',
      'Custom feeds plus integrations',
      'CrowdStrike, Entra ID, Okta, Intune, Jamf, Workspace',
      'Priority support plus an SLA',
    ],
  },
];

function Cta({ kind, onStart, highlight }) {
  if (kind === 'browse') {
    return (
      <button
        onClick={onStart}
        className="w-full rounded-md py-2 text-sm font-semibold"
        style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.bone, color: COLORS.ink }}
      >
        Browse the ledger
      </button>
    );
  }
  return (
    <button
      disabled
      className="w-full rounded-md py-2 text-sm font-semibold cursor-default"
      style={{
        fontFamily: FONT_BODY,
        border: `1px solid ${highlight ? COLORS.amber : COLORS.line}`,
        color: highlight ? COLORS.amber : COLORS.boneDim,
        backgroundColor: 'transparent',
      }}
    >
      Coming soon
    </button>
  );
}

function PlanCard({ plan, onStart }) {
  return (
    <div
      className="flex flex-col rounded-lg p-5"
      style={{
        backgroundColor: COLORS.panel,
        border: `1px solid ${plan.highlight ? COLORS.amber : COLORS.line}`,
      }}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{plan.name}</span>
        {plan.highlight && (
          <span
            className="text-xs px-2 py-0.5 rounded-full"
            style={{ fontFamily: FONT_MONO, color: COLORS.ink, backgroundColor: COLORS.amber }}
          >
            Most popular
          </span>
        )}
      </div>

      <div className="mt-3 flex items-baseline gap-1.5">
        <span style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 30, fontWeight: 600 }}>{plan.price}</span>
        <span className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{plan.cadence}</span>
      </div>

      <p className="mt-2 text-xs leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY, minHeight: 32 }}>
        {plan.tagline}
      </p>

      <div className="mt-4 mb-4">
        <Cta kind={plan.cta} onStart={onStart} highlight={plan.highlight} />
      </div>

      <ul className="space-y-2">
        {plan.features.map((f) => (
          <li key={f} className="flex items-start gap-2 text-xs leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
            <Check size={14} color={plan.highlight ? COLORS.amber : COLORS.teal} className="mt-0.5 shrink-0" />
            <span>{f}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function PricingView({ onStart }) {
  return (
    <div className="px-6 py-10 max-w-5xl mx-auto">
      <div className="flex items-center gap-2 mb-3">
        <Tag size={18} color={COLORS.amber} />
        <h1 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 26, fontWeight: 600 }}>Plans and pricing</h1>
      </div>

      <p className="text-sm leading-relaxed mb-3 max-w-2xl" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>
        The ledger stays free to browse. Paid plans unlock the full history, monitoring with alerts, exports plus an API,
        priced to sit between a basic breach lookup and the enterprise platforms that start in the thousands per month.
      </p>

      <div
        className="inline-flex items-center gap-2 rounded px-3 py-1.5 mb-8"
        style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneDim, fontFamily: FONT_MONO, fontSize: 12 }}
      >
        Paid plans launch soon. Prices are indicative and shown in GBP.
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {PLANS.map((p) => (
          <PlanCard key={p.name} plan={p} onStart={onStart} />
        ))}
      </div>

      <p className="mt-8 text-xs leading-relaxed max-w-2xl" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
        Every plan holds breach metadata only, never the leaked personal data itself. Made in the UK, aligned with
        UK GDPR and the ICO. Card payments will be handled by a dedicated payment provider, so card details never touch
        our servers.
      </p>
    </div>
  );
}
