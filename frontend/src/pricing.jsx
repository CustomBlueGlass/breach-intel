import React, { useEffect, useState } from 'react';
import { Check, Minus, Tag } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';
import { track, EVENTS } from './lib/analytics';

/* Public pricing page. Checkout is not wired yet (Phase 2), so paid tiers open a
   demand-capture flow (waitlist / access request / contact sales) rather than a
   dead "coming soon" button. Prices are introductory and in GBP. */

const PLANS = [
  {
    name: 'Free', price: '£0', cadence: 'forever', cta: 'browse',
    tagline: 'Browse the public ledger and the analyst tools.',
    features: [
      'Browse the breach ledger (recent window)',
      'Threat radar plus the analyst tools',
      'Keyless indicator enrichment (IP, domain, hash, CVE)',
      'Export a filtered view as CSV or JSON',
    ],
  },
  {
    name: 'Analyst Pro', price: '£19', cadence: 'per month', cta: 'waitlist', enquiryPlan: 'pro', highlight: true,
    tagline: 'For the individual analyst who needs the full picture.',
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
    name: 'Business', price: '£149', cadence: 'per month', cta: 'request', enquiryPlan: 'business',
    tagline: 'For a team that needs to watch its own exposure.',
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
    name: 'Enterprise', price: 'Custom', cadence: 'talk to us', cta: 'contact', enquiryPlan: 'enterprise',
    tagline: 'For security teams with scale, SSO plus compliance needs.',
    features: [
      'Everything in Business',
      'SSO plus role-based access',
      'Custom feeds plus integrations',
      'CrowdStrike, Entra ID, Okta, Intune, Jamf, Workspace',
      'Priority support plus an SLA',
    ],
  },
];

const CTA_LABEL = { browse: 'Browse the ledger', waitlist: 'Join Pro waitlist', request: 'Request Business access', contact: 'Contact sales' };

// Compact entitlement comparison. true = included, false = not included.
const MATRIX = [
  ['Recent ledger + analyst tools', true, true, true, true],
  ['Full breach history + every field', false, true, true, true],
  ['Cloud watchlists + saved searches', false, true, true, true],
  ['Bulk export (CSV / JSON / STIX)', false, true, true, true],
  ['Metered API access', false, true, true, true],
  ['Domain / company monitoring + alerts', false, false, true, true],
  ['Up to 5 seats', false, false, true, true],
  ['SSO + custom integrations + SLA', false, false, false, true],
];

function Cta({ plan, onStart, onEnquire }) {
  if (plan.cta === 'browse') {
    return (
      <button onClick={onStart} className="w-full rounded-md py-2 text-sm font-semibold"
        style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.bone, color: COLORS.ink }}>
        {CTA_LABEL.browse}
      </button>
    );
  }
  return (
    <button
      onClick={() => { track(EVENTS.PLAN_SELECTED, { plan: plan.enquiryPlan, source: 'pricing_page' }); onEnquire?.(plan.enquiryPlan, 'pricing_page'); }}
      className="w-full rounded-md py-2 text-sm font-semibold"
      style={{ fontFamily: FONT_BODY, backgroundColor: plan.highlight ? COLORS.amber : 'transparent',
               color: plan.highlight ? COLORS.ink : COLORS.bone, border: plan.highlight ? 'none' : `1px solid ${COLORS.line}` }}>
      {CTA_LABEL[plan.cta]}
    </button>
  );
}

function PlanCard({ plan, onStart, onEnquire }) {
  return (
    <div className="flex flex-col rounded-lg p-5" style={{ backgroundColor: COLORS.panel, border: `1px solid ${plan.highlight ? COLORS.amber : COLORS.line}` }}>
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{plan.name}</span>
        {plan.highlight && <span className="text-xs px-2 py-0.5 rounded-full" style={{ fontFamily: FONT_MONO, color: COLORS.ink, backgroundColor: COLORS.amber }}>Most popular</span>}
      </div>
      <div className="mt-3 flex items-baseline gap-1.5">
        <span style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 30, fontWeight: 600 }}>{plan.price}</span>
        <span className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>{plan.cadence}</span>
      </div>
      <p className="mt-2 text-xs leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY, minHeight: 32 }}>{plan.tagline}</p>
      <div className="mt-4 mb-4"><Cta plan={plan} onStart={onStart} onEnquire={onEnquire} /></div>
      <ul className="space-y-2">
        {plan.features.map((f) => (
          <li key={f} className="flex items-start gap-2 text-xs leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
            <Check size={14} color={plan.highlight ? COLORS.amber : COLORS.teal} className="mt-0.5 shrink-0" /><span>{f}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function PricingView({ onStart, onEnquire }) {
  const [annual, setAnnual] = useState(false);
  useEffect(() => { track(EVENTS.PRICING_VIEWED, {}); }, []);

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

      <div className="flex flex-wrap items-center gap-3 mb-8">
        <div className="inline-flex items-center gap-2 rounded px-3 py-1.5" style={{ border: `1px solid ${COLORS.line}`, color: COLORS.boneDim, fontFamily: FONT_MONO, fontSize: 12 }}>
          Introductory prices, shown in GBP.
        </div>
        {/* Annual billing placeholder, explicitly unavailable. */}
        <div className="inline-flex items-center rounded overflow-hidden" style={{ border: `1px solid ${COLORS.line}`, fontFamily: FONT_MONO, fontSize: 12 }}>
          <button onClick={() => setAnnual(false)} className="px-3 py-1.5" style={{ color: !annual ? COLORS.ink : COLORS.boneDim, backgroundColor: !annual ? COLORS.bone : 'transparent' }}>Monthly</button>
          <button disabled title="Annual billing is not available yet" className="px-3 py-1.5 cursor-default" style={{ color: COLORS.boneFaint, backgroundColor: 'transparent' }}>Annual (soon)</button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {PLANS.map((p) => <PlanCard key={p.name} plan={p} onStart={onStart} onEnquire={onEnquire} />)}
      </div>

      {/* Entitlement comparison */}
      <div className="mt-10 overflow-x-auto">
        <table className="w-full text-xs" style={{ borderCollapse: 'collapse', fontFamily: FONT_BODY, color: COLORS.boneDim }}>
          <thead>
            <tr>
              <th className="text-left font-semibold py-2 pr-3" style={{ color: COLORS.bone }}>What's included</th>
              {['Free', 'Pro', 'Business', 'Enterprise'].map((h) => (
                <th key={h} className="py-2 px-3 font-semibold text-center" style={{ color: COLORS.bone, fontFamily: FONT_MONO }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MATRIX.map((row) => (
              <tr key={row[0]} style={{ borderTop: `1px solid ${COLORS.lineFaint}` }}>
                <td className="py-2 pr-3">{row[0]}</td>
                {row.slice(1).map((v, i) => (
                  <td key={i} className="py-2 px-3 text-center">
                    {v ? <Check size={14} color={COLORS.teal} className="inline" /> : <Minus size={14} color={COLORS.boneFaint} className="inline" />}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-8 text-xs leading-relaxed max-w-2xl" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
        Every plan holds breach metadata only, never the leaked personal data itself. Made in the UK, aligned with
        UK GDPR and the ICO. When billing launches, card payments will be handled by a dedicated payment provider, so
        card details never touch our servers.
      </p>
    </div>
  );
}
