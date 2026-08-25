import React, { useState, useEffect } from 'react';
import { Mail, ShieldCheck, LogIn, Check } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO } from './constants';
import { useAuth } from './lib/auth';
import { track, EVENTS } from './lib/analytics';

/* Demand-capture modal for the paid plans. Sign-in is required so the email is
   verified server-side; the form only collects organisation, role/use case and
   an optional message. Submission goes to the server-side /api/enquiry function,
   which validates, rate-limits and persists to the private plan_enquiries table.
   Success is shown only when the server confirms it saved. */

const PLAN_META = {
  pro: { title: 'Join the Pro waitlist', blurb: "We'll email you when Analyst Pro opens. No charge until you choose to subscribe." },
  business: { title: 'Request Business access', blurb: 'Tell us about your team and we will be in touch about Business monitoring.' },
  enterprise: { title: 'Contact sales', blurb: 'SSO, custom feeds, integrations and an SLA. Tell us what you need.' },
};

const inputStyle = {
  fontFamily: FONT_MONO, backgroundColor: COLORS.panelAlt, color: COLORS.bone,
  border: `1px solid ${COLORS.line}`,
};

export function EnquiryModal({ open, plan, source = 'pricing_page', onClose, onSignIn }) {
  const { session, user } = useAuth();
  const [org, setOrg] = useState('');
  const [roleUse, setRoleUse] = useState('');
  const [message, setMessage] = useState('');
  const [st, setSt] = useState({ status: 'idle' });

  useEffect(() => { if (open) setSt({ status: 'idle' }); }, [open, plan]);

  if (!open || !plan) return null;
  const meta = PLAN_META[plan] || PLAN_META.pro;

  async function submit(e) {
    e?.preventDefault?.();
    if (!session?.access_token) { setSt({ status: 'auth' }); return; }
    setSt({ status: 'sending' });
    try {
      const r = await fetch('/api/enquiry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ plan, source, organisation: org, role_use_case: roleUse, message }),
      });
      const data = await r.json().catch(() => ({}));
      if (r.status === 401 || data.authRequired) { setSt({ status: 'auth' }); return; }
      // Only a genuinely unconfigured host is "unavailable"; a transient 503
      // (e.g. the rate limiter failing closed) is a retryable error.
      if (data.configured === false) { setSt({ status: 'unavailable' }); return; }
      if (!r.ok || !data.ok) { setSt({ status: 'error', msg: data.error || 'Something went wrong. Please try again.' }); return; }
      // Only record success after the server confirms persistence.
      setSt({ status: 'done' });
      track(plan === 'pro' ? EVENTS.WAITLIST_SUBMITTED : EVENTS.BUSINESS_ENQUIRY_SUBMITTED, { plan, source });
    } catch {
      setSt({ status: 'error', msg: 'Network error. Please try again.' });
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-md rounded-lg p-6" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-1">
          <ShieldCheck size={18} color={COLORS.amber} />
          <h2 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 20, fontWeight: 600 }}>{meta.title}</h2>
        </div>
        <p className="mt-1 mb-4 text-xs leading-relaxed" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{meta.blurb}</p>

        {st.status === 'done' ? (
          <div className="text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
            <div className="flex items-center gap-2 mb-2" style={{ color: COLORS.teal }}><Check size={16} /> Request received</div>
            Thanks. We have your request against <span style={{ color: COLORS.bone }}>{user?.email}</span> and will be in touch.
          </div>
        ) : !session ? (
          <div>
            <div className="text-sm leading-relaxed mb-3" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
              Sign in first so we can verify your email. We never ask for a password.
            </div>
            <button onClick={onSignIn} className="w-full inline-flex items-center justify-center gap-1.5 rounded-md py-2 text-sm font-semibold"
              style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.amber, color: COLORS.ink }}>
              <LogIn size={14} /> Sign in to continue
            </button>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-3">
            <div className="flex items-center gap-2 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>
              <Mail size={13} /> {user?.email}
            </div>
            <input value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Organisation (optional)" maxLength={200}
              className="w-full rounded-md px-3 py-2 text-sm outline-none" style={inputStyle} />
            <input value={roleUse} onChange={(e) => setRoleUse(e.target.value)} placeholder="Your role or how you would use it (optional)" maxLength={200}
              className="w-full rounded-md px-3 py-2 text-sm outline-none" style={inputStyle} />
            <textarea value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Anything else? (optional)" maxLength={2000} rows={3}
              className="w-full rounded-md px-3 py-2 text-sm outline-none resize-y" style={inputStyle} />
            <button type="submit" disabled={st.status === 'sending'} className="w-full rounded-md py-2 text-sm font-semibold"
              style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.amber, color: COLORS.ink, opacity: st.status === 'sending' ? 0.6 : 1 }}>
              {st.status === 'sending' ? 'Sending...' : 'Submit request'}
            </button>
            {st.status === 'error' && <div className="text-xs" style={{ color: COLORS.red, fontFamily: FONT_MONO }}>{st.msg}</div>}
            {st.status === 'auth' && <div className="text-xs" style={{ color: COLORS.amber, fontFamily: FONT_MONO }}>Your session expired. Please sign in again.</div>}
            {st.status === 'unavailable' && <div className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>Enquiries are not enabled on this host yet.</div>}
            <p className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>We store only what you enter here plus your verified email. No card details.</p>
          </form>
        )}

        <button onClick={onClose} className="mt-4 w-full text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}>Close</button>
      </div>
    </div>
  );
}
