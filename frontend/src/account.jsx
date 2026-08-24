import React, { useState, useEffect } from 'react';
import { LogIn, LogOut, Mail, ShieldCheck, KeyRound, BellRing, Lock } from 'lucide-react';
import { COLORS, FONT_DISPLAY, FONT_BODY, FONT_MONO, fmtDate } from './constants';
import { useAuth } from './lib/auth';
import { track, EVENTS } from './lib/analytics';

/* Sign-in modal, the top-bar auth control plus the signed-in dashboard.
   Passwordless magic-link is the primary flow. Billing is not wired yet, so
   the dashboard shows the Free plan and points paid features at /pricing. */

const inputStyle = {
  fontFamily: FONT_MONO,
  backgroundColor: COLORS.panelAlt,
  color: COLORS.bone,
  border: `1px solid ${COLORS.line}`,
};

export function AuthModal({ open, onClose }) {
  const { signInWithEmail, signInWithOAuth } = useAuth();
  const [email, setEmail] = useState('');
  const [state, setState] = useState({ status: 'idle' });

  if (!open) return null;

  async function sendLink(e) {
    e.preventDefault();
    const addr = email.trim();
    if (!addr) return;
    setState({ status: 'sending' });
    const { error } = await signInWithEmail(addr);
    setState(error ? { status: 'error', msg: error.message } : { status: 'sent' });
  }

  async function oauth(provider) {
    setState({ status: 'sending' });
    const { error } = await signInWithOAuth(provider);
    if (error) setState({ status: 'error', msg: `${provider} sign-in is not enabled yet.` });
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-sm rounded-lg p-6"
        style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 mb-1">
          <ShieldCheck size={18} color={COLORS.amber} />
          <h2 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 20, fontWeight: 600 }}>Sign in</h2>
        </div>

        {state.status === 'sent' ? (
          <div className="mt-3 text-sm leading-relaxed" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
            <div className="flex items-center gap-2 mb-2" style={{ color: COLORS.teal }}>
              <Mail size={16} /> Check your inbox
            </div>
            We sent a secure sign-in link to <span style={{ color: COLORS.bone }}>{email}</span>. Open it on this device to
            finish signing in.
          </div>
        ) : (
          <>
            <p className="mt-1 mb-4 text-xs leading-relaxed" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>
              We email you a secure link. No password needed.
            </p>
            <form onSubmit={sendLink}>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                autoFocus
                spellCheck={false}
                autoCapitalize="none"
                className="w-full rounded-md px-3 py-2 text-sm outline-none"
                style={inputStyle}
              />
              <button
                type="submit"
                disabled={state.status === 'sending'}
                className="mt-3 w-full rounded-md py-2 text-sm font-semibold"
                style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.amber, color: COLORS.ink, opacity: state.status === 'sending' ? 0.6 : 1 }}
              >
                {state.status === 'sending' ? 'Working...' : 'Send magic link'}
              </button>
            </form>

            <div className="my-4 flex items-center gap-3" style={{ color: COLORS.boneFaint }}>
              <span className="flex-1" style={{ height: 1, backgroundColor: COLORS.line }} />
              <span className="text-xs" style={{ fontFamily: FONT_MONO }}>or</span>
              <span className="flex-1" style={{ height: 1, backgroundColor: COLORS.line }} />
            </div>

            <div className="space-y-2">
              {['google', 'github', 'azure'].map((p) => (
                <button
                  key={p}
                  onClick={() => oauth(p)}
                  className="w-full rounded-md py-2 text-sm"
                  style={{ fontFamily: FONT_BODY, color: COLORS.bone, border: `1px solid ${COLORS.line}`, backgroundColor: 'transparent' }}
                >
                  Continue with {p === 'azure' ? 'Microsoft' : p.charAt(0).toUpperCase() + p.slice(1)}
                </button>
              ))}
            </div>

            {state.status === 'error' && (
              <div className="mt-3 text-xs" style={{ color: COLORS.red, fontFamily: FONT_MONO }}>{state.msg}</div>
            )}
          </>
        )}

        <button
          onClick={onClose}
          className="mt-4 w-full text-xs"
          style={{ color: COLORS.boneFaint, fontFamily: FONT_MONO }}
        >
          Close
        </button>
      </div>
    </div>
  );
}

export function AuthButton({ onOpenAuth, onDashboard }) {
  const { session, user, signOut } = useAuth();
  if (!session) {
    return (
      <button
        onClick={onOpenAuth}
        className="shrink-0 inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium"
        style={{ fontFamily: FONT_BODY, color: COLORS.ink, backgroundColor: COLORS.amber }}
      >
        <LogIn size={14} /> Sign in
      </button>
    );
  }
  const label = (user?.email || 'account').split('@')[0];
  return (
    <div className="shrink-0 flex items-center gap-1">
      <button
        onClick={onDashboard}
        title={user?.email}
        className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium max-w-[9rem]"
        style={{ fontFamily: FONT_BODY, color: COLORS.bone, border: `1px solid ${COLORS.line}` }}
      >
        <span
          className="flex items-center justify-center rounded-full text-xs shrink-0"
          style={{ width: 20, height: 20, backgroundColor: COLORS.amber, color: COLORS.ink, fontFamily: FONT_MONO }}
        >
          {label.charAt(0).toUpperCase()}
        </span>
        <span className="truncate">{label}</span>
      </button>
      <button
        onClick={signOut}
        title="Sign out"
        className="rounded-md p-1.5"
        style={{ color: COLORS.boneFaint, border: `1px solid ${COLORS.line}` }}
      >
        <LogOut size={14} />
      </button>
    </div>
  );
}

function LockedFeature({ Icon, title, unlock, ctaLabel, onCta }) {
  return (
    <div className="rounded-lg p-4" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}>
      <div className="flex items-center gap-2 mb-1">
        <Icon size={15} color={COLORS.boneFaint} />
        <span className="text-sm font-semibold" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{title}</span>
        <Lock size={12} color={COLORS.boneFaint} className="ml-auto" />
      </div>
      <div className="text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{unlock}</div>
      {ctaLabel && onCta && (
        <button onClick={onCta} className="mt-3 rounded-md px-2.5 py-1 text-xs font-semibold"
          style={{ fontFamily: FONT_BODY, color: COLORS.amber, border: `1px solid ${COLORS.amber}`, backgroundColor: 'transparent' }}>
          {ctaLabel}
        </button>
      )}
    </div>
  );
}

export function DashboardView({ onBrowsePlans, onEnquire }) {
  const { user, signOut } = useAuth();
  useEffect(() => { track(EVENTS.UPGRADE_PROMPT_SHOWN, { source: 'dashboard' }); }, []);
  if (!user) return null;
  const enquire = (plan) => { track(EVENTS.UPGRADE_PROMPT_SELECTED, { plan, source: 'dashboard' }); onEnquire?.(plan); };
  return (
    <div className="px-6 py-10 max-w-3xl">
      <h1 className="mb-6" style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 26, fontWeight: 600 }}>Dashboard</h1>

      <div className="rounded-lg p-5 mb-4" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}>
        <div className="text-xs uppercase tracking-widest mb-3" style={{ fontFamily: FONT_MONO, color: COLORS.boneFaint, letterSpacing: '0.12em' }}>Account</div>
        <div className="flex items-center justify-between py-1 text-sm" style={{ fontFamily: FONT_BODY }}>
          <span style={{ color: COLORS.boneFaint }}>Email</span>
          <span style={{ color: COLORS.bone }}>{user.email}</span>
        </div>
        <div className="flex items-center justify-between py-1 text-sm" style={{ borderTop: `1px solid ${COLORS.lineFaint}`, fontFamily: FONT_BODY }}>
          <span style={{ color: COLORS.boneFaint }}>Member since</span>
          <span style={{ color: COLORS.bone }}>{fmtDate(user.created_at)}</span>
        </div>
        <div className="flex items-center justify-between py-1 text-sm" style={{ borderTop: `1px solid ${COLORS.lineFaint}`, fontFamily: FONT_BODY }}>
          <span style={{ color: COLORS.boneFaint }}>Plan</span>
          <span className="text-xs px-2 py-0.5 rounded-full" style={{ fontFamily: FONT_MONO, color: COLORS.ink, backgroundColor: COLORS.bone }}>Free</span>
        </div>
        <button
          onClick={onBrowsePlans}
          className="mt-4 rounded-md px-3 py-1.5 text-sm font-semibold"
          style={{ fontFamily: FONT_BODY, backgroundColor: COLORS.amber, color: COLORS.ink }}
        >
          See plans
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <LockedFeature Icon={KeyRound} title="API key" unlock="Unlocks on Pro. Query the ledger plus enrichment from your own tooling."
          ctaLabel="Join Pro waitlist" onCta={() => enquire('pro')} />
        <LockedFeature Icon={BellRing} title="Monitoring and alerts" unlock="Unlocks on Business. Watch your domains for new breaches plus credential exposure."
          ctaLabel="Request Business access" onCta={() => enquire('business')} />
      </div>

      <button
        onClick={signOut}
        className="mt-6 inline-flex items-center gap-1.5 text-sm"
        style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}
      >
        <LogOut size={14} /> Sign out
      </button>
    </div>
  );
}
