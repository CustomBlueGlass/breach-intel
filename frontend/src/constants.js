import React, { useEffect } from 'react';
import {
  Search, Database, Landmark, ShieldAlert, FileText, Newspaper,
  Building2, AlertTriangle, Globe,
} from 'lucide-react';

/* ----------------------------------------------------------------------
   Design tokens — "intelligence ledger": ink + bone, with a strict rule
   that color (amber/red/teal) is reserved for severity/status signaling
   only, never decoration. See accompanying design notes.
---------------------------------------------------------------------- */
export const COLORS = {
  ink: '#0E1116',
  panel: '#151B22',
  panelAlt: '#1B222B',
  line: '#2A323C',
  lineFaint: '#1F2630',
  bone: '#ECE7DE',
  boneDim: '#9CA3AF',
  boneFaint: '#6B7280',
  amber: '#D98E33',
  amberSoft: '#C99A52',
  red: '#C0473A',
  teal: '#4F9D8C',
};

export const FONT_DISPLAY = "'Source Serif 4', 'Iowan Old Style', Georgia, serif";
export const FONT_BODY = "'Inter', -apple-system, 'Segoe UI', sans-serif";
export const FONT_MONO = "'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace";

export function useGoogleFonts() {
  useEffect(() => {
    const id = 'breach-ledger-fonts';
    if (document.getElementById(id)) return;
    const link = document.createElement('link');
    link.id = id;
    link.rel = 'stylesheet';
    link.href = 'https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400;8..60,600;8..60,700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap';
    document.head.appendChild(link);
  }, []);
}

export const INDUSTRY_LABELS = {
  healthcare: 'Healthcare', financial_services: 'Financial Services', education: 'Education',
  government: 'Government', retail: 'Retail', technology: 'Technology',
  manufacturing: 'Manufacturing', energy_utilities: 'Energy & Utilities',
  legal_services: 'Legal Services', hospitality: 'Hospitality',
  transportation: 'Transportation', nonprofit: 'Nonprofit',
};

export const SOURCE_CATEGORY_META = {
  ransomware_leak_tracker: { label: 'Leak-site tracker', Icon: Database },
  state_ag_notification: { label: 'State AG notice', Icon: Landmark },
  federal_regulatory: { label: 'Federal regulator', Icon: ShieldAlert },
  sec_filing: { label: 'SEC filing', Icon: FileText },
  security_news: { label: 'Security press', Icon: Newspaper },
  breach_lookup_service: { label: 'Lookup service', Icon: Search },
  nonprofit_tracker: { label: 'Nonprofit tracker', Icon: Building2 },
  government_advisory: { label: 'Gov. advisory', Icon: AlertTriangle },
  eu_uk_regulatory: { label: 'EU/UK regulator', Icon: Globe },
};

export const SEVERITY_META = {
  low: { label: 'Low', text: COLORS.teal, bg: 'rgba(79,157,140,0.14)' },
  moderate: { label: 'Moderate', text: COLORS.amberSoft, bg: 'rgba(201,154,82,0.14)' },
  high: { label: 'High', text: COLORS.amber, bg: 'rgba(217,142,51,0.16)' },
  critical: { label: 'Critical', text: COLORS.red, bg: 'rgba(192,71,58,0.18)' },
};

export function fmtNumber(n) {
  if (n == null) return '—';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
  return String(n);
}

export function fmtDate(d) {
  if (!d) return '—';
  const dt = new Date(d + 'T00:00:00');
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function daysAgo(d) {
  if (!d) return null;
  const diff = Math.round((new Date() - new Date(d + 'T00:00:00')) / 86400000);
  return diff;
}

export function relativeTime(d) {
  const days = daysAgo(d);
  if (days == null) return '—';
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.round(days / 7)}w ago`;
  return `${Math.round(days / 30)}mo ago`;
}
