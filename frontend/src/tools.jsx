import React, { useState, useMemo } from 'react';
import { Wrench, Copy, Check, ExternalLink } from 'lucide-react';
import { COLORS, FONT_BODY, FONT_MONO, FONT_DISPLAY } from './constants';

/* ============================================================================
   Analyst Tools — free, client-side CTI/OSINT utilities. No backend, no data
   leaves the browser. The point is to keep an analyst inside the platform for
   the small pivots they otherwise open five other tabs for.
   ========================================================================== */

const mono = { fontFamily: FONT_MONO };
const inputStyle = {
  fontFamily: FONT_MONO, backgroundColor: COLORS.panelAlt, color: COLORS.bone,
  border: `1px solid ${COLORS.line}`,
};

function CopyBtn({ text, small }) {
  const [done, setDone] = useState(false);
  if (text == null || text === '') return null;
  return (
    <button
      onClick={() => navigator.clipboard?.writeText(String(text)).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); })}
      className={`inline-flex items-center gap-1 rounded ${small ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-xs'}`}
      style={{ ...mono, color: done ? COLORS.teal : COLORS.boneDim, border: `1px solid ${COLORS.line}` }}
      title="Copy to clipboard"
    >
      {done ? <Check size={11} /> : <Copy size={11} />} {done ? 'Copied' : 'Copy'}
    </button>
  );
}

function ToolCard({ title, subtitle, children }) {
  return (
    <div className="rounded-lg p-5" style={{ backgroundColor: COLORS.panel, border: `1px solid ${COLORS.line}` }}>
      <div className="mb-1 text-sm font-semibold" style={{ color: COLORS.bone, fontFamily: FONT_BODY }}>{title}</div>
      {subtitle && <div className="mb-3 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{subtitle}</div>}
      {children}
    </div>
  );
}

function Field({ label, value, mono: isMono = true }) {
  return (
    <div className="flex items-start justify-between gap-2 py-1" style={{ borderTop: `1px solid ${COLORS.lineFaint}` }}>
      <span className="text-xs shrink-0" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{label}</span>
      <span className="text-xs text-right break-all" style={{ color: COLORS.bone, fontFamily: isMono ? FONT_MONO : FONT_BODY }}>{value}</span>
    </div>
  );
}

/* ------------------------------ IOC extractor ----------------------------- */

const IOC_PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  url: /\b(?:https?|hxxps?|ftp):\/\/[^\s<>"')]+/gi,
  eth: /\b0x[a-fA-F0-9]{40}\b/g,
  btc: /\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/g,
  domain: /\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b/g,
};

// Refang first so defanged indicators (hxxp, [.], (at)) are recognised.
function refang(text) {
  return text
    .replace(/\[\.\]|\(\.\)|\{\.\}|\s?dot\s?/gi, '.')
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/\[@\]|\(at\)|\[at\]/gi, '@')
    .replace(/h[x]{2}p(s?)/gi, 'http$1')
    .replace(/\[\/\]/g, '/');
}

function defang(text) {
  return text
    .replace(/https?/gi, (m) => m.replace(/t/gi, 'x').replace(/http/i, 'hxxp').replace(/HTTP/, 'HXXP'))
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]')
    .replace(/:\/\//g, '[://]');
}

function extractIocs(raw) {
  const text = refang(raw);
  const found = {};
  const claimed = new Set(); // avoid a sha256 also being reported as md5/sha1 substring, etc.

  for (const type of ['url', 'email', 'sha256', 'sha1', 'md5', 'eth', 'btc', 'cve', 'ipv4']) {
    const matches = text.match(IOC_PATTERNS[type]) || [];
    const uniq = [...new Set(matches)].filter((m) => {
      // hashes: don't double-count nested hex; a 64-hex already claimed shouldn't yield its 40/32 prefix
      if (['md5', 'sha1'].includes(type) && [...claimed].some((c) => c.includes(m))) return false;
      return true;
    });
    if (uniq.length) { found[type] = uniq; uniq.forEach((m) => claimed.add(m)); }
  }
  // domains last, excluding those already inside emails/urls
  const domains = [...new Set(text.match(IOC_PATTERNS.domain) || [])].filter(
    (d) => !(found.email || []).some((e) => e.endsWith(d)) &&
           !(found.url || []).some((u) => u.includes(d)) &&
           !/^\d+\.\d+\.\d+\.\d+$/.test(d)
  );
  if (domains.length) found.domain = domains;
  return found;
}

const IOC_LABELS = {
  ipv4: 'IPv4', domain: 'Domains', url: 'URLs', email: 'Emails', md5: 'MD5',
  sha1: 'SHA-1', sha256: 'SHA-256', cve: 'CVEs', btc: 'Bitcoin', eth: 'Ethereum',
};

function IocExtractor() {
  const [input, setInput] = useState('');
  const iocs = useMemo(() => (input.trim() ? extractIocs(input) : {}), [input]);
  const total = Object.values(iocs).reduce((n, a) => n + a.length, 0);
  const allDefanged = useMemo(() => {
    const lines = [];
    for (const [t, arr] of Object.entries(iocs)) arr.forEach((v) => lines.push(defang(v)));
    return lines.join('\n');
  }, [iocs]);

  return (
    <ToolCard title="IOC extractor & defanger" subtitle="Paste logs, an email, or a report. Extracts and de-duplicates indicators (defanged inputs like hxxp / [.] are recognised). Nothing is uploaded.">
      <textarea
        value={input} onChange={(e) => setInput(e.target.value)} rows={5}
        placeholder="Paste text containing IOCs…"
        className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y" style={inputStyle}
      />
      <div className="mt-2 flex items-center justify-between">
        <span className="text-xs" style={{ ...mono, color: COLORS.boneFaint }}>{total} indicator{total === 1 ? '' : 's'}</span>
        {total > 0 && <CopyBtn text={allDefanged} />}
      </div>
      {total > 0 && (
        <div className="mt-2 space-y-2">
          {Object.entries(iocs).map(([type, arr]) => (
            <div key={type}>
              <div className="text-xs mb-1" style={{ ...mono, color: COLORS.amber }}>{IOC_LABELS[type]} ({arr.length})</div>
              <div className="rounded p-2 text-xs break-all" style={{ ...mono, color: COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>
                {arr.map((v) => <div key={v}>{defang(v)}</div>)}
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolCard>
  );
}

/* -------------------------- Enrichment launchpad -------------------------- */

function detectIndicatorType(v) {
  const s = refang(v.trim());
  if (!s) return null;
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s)) return 'ip';
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(s)) return 'hash';
  if (/^CVE-\d{4}-\d{4,7}$/i.test(s)) return 'cve';
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s)) return 'email';
  if (/^(?:https?):\/\//i.test(s)) return 'url';
  if (/^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}$/.test(s)) return 'domain';
  return 'keyword';
}

// All links are keyless deep-links into each engine's own UI (pre-filled with
// the indicator). No API keys — a public site can't safely hold them — and no
// cross-origin fetch, so nothing here can break on CORS. This is the correct
// way to "add" the big threat-intel APIs (VirusTotal, OTX, Shodan, GreyNoise,
// AbuseIPDB, Pulsedive, ThreatMiner, URLhaus, IntelX, HIBP…) to a keyless site.
const PIVOTS = {
  ip: (v) => [
    ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${v}`],
    ['AbuseIPDB', `https://www.abuseipdb.com/check/${v}`],
    ['GreyNoise', `https://viz.greynoise.io/ip/${v}`],
    ['Shodan', `https://www.shodan.io/host/${v}`],
    ['AlienVault OTX', `https://otx.alienvault.com/indicator/ip/${v}`],
    ['Pulsedive', `https://pulsedive.com/indicator/?ioc=${encodeURIComponent(v)}`],
    ['ThreatMiner', `https://www.threatminer.org/host.php?q=${v}`],
    ['Censys', `https://search.censys.io/hosts/${v}`],
    ['urlscan', `https://urlscan.io/search/#${encodeURIComponent(v)}`],
  ],
  domain: (v) => [
    ['VirusTotal', `https://www.virustotal.com/gui/domain/${v}`],
    ['AlienVault OTX', `https://otx.alienvault.com/indicator/domain/${v}`],
    ['Pulsedive', `https://pulsedive.com/indicator/?ioc=${encodeURIComponent(v)}`],
    ['URLhaus', `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(v)}`],
    ['ThreatMiner', `https://www.threatminer.org/domain.php?q=${v}`],
    ['urlscan', `https://urlscan.io/domain/${v}`],
    ['crt.sh', `https://crt.sh/?q=${encodeURIComponent(v)}`],
    ['Shodan', `https://www.shodan.io/search?query=${encodeURIComponent('hostname:' + v)}`],
    ['Web Archive', `https://web.archive.org/web/2/${v}`],
    ['WHOIS', `https://www.whois.com/whois/${v}`],
  ],
  url: (v) => [
    ['VirusTotal', `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`],
    ['URLhaus', `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(v)}`],
    ['urlscan', `https://urlscan.io/search/#${encodeURIComponent(v)}`],
    ['Web Archive', `https://web.archive.org/web/2/${v}`],
  ],
  hash: (v) => [
    ['VirusTotal', `https://www.virustotal.com/gui/file/${v}`],
    ['AlienVault OTX', `https://otx.alienvault.com/indicator/file/${v}`],
    ['MalwareBazaar', `https://bazaar.abuse.ch/browse.php?search=${v}`],
    ['ThreatFox', `https://threatfox.abuse.ch/browse.php?search=ioc%3A${v}`],
    ['ThreatMiner', `https://www.threatminer.org/sample.php?q=${v}`],
  ],
  email: (v) => [
    ['Have I Been Pwned', `https://haveibeenpwned.com/account/${encodeURIComponent(v)}`],
    ['Intelligence X', `https://intelx.io/?s=${encodeURIComponent(v)}`],
    ['Epieos', `https://epieos.com/?q=${encodeURIComponent(v)}`],
  ],
  cve: (v) => [
    ['NVD', `https://nvd.nist.gov/vuln/detail/${v}`],
    ['CVE.org', `https://www.cve.org/CVERecord?id=${v}`],
    ['CISA KEV', `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${v}`],
    ['Exploit-DB', `https://www.exploit-db.com/search?cve=${v}`],
  ],
  keyword: (v) => [
    ['ransomware.live', `https://www.ransomware.live/#/search?search=${encodeURIComponent(v)}`],
    ['AlienVault OTX', `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}`],
    ['MITRE ATT&CK', `https://attack.mitre.org/groups/`],
    ['Google', `https://www.google.com/search?q=${encodeURIComponent(v)}`],
  ],
};

function EnrichmentLaunchpad() {
  const [value, setValue] = useState('');
  const type = value.trim() ? detectIndicatorType(value) : null;
  const clean = refang(value.trim());
  const links = type ? PIVOTS[type](clean) : [];
  return (
    <ToolCard title="Enrichment launchpad" subtitle="Paste any indicator (IP, domain, URL, hash, email, CVE, or actor name). One click pivots to the right free tool, so no more retyping into six tabs.">
      <input
        value={value} onChange={(e) => setValue(e.target.value)}
        placeholder="8.8.8.8 · evil[.]com · <sha256> · CVE-2024-3400 · LockBit"
        className="w-full text-sm rounded-md px-3 py-2 outline-none" style={inputStyle}
      />
      {type && (
        <>
          <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.boneFaint }}>
            detected: <span style={{ color: COLORS.teal }}>{type}</span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {links.map(([name, href]) => (
              <a key={name} href={href} target="_blank" rel="noopener noreferrer"
                 className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs hover:underline"
                 style={{ ...mono, color: COLORS.amberSoft, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}` }}>
                <ExternalLink size={11} /> {name}
              </a>
            ))}
          </div>
        </>
      )}
    </ToolCard>
  );
}

/* ------------------------------ Base64 ------------------------------------ */

function Base64Tool() {
  const [text, setText] = useState('');
  let encoded = '', decoded = '', decErr = false;
  try { encoded = text ? btoa(unescape(encodeURIComponent(text))) : ''; } catch { /* noop */ }
  try { decoded = text ? decodeURIComponent(escape(atob(text.trim()))) : ''; } catch { decErr = true; }
  return (
    <ToolCard title="Base64 encode / decode" subtitle="UTF-8 safe, both directions at once.">
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3}
        placeholder="Type text to encode, or paste base64 to decode…"
        className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y" style={inputStyle} />
      <div className="mt-2 space-y-2">
        <div>
          <div className="flex items-center justify-between mb-1"><span className="text-xs" style={{ ...mono, color: COLORS.amber }}>Encoded</span><CopyBtn text={encoded} small /></div>
          <div className="rounded p-2 text-xs break-all min-h-[2rem]" style={{ ...mono, color: COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{encoded}</div>
        </div>
        <div>
          <div className="flex items-center justify-between mb-1"><span className="text-xs" style={{ ...mono, color: COLORS.amber }}>Decoded</span><CopyBtn text={decErr ? '' : decoded} small /></div>
          <div className="rounded p-2 text-xs break-all min-h-[2rem]" style={{ ...mono, color: decErr ? COLORS.boneFaint : COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{decErr ? 'not valid base64' : decoded}</div>
        </div>
      </div>
    </ToolCard>
  );
}

/* ------------------------------ JWT decoder ------------------------------- */

function b64urlDecode(seg) {
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4));
  return decodeURIComponent(escape(atob(seg.replace(/-/g, '+').replace(/_/g, '/') + pad)));
}

function JwtTool() {
  const [token, setToken] = useState('');
  let header = null, payload = null, err = null;
  if (token.trim()) {
    try {
      const [h, p] = token.trim().split('.');
      header = JSON.stringify(JSON.parse(b64urlDecode(h)), null, 2);
      payload = JSON.parse(b64urlDecode(p));
    } catch { err = 'not a decodable JWT'; }
  }
  const claim = (k) => (payload && payload[k] != null ? new Date(payload[k] * 1000).toISOString() : null);
  return (
    <ToolCard title="JWT decoder" subtitle="Decodes header & claims (does NOT verify the signature, so never paste production secrets).">
      <textarea value={token} onChange={(e) => setToken(e.target.value)} rows={3}
        placeholder="eyJhbGciOi…" className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y break-all" style={inputStyle} />
      {err && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>{err}</div>}
      {payload && (
        <div className="mt-2 space-y-2">
          <div><div className="text-xs mb-1" style={{ ...mono, color: COLORS.amber }}>Header</div>
            <pre className="rounded p-2 text-xs overflow-x-auto" style={{ ...mono, color: COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{header}</pre></div>
          <div><div className="text-xs mb-1" style={{ ...mono, color: COLORS.amber }}>Payload</div>
            <pre className="rounded p-2 text-xs overflow-x-auto" style={{ ...mono, color: COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{JSON.stringify(payload, null, 2)}</pre></div>
          {claim('iat') && <Field label="issued (iat)" value={claim('iat')} />}
          {claim('exp') && <Field label="expires (exp)" value={`${claim('exp')} ${new Date(payload.exp * 1000) < new Date() ? '· EXPIRED' : ''}`} />}
        </div>
      )}
    </ToolCard>
  );
}

/* --------------------------- Timestamp converter -------------------------- */

function TimestampTool() {
  const [val, setVal] = useState('');
  let date = null;
  const t = val.trim();
  if (t) {
    if (/^\d{10}$/.test(t)) date = new Date(parseInt(t, 10) * 1000);
    else if (/^\d{13}$/.test(t)) date = new Date(parseInt(t, 10));
    else { const d = new Date(t); if (!isNaN(d.getTime())) date = d; }
  }
  const ok = date && !isNaN(date.getTime());
  return (
    <ToolCard title="Timestamp converter" subtitle="Unix seconds/ms or any date string ↔ UTC / local / epoch.">
      <div className="flex gap-2">
        <input value={val} onChange={(e) => setVal(e.target.value)} placeholder="1718900000 · 2026-07-21T14:00:00Z"
          className="flex-1 text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
        <button onClick={() => setVal(String(Math.floor(Date.now() / 1000)))}
          className="text-xs px-2 rounded-md" style={{ ...mono, color: COLORS.boneDim, border: `1px solid ${COLORS.line}` }}>now</button>
      </div>
      {t && !ok && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>unrecognised timestamp</div>}
      {ok && (
        <div className="mt-2">
          <Field label="ISO 8601 (UTC)" value={date.toISOString()} />
          <Field label="Local" value={date.toString()} />
          <Field label="Unix (s)" value={Math.floor(date.getTime() / 1000)} />
          <Field label="Unix (ms)" value={date.getTime()} />
        </div>
      )}
    </ToolCard>
  );
}

/* ---------------------------- Hash calculator ----------------------------- */

const HASH_ALGOS = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

function HashTool() {
  const [text, setText] = useState('');
  const [hashes, setHashes] = useState({});
  React.useEffect(() => {
    let cancelled = false;
    if (!text) { setHashes({}); return; }
    (async () => {
      const enc = new TextEncoder().encode(text);
      const out = {};
      for (const algo of HASH_ALGOS) {
        const buf = await crypto.subtle.digest(algo, enc);
        out[algo] = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
      }
      if (!cancelled) setHashes(out);
    })();
    return () => { cancelled = true; };
  }, [text]);
  return (
    <ToolCard title="Hash calculator" subtitle="SHA family via the browser's WebCrypto (computed locally).">
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={2}
        placeholder="Text to hash…" className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y" style={inputStyle} />
      {Object.keys(hashes).length > 0 && (
        <div className="mt-2 space-y-1">
          {HASH_ALGOS.map((a) => (
            <div key={a}>
              <div className="flex items-center justify-between"><span className="text-xs" style={{ ...mono, color: COLORS.amber }}>{a}</span><CopyBtn text={hashes[a]} small /></div>
              <div className="rounded p-1.5 text-xs break-all" style={{ ...mono, color: COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{hashes[a]}</div>
            </div>
          ))}
        </div>
      )}
    </ToolCard>
  );
}

/* ----------------------------- Entropy ------------------------------------ */

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((s, c) => { const p = c / len; return s + p * Math.log2(p); }, 0);
}

function EntropyTool() {
  const [text, setText] = useState('');
  const e = shannonEntropy(text);
  const verdict = !text ? '' : e > 4.2 ? 'high: looks random/encoded (DGA, packed, ciphertext)' : e > 3 ? 'moderate' : 'low: looks like natural text';
  return (
    <ToolCard title="Shannon entropy" subtitle="Score a string's randomness to flag DGA domains, packed strings, or encoded blobs.">
      <input value={text} onChange={(e2) => setText(e2.target.value)} placeholder="kq3v9z7x2p.com"
        className="w-full text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
      {text && (
        <div className="mt-2">
          <Field label="Entropy (bits/char)" value={e.toFixed(3)} />
          <Field label="Assessment" value={verdict} mono={false} />
        </div>
      )}
    </ToolCard>
  );
}

/* ---------------------------- Regex tester -------------------------------- */

function RegexTool() {
  const [pattern, setPattern] = useState('');
  const [flags, setFlags] = useState('g');
  const [test, setTest] = useState('');
  let matches = [], err = null;
  if (pattern && test) {
    try {
      const re = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g');
      matches = [...test.matchAll(re)].map((m) => m[0]);
    } catch (e) { err = e.message; }
  }
  return (
    <ToolCard title="Regex tester" subtitle="Live match against a test string.">
      <div className="flex gap-2">
        <input value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="pattern"
          className="flex-1 text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
        <input value={flags} onChange={(e) => setFlags(e.target.value)} placeholder="flags"
          className="w-20 text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
      </div>
      <textarea value={test} onChange={(e) => setTest(e.target.value)} rows={3} placeholder="test string…"
        className="mt-2 w-full text-sm rounded-md px-3 py-2 outline-none resize-y" style={inputStyle} />
      {err && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>{err}</div>}
      {!err && pattern && test && (
        <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.boneFaint }}>
          {matches.length} match{matches.length === 1 ? '' : 'es'}
          {matches.length > 0 && <div className="mt-1 rounded p-2 break-all" style={{ color: COLORS.teal, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{matches.join('  ·  ')}</div>}
        </div>
      )}
    </ToolCard>
  );
}

/* ----------------------------- CVSS 3.1 ----------------------------------- */

const CVSS_METRICS = [
  ['AV', 'Attack Vector', [['N', 'Network', 0.85], ['A', 'Adjacent', 0.62], ['L', 'Local', 0.55], ['P', 'Physical', 0.2]]],
  ['AC', 'Attack Complexity', [['L', 'Low', 0.77], ['H', 'High', 0.44]]],
  ['PR', 'Privileges Required', [['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  ['UI', 'User Interaction', [['N', 'None', 0.85], ['R', 'Required', 0.62]]],
  ['S', 'Scope', [['U', 'Unchanged'], ['C', 'Changed']]],
  ['C', 'Confidentiality', [['N', 'None', 0], ['L', 'Low', 0.22], ['H', 'High', 0.56]]],
  ['I', 'Integrity', [['N', 'None', 0], ['L', 'Low', 0.22], ['H', 'High', 0.56]]],
  ['A', 'Availability', [['N', 'None', 0], ['L', 'Low', 0.22], ['H', 'High', 0.56]]],
];

function cvssRoundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function cvssScore(m) {
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const ac = { L: 0.77, H: 0.44 }[m.AC];
  const ui = { N: 0.85, R: 0.62 }[m.UI];
  const pr = m.S === 'C'
    ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR]
    : { N: 0.85, L: 0.62, H: 0.27 }[m.PR];
  const cia = { N: 0, L: 0.22, H: 0.56 };
  const iss = 1 - (1 - cia[m.C]) * (1 - cia[m.I]) * (1 - cia[m.A]);
  const impact = m.S === 'C'
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return cvssRoundup(Math.min((m.S === 'C' ? 1.08 : 1) * (impact + expl), 10));
}

function cvssSeverity(s) {
  if (s === 0) return ['None', COLORS.teal];
  if (s < 4) return ['Low', COLORS.teal];
  if (s < 7) return ['Medium', COLORS.amberSoft];
  if (s < 9) return ['High', COLORS.amber];
  return ['Critical', COLORS.red];
}

function CvssTool() {
  const [m, setM] = useState({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  const score = cvssScore(m);
  const [sevLabel, sevColor] = cvssSeverity(score);
  const vector = `CVSS:3.1/${CVSS_METRICS.map(([k]) => `${k}:${m[k]}`).join('/')}`;
  return (
    <ToolCard title="CVSS 3.1 base score" subtitle="Compute a base score + vector string from the eight base metrics.">
      <div className="grid grid-cols-2 gap-2">
        {CVSS_METRICS.map(([key, label, opts]) => (
          <div key={key}>
            <div className="text-xs mb-1" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>{label}</div>
            <div className="flex flex-wrap gap-1">
              {opts.map(([code, name]) => (
                <button key={code} onClick={() => setM({ ...m, [key]: code })}
                  className="text-xs px-1.5 py-0.5 rounded" title={name}
                  style={{ ...mono, border: `1px solid ${COLORS.line}`,
                    color: m[key] === code ? COLORS.ink : COLORS.boneDim,
                    backgroundColor: m[key] === code ? COLORS.amber : 'transparent' }}>
                  {code}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-3" style={{ borderTop: `1px solid ${COLORS.line}`, paddingTop: 12 }}>
        <span style={{ ...mono, fontSize: 28, color: sevColor }}>{score.toFixed(1)}</span>
        <span className="text-sm font-semibold" style={{ color: sevColor, fontFamily: FONT_BODY }}>{sevLabel}</span>
        <div className="ml-auto"><CopyBtn text={vector} /></div>
      </div>
      <div className="mt-1 text-xs break-all" style={{ ...mono, color: COLORS.boneFaint }}>{vector}</div>
    </ToolCard>
  );
}

/* --------------------------- CIDR / subnet calc --------------------------- */

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const oct of parts) {
    if (!/^\d{1,3}$/.test(oct)) return null;
    const v = Number(oct);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function CidrTool() {
  const [val, setVal] = useState('');
  const [testIp, setTestIp] = useState('');
  const info = useMemo(() => {
    const s = val.trim();
    if (!s) return null;
    let ipStr = s, prefix = 32;
    if (s.includes('/')) { const [a, b] = s.split('/'); ipStr = a; prefix = Number(b); }
    const base = ipToInt(ipStr);
    if (base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return { error: true };
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const network = (base & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const total = Math.pow(2, 32 - prefix);
    return {
      prefix,
      netmask: intToIp(mask),
      wildcard: intToIp(~mask >>> 0),
      network: intToIp(network),
      broadcast: intToIp(broadcast),
      firstHost: intToIp(prefix >= 31 ? network : (network + 1) >>> 0),
      lastHost: intToIp(prefix >= 31 ? broadcast : (broadcast - 1) >>> 0),
      total,
      usable: prefix >= 31 ? total : Math.max(total - 2, 0),
      _net: network, _bcast: broadcast,
    };
  }, [val]);
  const contains = useMemo(() => {
    if (!info || info.error || !testIp.trim()) return null;
    const t = ipToInt(testIp.trim());
    if (t === null) return null;
    return t >= info._net && t <= info._bcast;
  }, [info, testIp]);
  return (
    <ToolCard title="CIDR / subnet calculator" subtitle="Expand an IPv4 CIDR to its range, mask, and host count, and test whether an address falls inside it. Handy for scoping and blocklists.">
      <input value={val} onChange={(e) => setVal(e.target.value)} placeholder="10.0.0.0/24  ·  192.168.1.50/26"
        className="w-full text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
      {info && info.error && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>not a valid IPv4 CIDR</div>}
      {info && !info.error && (
        <div className="mt-2">
          <Field label="Network" value={`${info.network}/${info.prefix}`} />
          <Field label="Netmask" value={info.netmask} />
          <Field label="Wildcard" value={info.wildcard} />
          <Field label="Broadcast" value={info.broadcast} />
          <Field label="Host range" value={`${info.firstHost} to ${info.lastHost}`} />
          <Field label="Total addresses" value={info.total.toLocaleString()} />
          <Field label="Usable hosts" value={info.usable.toLocaleString()} />
          <div className="mt-3">
            <div className="text-xs mb-1" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>Contains address?</div>
            <input value={testIp} onChange={(e) => setTestIp(e.target.value)} placeholder="10.0.0.42"
              className="w-full text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
            {testIp.trim() && (
              <div className="mt-1 text-xs" style={{ ...mono, color: contains == null ? COLORS.red : contains ? COLORS.teal : COLORS.amber }}>
                {contains == null ? 'not a valid address' : contains ? 'in range ✓' : 'outside range ✗'}
              </div>
            )}
          </div>
        </div>
      )}
    </ToolCard>
  );
}

/* --------------------------- Hash identifier ------------------------------ */

function identifyHash(raw) {
  const s = raw.trim();
  if (!s) return null;
  const prefixed = [
    [/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/, 'bcrypt'],
    [/^\$argon2(id|i|d)\$/, 'Argon2'],
    [/^\$6\$/, 'sha512crypt ($6$)'],
    [/^\$5\$/, 'sha256crypt ($5$)'],
    [/^\$1\$/, 'md5crypt ($1$)'],
    [/^\$y\$/, 'yescrypt'],
    [/^\{SSHA\}/i, 'SSHA (LDAP)'],
    [/^\{SHA\}/i, 'SHA-1 (LDAP)'],
    [/^[0-9a-f]{32}:[0-9a-f]{1,}$/i, 'MD5 / NTLM with salt'],
  ];
  for (const [re, name] of prefixed) if (re.test(s)) return { candidates: [name] };
  if (!/^[0-9a-fA-F]+$/.test(s)) return { candidates: [] };
  const byLen = {
    8: ['CRC-32', 'Adler-32'],
    16: ['CRC-64', 'MySQL 3.23'],
    32: ['MD5', 'NTLM', 'MD4', 'LM'],
    40: ['SHA-1', 'RIPEMD-160', 'MySQL 4.1+'],
    56: ['SHA-224', 'SHA3-224'],
    64: ['SHA-256', 'SHA3-256', 'BLAKE2s', 'RIPEMD-256'],
    96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool'],
  };
  return { len: s.length, candidates: byLen[s.length] || [] };
}

function HashIdTool() {
  const [val, setVal] = useState('');
  const res = useMemo(() => identifyHash(val), [val]);
  return (
    <ToolCard title="Hash identifier" subtitle="Guess a hash's algorithm from its length and format (MD5, SHA family, NTLM, bcrypt, crypt schemes). Pairs with the IOC extractor.">
      <textarea value={val} onChange={(e) => setVal(e.target.value)} rows={2}
        placeholder="Paste a hash…" className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y break-all" style={inputStyle} />
      {res && (
        <div className="mt-2">
          {res.len && <div className="text-xs mb-1" style={{ ...mono, color: COLORS.boneFaint }}>{res.len} hex chars</div>}
          {res.candidates.length === 0 ? (
            <div className="text-xs" style={{ ...mono, color: COLORS.boneFaint }}>no known format matches</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {res.candidates.map((c, i) => (
                <span key={c} className="text-xs px-2 py-0.5 rounded" style={{ ...mono, color: i === 0 ? COLORS.teal : COLORS.amberSoft, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.line}` }}>{c}</span>
              ))}
            </div>
          )}
          {res.candidates.length > 1 && <div className="mt-1 text-xs" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>Length is ambiguous, most likely first.</div>}
        </div>
      )}
    </ToolCard>
  );
}

/* ------------------------------ URL dissector ----------------------------- */

function UrlTool() {
  const [val, setVal] = useState('');
  const info = useMemo(() => {
    const raw = refang(val.trim());
    if (!raw) return null;
    let u;
    try { u = new URL(raw); } catch { try { u = new URL('http://' + raw); } catch { return { error: true }; } }
    let params = [];
    try { params = [...u.searchParams.entries()]; } catch { /* noop */ }
    const flags = [];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) flags.push('Host is a raw IP address');
    if (u.hostname.split('.').some((l) => l.startsWith('xn--'))) flags.push('Punycode/IDN host (possible homograph)');
    if (u.username || u.password) flags.push('Embedded credentials in userinfo (@)');
    if (u.port && !['80', '443', ''].includes(u.port)) flags.push(`Non-standard port ${u.port}`);
    if (!['http:', 'https:'].includes(u.protocol)) flags.push(`Unusual scheme ${u.protocol}`);
    if (u.hostname.split('.').length > 4) flags.push('Deeply nested subdomains');
    if (/%[0-9a-fA-F]{2}/.test(u.pathname + u.search)) flags.push('Percent-encoded characters');
    let decodedPath = u.pathname;
    try { decodedPath = decodeURIComponent(u.pathname); } catch { /* keep raw */ }
    return { u, params, flags, decodedPath };
  }, [val]);
  return (
    <ToolCard title="URL dissector" subtitle="Break a URL into its parts, decode the query string, and flag phishing/C2 traits (raw-IP host, punycode, embedded creds, odd ports). Defanged input is accepted.">
      <textarea value={val} onChange={(e) => setVal(e.target.value)} rows={2}
        placeholder="hxxps://user@evil[.]com:8443/login?next=%2Fadmin" className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y break-all" style={inputStyle} />
      {info && info.error && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>could not parse as a URL</div>}
      {info && !info.error && (
        <div className="mt-2">
          {info.flags.length > 0 && (
            <div className="mb-2 flex flex-wrap gap-1.5">
              {info.flags.map((f) => (
                <span key={f} className="text-xs px-2 py-0.5 rounded" style={{ ...mono, color: COLORS.amber, backgroundColor: 'rgba(217,142,51,0.10)', border: `1px solid ${COLORS.line}` }}>{f}</span>
              ))}
            </div>
          )}
          <Field label="Scheme" value={info.u.protocol.replace(':', '')} />
          <Field label="Host" value={info.u.hostname} />
          {info.u.port && <Field label="Port" value={info.u.port} />}
          {(info.u.username || info.u.password) && <Field label="Userinfo" value={`${info.u.username}${info.u.password ? ':' + info.u.password : ''}`} />}
          <Field label="Path" value={info.decodedPath || '/'} />
          {info.u.hash && <Field label="Fragment" value={info.u.hash} />}
          {info.params.length > 0 && (
            <div className="mt-2">
              <div className="text-xs mb-1" style={{ color: COLORS.boneFaint, fontFamily: FONT_BODY }}>Query parameters</div>
              {info.params.map(([k, v], i) => (
                <Field key={i} label={k} value={v || '(empty)'} />
              ))}
            </div>
          )}
          <div className="mt-2 flex items-center justify-between">
            <span className="text-xs break-all" style={{ ...mono, color: COLORS.boneFaint }}>{defang(info.u.href)}</span>
            <CopyBtn text={defang(info.u.href)} small />
          </div>
        </div>
      )}
    </ToolCard>
  );
}

/* --------------------------- JSON formatter ------------------------------- */

function JsonTool() {
  const [text, setText] = useState('');
  let pretty = '', min = '', err = null;
  const t = text.trim();
  if (t) {
    try { const o = JSON.parse(t); pretty = JSON.stringify(o, null, 2); min = JSON.stringify(o); }
    catch (e) { err = e.message; }
  }
  return (
    <ToolCard title="JSON formatter & validator" subtitle="Pretty-print, minify, and validate JSON. Runs locally.">
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={4}
        placeholder='{"paste":"JSON here"}' className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y break-all" style={inputStyle} />
      {err && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>invalid JSON: {err}</div>}
      {pretty && (
        <div className="mt-2 space-y-2">
          <div>
            <div className="flex items-center justify-between mb-1"><span className="text-xs" style={{ ...mono, color: COLORS.amber }}>Formatted</span><CopyBtn text={pretty} small /></div>
            <pre className="rounded p-2 text-xs overflow-x-auto" style={{ ...mono, color: COLORS.bone, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}`, maxHeight: 240 }}>{pretty}</pre>
          </div>
          <div>
            <div className="flex items-center justify-between mb-1"><span className="text-xs" style={{ ...mono, color: COLORS.amber }}>Minified ({min.length} bytes)</span><CopyBtn text={min} small /></div>
            <div className="rounded p-2 text-xs break-all" style={{ ...mono, color: COLORS.boneDim, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>{min}</div>
          </div>
        </div>
      )}
    </ToolCard>
  );
}

/* --------------------------- Google dork generator ------------------------ */

function DorkTool() {
  const [domain, setDomain] = useState('');
  const [kw, setKw] = useState('');
  const d = domain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  const k = kw.trim();
  const dorks = useMemo(() => {
    const list = [];
    if (d) {
      list.push(['All indexed pages', `site:${d}`]);
      list.push(['Subdomains (exclude www)', `site:${d} -inurl:www`]);
      list.push(['Documents', `site:${d} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:csv)`]);
      list.push(['Exposed configs / data', `site:${d} (ext:env OR ext:sql OR ext:log OR ext:bak OR ext:ini OR ext:yml OR ext:conf)`]);
      list.push(['Login / admin surfaces', `site:${d} (inurl:login OR inurl:admin OR inurl:signin OR inurl:portal OR inurl:dashboard)`]);
      list.push(['Open directory listings', `site:${d} intitle:"index of"`]);
      list.push(['Sensitive text', `site:${d} (intext:password OR intext:confidential OR intext:"internal use only")`]);
      list.push(['Mentioned on Pastebin', `site:pastebin.com "${d}"`]);
      list.push(['Mentioned on GitHub', `site:github.com "${d}"`]);
      list.push(['On cloud / paste hosts', `"${d}" (site:s3.amazonaws.com OR site:trello.com OR site:gitlab.com OR site:atlassian.net)`]);
    }
    if (k) {
      list.push([`"${k}" documents`, `"${k}" (filetype:pdf OR filetype:xlsx OR filetype:docx)`]);
      list.push([`"${k}" on paste sites`, `"${k}" (site:pastebin.com OR site:ghostbin.com OR site:justpaste.it)`]);
      if (d) list.push([`"${k}" on ${d}`, `site:${d} "${k}"`]);
    }
    return list;
  }, [d, k]);

  return (
    <ToolCard title="Google dork generator" subtitle="Build OSINT/recon search queries for a domain or keyword. Opens Google in a new tab; nothing is sent from here.">
      <div className="flex gap-2">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com"
          className="flex-1 text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
        <input value={kw} onChange={(e) => setKw(e.target.value)} placeholder="keyword (optional)"
          className="flex-1 text-sm rounded-md px-3 py-2 outline-none" style={inputStyle} />
      </div>
      {dorks.length > 0 && (
        <div className="mt-2 flex items-center justify-between">
          <span className="text-xs" style={{ ...mono, color: COLORS.boneFaint }}>{dorks.length} dorks</span>
          <CopyBtn text={dorks.map(([, q]) => q).join('\n')} small />
        </div>
      )}
      <div className="mt-2 space-y-1">
        {dorks.map(([label, q]) => (
          <a key={label} href={`https://www.google.com/search?q=${encodeURIComponent(q)}`} target="_blank" rel="noopener noreferrer"
            className="block rounded px-2 py-1.5 hover:underline" style={{ border: `1px solid ${COLORS.lineFaint}` }}>
            <span className="flex items-center gap-1.5 text-xs" style={{ color: COLORS.amberSoft, fontFamily: FONT_BODY }}>
              <ExternalLink size={11} /> {label}
            </span>
            <span className="block text-xs break-all mt-0.5" style={{ ...mono, color: COLORS.boneDim }}>{q}</span>
          </a>
        ))}
        {dorks.length === 0 && <div className="text-xs" style={{ ...mono, color: COLORS.boneFaint }}>Enter a domain or keyword.</div>}
      </div>
    </ToolCard>
  );
}

/* --------------------------- Email header analyzer ------------------------ */

function parseHeaders(raw) {
  const lines = raw.replace(/\r\n/g, '\n').split('\n');
  const headers = [];
  for (const line of lines) {
    if (line.trim() === '' && headers.length) break; // blank line ends the header block
    if (/^[ \t]/.test(line) && headers.length) headers[headers.length - 1].value += ' ' + line.trim();
    else { const m = line.match(/^([!-9;-~]+):[ \t]?(.*)$/); if (m) headers.push({ name: m[1], value: m[2] }); }
  }
  return headers;
}

function EmailHeaderTool() {
  const [raw, setRaw] = useState('');
  const info = useMemo(() => {
    if (!raw.trim()) return null;
    const headers = parseHeaders(raw);
    if (!headers.length) return { empty: true };
    const get = (n) => headers.find((h) => h.name.toLowerCase() === n.toLowerCase())?.value;
    const received = headers.filter((h) => h.name.toLowerCase() === 'received').map((h) => h.value);
    const hops = received.map((r) => {
      const from = (r.match(/from\s+([^\s;()]+)/i) || [])[1];
      const by = (r.match(/\bby\s+([^\s;()]+)/i) || [])[1];
      const dt = new Date((r.split(';').pop() || '').trim());
      return { from, by, date: Number.isNaN(dt.getTime()) ? null : dt };
    });
    const path = [...hops].reverse(); // Received headers are prepended -> reverse = chronological
    const auth = get('Authentication-Results') || '';
    const grab = (re) => (auth.match(re) || [])[1];
    const spf = grab(/spf=(\w+)/i), dkim = grab(/dkim=(\w+)/i), dmarc = grab(/dmarc=(\w+)/i);
    const fromH = get('From'), replyTo = get('Reply-To');
    const domOf = (s) => (s && (s.match(/@([^\s>]+)/) || [])[1] || '').toLowerCase();
    const flags = [];
    const bad = (v) => v && v.toLowerCase() !== 'pass';
    if (bad(spf)) flags.push(`SPF ${spf}`);
    if (bad(dkim)) flags.push(`DKIM ${dkim}`);
    if (bad(dmarc)) flags.push(`DMARC ${dmarc}`);
    if (replyTo && fromH && domOf(replyTo) && domOf(replyTo) !== domOf(fromH)) flags.push('Reply-To domain differs from From');
    return { get, path, spf, dkim, dmarc, fromH, replyTo, flags };
  }, [raw]);

  const authColor = (v) => (!v ? COLORS.boneFaint : v.toLowerCase() === 'pass' ? COLORS.teal : COLORS.red);

  return (
    <ToolCard title="Email header analyzer" subtitle="Paste raw headers to trace the delivery path and read SPF/DKIM/DMARC. Parsed locally; nothing is uploaded.">
      <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={4}
        placeholder="Paste full email headers (Received, From, Authentication-Results, …)" className="w-full text-sm rounded-md px-3 py-2 outline-none resize-y" style={inputStyle} />
      {info && info.empty && <div className="mt-2 text-xs" style={{ ...mono, color: COLORS.red }}>no headers found</div>}
      {info && !info.empty && (
        <div className="mt-2">
          <Field label="From" value={info.fromH || '-'} mono={false} />
          {info.get('To') && <Field label="To" value={info.get('To')} mono={false} />}
          {info.get('Subject') && <Field label="Subject" value={info.get('Subject')} mono={false} />}
          {info.replyTo && <Field label="Reply-To" value={info.replyTo} mono={false} />}
          <div className="flex items-center gap-3 py-1.5" style={{ borderTop: `1px solid ${COLORS.lineFaint}` }}>
            {['SPF', 'DKIM', 'DMARC'].map((a, i) => {
              const v = [info.spf, info.dkim, info.dmarc][i];
              return <span key={a} className="text-xs" style={{ ...mono, color: authColor(v) }}>{a}: {v || 'n/a'}</span>;
            })}
          </div>
          {info.flags.length > 0 && (
            <div className="flex flex-wrap gap-1.5 py-1">
              {info.flags.map((f) => <span key={f} className="text-xs px-2 py-0.5 rounded" style={{ ...mono, color: COLORS.red, backgroundColor: 'rgba(192,71,58,0.10)', border: `1px solid ${COLORS.line}` }}>{f}</span>)}
            </div>
          )}
          {info.path.length > 0 && (
            <div className="mt-1">
              <div className="text-xs mb-1" style={{ ...mono, color: COLORS.amber }}>Delivery path ({info.path.length} hops)</div>
              <div className="space-y-1">
                {info.path.map((h, i) => {
                  const prev = info.path[i - 1];
                  const delay = prev && prev.date && h.date ? Math.round((h.date - prev.date) / 1000) : null;
                  return (
                    <div key={i} className="text-xs rounded p-1.5 break-all" style={{ ...mono, color: COLORS.boneDim, backgroundColor: COLORS.ink, border: `1px solid ${COLORS.lineFaint}` }}>
                      <span style={{ color: COLORS.boneFaint }}>{i + 1}.</span> {h.from || '?'} <span style={{ color: COLORS.boneFaint }}>→</span> {h.by || '?'}
                      {delay != null && <span style={{ color: delay > 30 ? COLORS.amber : COLORS.boneFaint }}> (+{delay}s)</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </ToolCard>
  );
}

/* --------------------------------- View ----------------------------------- */

export function ToolsView() {
  return (
    <div className="px-6 py-6">
      <div className="flex items-center gap-2 mb-1">
        <Wrench size={16} color={COLORS.amber} />
        <h2 style={{ fontFamily: FONT_DISPLAY, color: COLORS.bone, fontSize: 22, fontWeight: 600 }}>Analyst tools</h2>
      </div>
      <p className="text-sm mb-5 max-w-2xl" style={{ color: COLORS.boneDim, fontFamily: FONT_BODY }}>
        Free, browser-only utilities so you don't have to leave the platform for the small pivots.
        Everything here runs locally. No input is uploaded or logged.
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <EnrichmentLaunchpad />
        <IocExtractor />
        <UrlTool />
        <EmailHeaderTool />
        <DorkTool />
        <CidrTool />
        <HashTool />
        <HashIdTool />
        <JsonTool />
        <Base64Tool />
        <JwtTool />
        <TimestampTool />
        <CvssTool />
        <RegexTool />
        <EntropyTool />
      </div>
    </div>
  );
}
