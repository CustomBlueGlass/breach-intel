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
        <HashTool />
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
