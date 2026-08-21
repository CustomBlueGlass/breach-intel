import test from "node:test";
import assert from "node:assert/strict";

import handler, {
  buildBundle,
  parseParams,
  buildLedgerQuery,
  sanitizeFilter,
  readConfig,
  LIMIT_DEFAULT,
  LIMIT_MAX,
  FILTER_MAX_LEN,
} from "../api/stix.js";

// ---- sample ledger rows (shape of mv_breach_ledger) -----------------------
const ROWS = [
  {
    id: "b1", canonical_name: "Acme Health", industry: "healthcare", country: "US",
    region_state: "CA", ransomware_group: "LockBit", incident_date: "2025-01-10",
    disclosed_date: "2025-02-01", records_affected_est: 120000, severity: "high",
    source_count: 3, data_flags: [],
  },
  {
    id: "b2", canonical_name: "Beta Bank", industry: "finance", country: "UK",
    region_state: null, ransomware_group: "lockbit", incident_date: "2025-03-05",
    disclosed_date: "2025-03-20", records_affected_est: 5000, severity: "moderate",
    source_count: 1, data_flags: [],
  },
  {
    id: "b3", canonical_name: "Gamma Retail", industry: "retail", country: "US",
    region_state: "NY", ransomware_group: null, incident_date: null,
    disclosed_date: "2025-04-01", records_affected_est: null, severity: "low",
    source_count: 2, data_flags: [],
  },
];

const byType = (bundle, t) => bundle.objects.filter((o) => o.type === t);

// ---- bundle structure -----------------------------------------------------
test("valid STIX 2.1 bundle structure", () => {
  const b = buildBundle(ROWS);
  assert.equal(b.type, "bundle");
  assert.match(b.id, /^bundle--/);
  assert.ok(Array.isArray(b.objects), "objects must be an array");
  assert.ok(b.objects.length > 0);
  for (const o of b.objects) {
    assert.ok(typeof o.id === "string" && o.id.length > 0);
    if (o.type !== "marking-definition") assert.equal(o.spec_version, "2.1");
  }
});

test("expected object types are present", () => {
  const b = buildBundle(ROWS);
  assert.equal(byType(b, "marking-definition").length, 1);
  assert.equal(byType(b, "identity").length, 3);
  assert.ok(byType(b, "intrusion-set").length >= 1);
  assert.ok(byType(b, "relationship").length >= 1);
  const ident = byType(b, "identity")[0];
  assert.equal(ident.identity_class, "organization");
  assert.equal(ident.x_breach_id, "b1");
  assert.deepEqual(ident.sectors, ["healthcare"]);
});

test("all references resolve to real objects", () => {
  const b = buildBundle(ROWS);
  const ids = new Set(b.objects.map((o) => o.id));
  for (const r of byType(b, "relationship")) {
    assert.ok(ids.has(r.source_ref), `source_ref ${r.source_ref} must resolve`);
    assert.ok(ids.has(r.target_ref), `target_ref ${r.target_ref} must resolve`);
  }
  for (const o of b.objects) {
    for (const m of o.object_marking_refs || []) {
      assert.ok(ids.has(m), `marking ref ${m} must resolve`);
    }
  }
});

test("threat actor is deduplicated across breaches (case-insensitive)", () => {
  const b = buildBundle(ROWS);
  // LockBit + lockbit -> a single intrusion-set, one relationship per victim.
  assert.equal(byType(b, "intrusion-set").length, 1);
  assert.equal(byType(b, "relationship").length, 2);
});

test("buildBundle tolerates empty / missing input", () => {
  for (const input of [[], null, undefined]) {
    const b = buildBundle(input);
    assert.equal(b.type, "bundle");
    assert.equal(byType(b, "identity").length, 0);
    assert.equal(byType(b, "marking-definition").length, 1);
  }
});

// ---- parameter validation -------------------------------------------------
test("limit bounds are clamped", () => {
  assert.equal(parseParams({}).limit, LIMIT_DEFAULT);
  assert.equal(parseParams({ limit: "50" }).limit, 50);
  assert.equal(parseParams({ limit: "999999" }).limit, LIMIT_MAX);
  assert.equal(parseParams({ limit: "0" }).limit, 1);
  assert.equal(parseParams({ limit: "-10" }).limit, 1);
  assert.equal(parseParams({ limit: "abc" }).limit, LIMIT_DEFAULT);
});

test("since accepts only YYYY-MM-DD", () => {
  assert.equal(parseParams({ since: "2025-01-01" }).since, "2025-01-01");
  assert.equal(parseParams({ since: "not-a-date" }).since, "");
  assert.equal(parseParams({ since: "2025-01-01;DROP TABLE" }).since, "");
  assert.equal(parseParams({ since: "" }).since, "");
});

test("group filter is included in the ledger query", () => {
  const p = parseParams({ group: "LockBit" });
  const qs = buildLedgerQuery(p).toString();
  assert.match(qs, /ransomware_group=ilike\.LockBit/);
});

test("industry filter is included in the ledger query", () => {
  const p = parseParams({ industry: "healthcare" });
  const qs = buildLedgerQuery(p).toString();
  assert.match(qs, /industry=eq\.healthcare/);
});

test("no filters => no group/industry/since params", () => {
  const qs = buildLedgerQuery(parseParams({})).toString();
  assert.doesNotMatch(qs, /ransomware_group=/);
  assert.doesNotMatch(qs, /industry=/);
  assert.match(qs, /limit=500/);
});

// ---- security: PostgREST filter injection / escaping ----------------------
test("sanitizeFilter strips PostgREST logic chars and bounds length", () => {
  assert.equal(sanitizeFilter("Lock,Bit()*"), "Lock Bit");
  assert.equal(sanitizeFilter("  spaced  "), "spaced");
  assert.equal(sanitizeFilter("x".repeat(500)).length, FILTER_MAX_LEN);
});

test("malicious group cannot inject extra PostgREST filters", () => {
  // Attempt to break out of ilike.<val> into an or()/extra filter.
  const p = parseParams({ group: "x,is.null),industry.eq.finance" });
  assert.doesNotMatch(p.group, /[,()*]/);
  const decoded = decodeURIComponent(buildLedgerQuery(p).toString());
  // Only one ransomware_group filter, and no injected industry filter.
  assert.equal((decoded.match(/ransomware_group=/g) || []).length, 1);
  assert.doesNotMatch(decoded, /industry=eq\.finance/);
});

// ---- handler behaviour (no live Supabase) ---------------------------------
function mockRes() {
  return {
    statusCode: null,
    headers: {},
    body: undefined,
    ended: false,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
    end() { this.ended = true; return this; },
  };
}

function withStubbedFetch(fn, impl) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve()
    .then(fn)
    .finally(() => { globalThis.fetch = original; });
}

test("unsupported HTTP method returns 405", async () => {
  const res = mockRes();
  await handler({ method: "POST", query: {} }, res);
  assert.equal(res.statusCode, 405);
});

test("OPTIONS preflight returns 204 with CORS headers", async () => {
  const res = mockRes();
  await handler({ method: "OPTIONS", query: {} }, res);
  assert.equal(res.statusCode, 204);
  assert.equal(res.headers["access-control-allow-origin"], "*");
  assert.ok(res.ended);
});

test("missing configuration returns 500 and makes no network call", async () => {
  const saved = {
    a: process.env.VITE_SUPABASE_URL, b: process.env.VITE_SUPABASE_ANON_KEY,
    c: process.env.SUPABASE_URL, d: process.env.SUPABASE_ANON_KEY,
  };
  delete process.env.VITE_SUPABASE_URL;
  delete process.env.VITE_SUPABASE_ANON_KEY;
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_ANON_KEY;
  let called = false;
  try {
    await withStubbedFetch(
      async () => {
        const res = mockRes();
        await handler({ method: "GET", query: {} }, res);
        assert.equal(res.statusCode, 500);
        assert.match(res.body.error, /not configured/);
      },
      async () => { called = true; return { ok: true, status: 200, json: async () => [] }; }
    );
    assert.equal(called, false, "fetch must not run without config");
  } finally {
    if (saved.a !== undefined) process.env.VITE_SUPABASE_URL = saved.a;
    if (saved.b !== undefined) process.env.VITE_SUPABASE_ANON_KEY = saved.b;
    if (saved.c !== undefined) process.env.SUPABASE_URL = saved.c;
    if (saved.d !== undefined) process.env.SUPABASE_ANON_KEY = saved.d;
  }
});

test("configured GET returns a 200 STIX bundle (stubbed Supabase)", async () => {
  process.env.VITE_SUPABASE_URL = "https://example.supabase.co";
  process.env.VITE_SUPABASE_ANON_KEY = "anon-key";
  let requestedUrl = null;
  await withStubbedFetch(
    async () => {
      const res = mockRes();
      await handler({ method: "GET", query: { limit: "10" } }, res);
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.type, "bundle");
      assert.ok(Array.isArray(res.body.objects));
      assert.match(res.headers["content-type"], /application\/json/);
    },
    async (url) => {
      requestedUrl = url;
      return { ok: true, status: 200, json: async () => ROWS };
    }
  );
  // Reads the public ledger view via the anon key, never a service-role path.
  assert.match(requestedUrl, /\/rest\/v1\/mv_breach_ledger\?/);
  delete process.env.VITE_SUPABASE_URL;
  delete process.env.VITE_SUPABASE_ANON_KEY;
});

test("upstream failure surfaces as 502, not a crash", async () => {
  process.env.VITE_SUPABASE_URL = "https://example.supabase.co";
  process.env.VITE_SUPABASE_ANON_KEY = "anon-key";
  await withStubbedFetch(
    async () => {
      const res = mockRes();
      await handler({ method: "GET", query: {} }, res);
      assert.equal(res.statusCode, 502);
    },
    async () => ({ ok: false, status: 500, json: async () => ({}) })
  );
  delete process.env.VITE_SUPABASE_URL;
  delete process.env.VITE_SUPABASE_ANON_KEY;
});

test("readConfig never falls back to a service-role variable", () => {
  // Guard against accidentally wiring the privileged key into the feed.
  const src = readConfig.toString();
  assert.doesNotMatch(src, /SERVICE_ROLE/i);
});
