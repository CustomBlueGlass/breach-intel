import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import enrich from "../api/enrich.js";
import exposure from "../api/exposure.js";

const HERE = dirname(fileURLToPath(import.meta.url));

function mockRes() {
  return {
    statusCode: null, headers: {}, body: undefined, ended: false,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
    end() { this.ended = true; return this; },
  };
}
const reqOf = (over = {}) => ({
  method: "GET", query: {}, headers: { "x-forwarded-for": `test-${Math.random()}` },
  socket: { remoteAddress: "203.0.113.9" }, ...over,
});
function withFetch(impl, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve().then(fn).finally(() => { globalThis.fetch = orig; });
}

// ---------------- /api/enrich ----------------
test("enrich: unsupported method -> 405", async () => {
  const res = mockRes();
  await enrich(reqOf({ method: "POST" }), res);
  assert.equal(res.statusCode, 405);
});

test("enrich: OPTIONS -> 204", async () => {
  const res = mockRes();
  await enrich(reqOf({ method: "OPTIONS" }), res);
  assert.equal(res.statusCode, 204);
});

test("enrich: empty / oversized / malformed indicator -> 400", async () => {
  for (const indicator of ["", "x".repeat(200), "not an indicator!!"]) {
    const res = mockRes();
    await enrich(reqOf({ query: { indicator } }), res);
    assert.equal(res.statusCode, 400, `indicator=${indicator.slice(0, 12)}`);
  }
});

test("enrich: private / reserved IP is rejected before any upstream call", async () => {
  let called = false;
  await withFetch(async () => { called = true; return { ok: true, json: async () => ({}) }; }, async () => {
    for (const ip of ["10.0.0.1", "127.0.0.1", "192.168.1.5", "169.254.1.1", "172.16.0.1"]) {
      const res = mockRes();
      await enrich(reqOf({ query: { indicator: ip } }), res);
      assert.equal(res.statusCode, 400, ip);
    }
  });
  assert.equal(called, false, "no upstream fetch for private IPs");
});

test("enrich: valid public CVE returns 200 (stubbed upstream)", async () => {
  await withFetch(
    async () => ({ ok: true, status: 200, json: async () => ({ data: [{ epss: "0.5", percentile: "0.9", date: "2026-01-01" }] }) }),
    async () => {
      const res = mockRes();
      await enrich(reqOf({ query: { indicator: "CVE-2024-3400" } }), res);
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.type, "cve");
    }
  );
});

test("enrich: rate limit kicks in for a hot client -> 429", async () => {
  const ip = "198.51.100.7";
  let last = mockRes();
  await withFetch(
    async () => ({ ok: true, status: 200, json: async () => ({ data: [] }) }),
    async () => {
      for (let i = 0; i < 65; i++) {
        last = mockRes();
        await enrich({ method: "GET", query: { indicator: "CVE-2024-3400" }, headers: { "x-forwarded-for": ip }, socket: {} }, last);
      }
    }
  );
  assert.equal(last.statusCode, 429);
});

// ---------------- /api/exposure ----------------
test("exposure: unsupported method -> 405", async () => {
  const res = mockRes();
  await exposure(reqOf({ method: "POST" }), res);
  assert.equal(res.statusCode, 405);
});

test("exposure: not configured -> 200 { configured:false } and no provider call", async () => {
  const saved = { b: process.env.BREACHDIRECTORY_API_KEY, d: process.env.DEHASHED_API_KEY };
  delete process.env.BREACHDIRECTORY_API_KEY;
  delete process.env.DEHASHED_API_KEY;
  try {
    const res = mockRes();
    await exposure(reqOf({ query: { domain: "example.com" } }), res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.configured, false);
  } finally {
    if (saved.b !== undefined) process.env.BREACHDIRECTORY_API_KEY = saved.b;
    if (saved.d !== undefined) process.env.DEHASHED_API_KEY = saved.d;
  }
});

test("exposure: configured but unauthenticated -> 401 (paid keys not consumed)", async () => {
  process.env.DEHASHED_API_KEY = "test-key";
  process.env.VITE_SUPABASE_URL = "https://x.supabase.co";
  process.env.VITE_SUPABASE_ANON_KEY = "anon";
  let dehashedCalled = false;
  try {
    await withFetch(
      async (url) => {
        if (url.includes("dehashed")) dehashedCalled = true;
        // no Authorization header provided -> hasValidSession returns false before any auth call
        return { ok: false, status: 401, json: async () => ({}) };
      },
      async () => {
        const res = mockRes();
        await exposure(reqOf({ query: { domain: "example.com" } }), res); // no auth header
        assert.equal(res.statusCode, 401);
        assert.equal(res.body.authRequired, true);
      }
    );
    assert.equal(dehashedCalled, false, "paid provider must not run without a session");
  } finally {
    delete process.env.DEHASHED_API_KEY;
    delete process.env.VITE_SUPABASE_URL;
    delete process.env.VITE_SUPABASE_ANON_KEY;
  }
});

test("exposure: authenticated + bad domain -> 400 (validated before providers)", async () => {
  process.env.DEHASHED_API_KEY = "test-key";
  process.env.VITE_SUPABASE_URL = "https://x.supabase.co";
  process.env.VITE_SUPABASE_ANON_KEY = "anon";
  let dehashedCalled = false;
  try {
    await withFetch(
      async (url) => {
        if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "u1" }) };
        if (url.includes("dehashed")) { dehashedCalled = true; return { ok: true, json: async () => ({ entries: [] }) }; }
        return { ok: true, json: async () => ({}) };
      },
      async () => {
        const res = mockRes();
        await exposure(reqOf({ query: { domain: "not a domain" }, headers: { "x-forwarded-for": "a1", authorization: "Bearer tok" } }), res);
        assert.equal(res.statusCode, 400);
      }
    );
    assert.equal(dehashedCalled, false);
  } finally {
    delete process.env.DEHASHED_API_KEY;
    delete process.env.VITE_SUPABASE_URL;
    delete process.env.VITE_SUPABASE_ANON_KEY;
  }
});

// ---------------- security headers (vercel.json) ----------------
test("vercel.json ships the expected security headers", () => {
  const cfg = JSON.parse(readFileSync(join(HERE, "..", "vercel.json"), "utf8"));
  const rule = (cfg.headers || []).find((h) => h.source === "/(.*)");
  assert.ok(rule, "a catch-all headers rule must exist");
  const byKey = Object.fromEntries(rule.headers.map((h) => [h.key.toLowerCase(), h.value]));
  const csp = byKey["content-security-policy"];
  assert.ok(csp, "CSP present");
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-eval/);
  assert.match(csp, /connect-src[^;]*\*\.supabase\.co/);
  assert.equal(byKey["x-content-type-options"], "nosniff");
  assert.equal(byKey["x-frame-options"], "DENY");
  assert.match(byKey["referrer-policy"], /strict-origin/);
  assert.ok(byKey["permissions-policy"]);
});

// ---------------- no privileged key on the client ----------------
test("no service-role key is referenced in client or serverless code", () => {
  const root = join(HERE, "..");
  const files = [
    "src/lib/supabaseClient.js", "src/lib/api.js", "src/lib/auth.jsx",
    "api/stix.js", "api/enrich.js", "api/exposure.js",
  ];
  for (const f of files) {
    const txt = readFileSync(join(root, f), "utf8");
    assert.doesNotMatch(txt, /service_role|SERVICE_ROLE/i, `${f} must not reference a service-role key`);
  }
});
