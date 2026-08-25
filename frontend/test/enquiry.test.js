import test from "node:test";
import assert from "node:assert/strict";
import handler, { validateEnquiry, clientIp, normalizeIp } from "../api/enquiry.js";

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
  method: "POST", headers: { "x-forwarded-for": `enq-${Math.random()}` },
  socket: { remoteAddress: "203.0.113.5" }, body: {}, ...over,
});
function withFetch(impl, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve().then(fn).finally(() => { globalThis.fetch = orig; });
}
function setEnv() {
  process.env.VITE_SUPABASE_URL = "https://x.supabase.co";
  process.env.VITE_SUPABASE_ANON_KEY = "anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "service-secret";
}
function clearEnv() {
  delete process.env.VITE_SUPABASE_URL;
  delete process.env.VITE_SUPABASE_ANON_KEY;
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
}

// ---- validation ----
test("validateEnquiry: rejects bad plan, enforces lengths, normalises source", () => {
  assert.equal(validateEnquiry({ plan: "gold" }).ok, false);
  assert.equal(validateEnquiry({ plan: "pro" }).ok, true);
  const long = validateEnquiry({ plan: "pro", organisation: "x".repeat(201) });
  assert.equal(long.ok, false);
  const msg = validateEnquiry({ plan: "business", message: "y".repeat(2001) });
  assert.equal(msg.ok, false);
  assert.equal(validateEnquiry({ plan: "enterprise", source: "evil" }).value.source, "other");
  assert.equal(validateEnquiry({ plan: "pro", source: "dashboard" }).value.source, "dashboard");
});

// ---- method + config gating ----
test("enquiry: non-POST -> 405; OPTIONS -> 204", async () => {
  setEnv();
  try {
    let res = mockRes(); await handler(reqOf({ method: "GET" }), res); assert.equal(res.statusCode, 405);
    res = mockRes(); await handler(reqOf({ method: "OPTIONS" }), res); assert.equal(res.statusCode, 204);
  } finally { clearEnv(); }
});

test("enquiry: unconfigured host -> 503 configured:false", async () => {
  clearEnv();
  const res = mockRes();
  await handler(reqOf({ body: { plan: "pro" } }), res);
  assert.equal(res.statusCode, 503);
  assert.equal(res.body.configured, false);
});

test("enquiry: no session -> 401 and no network call", async () => {
  setEnv();
  let called = false;
  try {
    await withFetch(async () => { called = true; return { ok: true, json: async () => ({}) }; }, async () => {
      const res = mockRes();
      await handler(reqOf({ body: { plan: "pro" } }), res); // no Authorization header
      assert.equal(res.statusCode, 401);
      assert.equal(res.body.authRequired, true);
    });
    assert.equal(called, false, "must not call upstream without a session");
  } finally { clearEnv(); }
});

test("enquiry: valid session + body -> 201; email/user_id come from session, not client", async () => {
  setEnv();
  let insertBody = null;
  let insertAuth = null;
  try {
    await withFetch(async (url, opts) => {
      if (url.includes("/rest/v1/rpc/rl_hit")) return { ok: true, status: 200, json: async () => true };
      if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "user-123", email: "real@corp.com" }) };
      if (url.includes("/rest/v1/plan_enquiries")) {
        insertBody = JSON.parse(opts.body);
        insertAuth = opts.headers.Authorization;
        return { status: 201, json: async () => ({}) };
      }
      return { ok: true, status: 200, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({
        headers: { authorization: "Bearer tok", "x-forwarded-for": "a-unique-1" },
        body: { plan: "business", organisation: "Acme", role_use_case: "SOC lead", message: "hi", email: "spoof@evil.com", user_id: "attacker" },
      }), res);
      assert.equal(res.statusCode, 201);
      assert.equal(res.body.ok, true);
    });
    assert.equal(insertBody.email, "real@corp.com", "email must come from verified session");
    assert.equal(insertBody.user_id, "user-123", "user_id must come from verified session");
    assert.equal(insertBody.plan, "business");
    assert.match(insertAuth, /service-secret/, "insert must use the service-role key");
  } finally { clearEnv(); }
});

test("enquiry: invalid plan with a valid session -> 400", async () => {
  setEnv();
  try {
    await withFetch(async (url) => {
      if (url.includes("/rest/v1/rpc/rl_hit")) return { ok: true, status: 200, json: async () => true };
      if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) };
      return { status: 201, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({ headers: { authorization: "Bearer tok", "x-forwarded-for": "a-unique-2" }, body: { plan: "gold" } }), res);
      assert.equal(res.statusCode, 400);
    });
  } finally { clearEnv(); }
});

test("enquiry: durable limiter (rl_hit) over budget -> 429, no insert", async () => {
  // The limiter is durable, not in-memory: when the shared Postgres counter
  // reports over budget, a single request is rejected with 429 and never
  // reaches the auth or insert calls.
  setEnv();
  let authCalled = false, insertCalled = false;
  try {
    await withFetch(async (url) => {
      if (url.includes("/rest/v1/rpc/rl_hit")) return { ok: true, status: 200, json: async () => false };
      if (url.includes("/auth/v1/user")) { authCalled = true; return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) }; }
      if (url.includes("/rest/v1/plan_enquiries")) { insertCalled = true; return { status: 201, json: async () => ({}) }; }
      return { ok: true, status: 200, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({ headers: { authorization: "Bearer tok", "x-forwarded-for": "hot-ip" }, body: { plan: "pro" } }), res);
      assert.equal(res.statusCode, 429);
      assert.equal(res.headers["retry-after"], "60");
    });
    assert.equal(authCalled, false, "over-budget IP must be blocked before the auth call");
    assert.equal(insertCalled, false, "over-budget request must not insert");
  } finally { clearEnv(); }
});

test("enquiry: rl_hit transport failure fails CLOSED (503, no auth, no insert)", async () => {
  // A limiter that fails open is not a limiter. On a transport error the request
  // is rejected with a generic 503 before authentication or the insert.
  setEnv();
  let authCalled = false, insertCalled = false;
  try {
    await withFetch(async (url) => {
      if (url.includes("/rest/v1/rpc/rl_hit")) throw new Error("db unreachable");
      if (url.includes("/auth/v1/user")) { authCalled = true; return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) }; }
      if (url.includes("/rest/v1/plan_enquiries")) { insertCalled = true; return { status: 201, json: async () => ({}) }; }
      return { ok: true, status: 200, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({ headers: { authorization: "Bearer tok", "x-forwarded-for": "open-ip" }, body: { plan: "pro" } }), res);
      assert.equal(res.statusCode, 503);
      assert.equal(/service|unavailable/i.test(res.body.error), true);
      assert.equal(res.body.configured, undefined, "must not leak configuration/database detail");
    });
    assert.equal(authCalled, false, "limiter error must block before the auth call");
    assert.equal(insertCalled, false, "limiter error must block before the insert");
  } finally { clearEnv(); }
});

test("enquiry: rl_hit non-2xx fails CLOSED (503, no insert)", async () => {
  setEnv();
  let insertCalled = false;
  try {
    await withFetch(async (url) => {
      if (url.includes("/rest/v1/rpc/rl_hit")) return { ok: false, status: 500, json: async () => ({ message: "boom" }) };
      if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) };
      if (url.includes("/rest/v1/plan_enquiries")) { insertCalled = true; return { status: 201, json: async () => ({}) }; }
      return { ok: true, status: 200, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({ headers: { authorization: "Bearer tok", "x-forwarded-for": "err-ip" }, body: { plan: "pro" } }), res);
      assert.equal(res.statusCode, 503);
    });
    assert.equal(insertCalled, false);
  } finally { clearEnv(); }
});

test("enquiry: rl_hit malformed (non-boolean) body fails CLOSED (503, no insert)", async () => {
  setEnv();
  let insertCalled = false;
  try {
    await withFetch(async (url) => {
      if (url.includes("/rest/v1/rpc/rl_hit")) return { ok: true, status: 200, json: async () => ({ unexpected: "shape" }) };
      if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) };
      if (url.includes("/rest/v1/plan_enquiries")) { insertCalled = true; return { status: 201, json: async () => ({}) }; }
      return { ok: true, status: 200, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({ headers: { authorization: "Bearer tok", "x-forwarded-for": "mal-ip" }, body: { plan: "pro" } }), res);
      assert.equal(res.statusCode, 503);
    });
    assert.equal(insertCalled, false, "a non-boolean limiter response must never reach the insert");
  } finally { clearEnv(); }
});

// ---- client IP extraction (Vercel-aware, anti-spoof) ----
test("clientIp: trusts the platform header, ignores a forged X-Forwarded-For", () => {
  const forged = { "x-forwarded-for": "1.2.3.4", "x-vercel-forwarded-for": "203.0.113.9" };
  assert.equal(clientIp({ headers: forged }), "203.0.113.9");
  // Forging only X-Forwarded-For must not change the derived IP once the trusted
  // header is fixed, so an attacker cannot split their bucket to evade the limit.
  const a = clientIp({ headers: { "x-vercel-forwarded-for": "203.0.113.9", "x-forwarded-for": "9.9.9.9" } });
  const b = clientIp({ headers: { "x-vercel-forwarded-for": "203.0.113.9", "x-forwarded-for": "8.8.8.8" } });
  assert.equal(a, b);
  // x-real-ip is the next most trusted platform header.
  assert.equal(clientIp({ headers: { "x-real-ip": "198.51.100.7", "x-forwarded-for": "1.1.1.1" } }), "198.51.100.7");
});

test("clientIp: with only X-Forwarded-For, uses the last hop not the client-forged first", () => {
  // chain is client, proxy1, proxy2 (nearest trusted proxy last)
  assert.equal(clientIp({ headers: { "x-forwarded-for": "1.2.3.4, 70.0.0.1, 100.64.0.5" } }), "100.64.0.5");
});

test("normalizeIp: strips ports/zones, handles IPv4 and IPv6", () => {
  assert.equal(normalizeIp("203.0.113.5:56789"), "203.0.113.5");
  assert.equal(normalizeIp("[2001:db8::1]:443"), "2001:db8::1");
  assert.equal(normalizeIp("2001:DB8::AB"), "2001:db8::ab");        // bare v6, lower-cased
  assert.equal(normalizeIp("fe80::1%eth0"), "fe80::1");             // zone id dropped
  assert.equal(normalizeIp("  198.51.100.7  "), "198.51.100.7");
  assert.equal(normalizeIp(""), "");
});
