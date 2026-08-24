import test from "node:test";
import assert from "node:assert/strict";
import handler, { validateEnquiry } from "../api/enquiry.js";

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
      if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) };
      return { status: 201, json: async () => ({}) };
    }, async () => {
      const res = mockRes();
      await handler(reqOf({ headers: { authorization: "Bearer tok", "x-forwarded-for": "a-unique-2" }, body: { plan: "gold" } }), res);
      assert.equal(res.statusCode, 400);
    });
  } finally { clearEnv(); }
});

test("enquiry: rate limit -> 429 for a hot client", async () => {
  setEnv();
  let last = mockRes();
  try {
    await withFetch(async (url) => {
      if (url.includes("/auth/v1/user")) return { ok: true, status: 200, json: async () => ({ id: "u", email: "e@e.com" }) };
      return { status: 201, json: async () => ({}) };
    }, async () => {
      for (let i = 0; i < 12; i++) {
        last = mockRes();
        await handler({ method: "POST", headers: { authorization: "Bearer tok", "x-forwarded-for": "hot-ip" }, socket: {}, body: { plan: "pro" } }, last);
      }
    });
    assert.equal(last.statusCode, 429);
  } finally { clearEnv(); }
});
