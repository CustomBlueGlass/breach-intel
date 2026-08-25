import test from "node:test";
import assert from "node:assert/strict";
import { sanitizeProps, track, setAnalyticsSink, EVENTS, doNotTrack } from "../src/lib/analytics.js";

test("sanitizeProps keeps only the non-sensitive allowlist", () => {
  const out = sanitizeProps({
    plan: "pro", source: "pricing_page", tier: "x", cadence: "monthly",
    email: "a@b.com", message: "secret text", organisation: "Acme", user_id: "abc",
  });
  assert.deepEqual(Object.keys(out).sort(), ["cadence", "plan", "source", "tier"]);
  assert.equal(out.email, undefined);
  assert.equal(out.message, undefined);
  assert.equal(out.organisation, undefined);
});

test("sanitizeProps drops non-primitive values and truncates strings", () => {
  const out = sanitizeProps({ plan: { nested: true }, source: "x".repeat(100) });
  assert.equal(out.plan, undefined);
  assert.ok(out.source.length <= 40);
});

test("track forwards only sanitised props to the sink", () => {
  let seen = null;
  setAnalyticsSink((p) => { seen = p; });
  try {
    track(EVENTS.WAITLIST_SUBMITTED, { plan: "pro", source: "pricing_page", email: "leak@x.com" });
    assert.equal(seen.event, "waitlist_submitted");
    assert.deepEqual(seen.props, { plan: "pro", source: "pricing_page" });
    assert.equal("email" in seen.props, false);
  } finally { setAnalyticsSink(null); }
});

test("track respects Do Not Track", () => {
  const had = "window" in globalThis;
  const saved = globalThis.window;
  globalThis.window = { doNotTrack: "1" };
  let called = false;
  setAnalyticsSink(() => { called = true; });
  try {
    assert.equal(doNotTrack(), true);
    assert.equal(track(EVENTS.PRICING_VIEWED, { plan: "pro" }), false);
    assert.equal(called, false);
  } finally {
    setAnalyticsSink(null);
    if (had) globalThis.window = saved; else delete globalThis.window;
  }
});

test("all documented event names exist", () => {
  for (const k of ["PRICING_VIEWED", "PLAN_SELECTED", "WAITLIST_SUBMITTED", "BUSINESS_ENQUIRY_SUBMITTED", "UPGRADE_PROMPT_SHOWN", "UPGRADE_PROMPT_SELECTED"]) {
    assert.equal(typeof EVENTS[k], "string");
  }
});
