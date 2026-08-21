import test from "node:test";
import assert from "node:assert/strict";

import {
  validAppUrl,
  resolveDeploymentUrl,
  decideRun,
  resolveTarget,
  runSmoke,
} from "../../scripts/smoke-test.mjs";

// ---- validAppUrl ----------------------------------------------------------
test("validAppUrl accepts app URLs and rejects dashboard/inspector + junk", () => {
  assert.equal(validAppUrl("https://proj-abc123.vercel.app"), "https://proj-abc123.vercel.app");
  assert.equal(validAppUrl("https://proj-abc123.vercel.app/"), "https://proj-abc123.vercel.app");
  // Vercel dashboard/inspector URLs must never be tested.
  assert.equal(validAppUrl("https://vercel.com/team/project/DEPLOY_ID"), null);
  assert.equal(validAppUrl("https://vercel.com/team/project/xyz/inspect"), null);
  assert.equal(validAppUrl(""), null);
  assert.equal(validAppUrl(null), null);
  assert.equal(validAppUrl("not a url"), null);
  assert.equal(validAppUrl("ftp://example.com"), null);
});

// ---- resolveDeploymentUrl -------------------------------------------------
test("resolveDeploymentUrl prefers environment_url over inspector target_url", () => {
  const r = resolveDeploymentUrl({
    environment: "Preview",
    environment_url: "https://proj-git-branch.vercel.app",
    target_url: "https://vercel.com/team/proj/DEPLOY_ID", // inspector
  });
  assert.equal(r.url, "https://proj-git-branch.vercel.app");
  assert.equal(r.environment, "preview");
});

test("resolveDeploymentUrl returns null when only an inspector URL is present", () => {
  const r = resolveDeploymentUrl({
    environment: "Preview",
    target_url: "https://vercel.com/team/proj/DEPLOY_ID",
  });
  assert.equal(r.url, null);
});

test("resolveDeploymentUrl falls back to a valid target_url when environment_url missing", () => {
  const r = resolveDeploymentUrl({
    environment: "Production",
    target_url: "https://breach-intel.vercel.app",
  });
  assert.equal(r.url, "https://breach-intel.vercel.app");
  assert.equal(r.environment, "production");
});

test("resolveDeploymentUrl handles an empty payload", () => {
  assert.deepEqual(resolveDeploymentUrl({}), { url: null, environment: "" });
  assert.deepEqual(resolveDeploymentUrl(), { url: null, environment: "" });
});

// ---- decideRun ------------------------------------------------------------
test("decideRun: manual always runs", () => {
  assert.equal(decideRun({ environment: "preview", hasBypass: false, manual: true }).run, true);
});

test("decideRun: production runs unauthenticated (public)", () => {
  assert.equal(decideRun({ environment: "production", hasBypass: false, manual: false }).run, true);
});

test("decideRun: protected preview runs only with a bypass secret", () => {
  assert.equal(decideRun({ environment: "preview", hasBypass: true, manual: false }).run, true);
  assert.equal(decideRun({ environment: "preview", hasBypass: false, manual: false }).run, false);
  // unknown environment is treated as protected
  assert.equal(decideRun({ environment: "", hasBypass: false, manual: false }).run, false);
});

// ---- resolveTarget --------------------------------------------------------
test("resolveTarget: explicit argv URL is manual", () => {
  const t = resolveTarget({ argvUrl: "https://x.vercel.app/", env: {} });
  assert.equal(t.url, "https://x.vercel.app");
  assert.equal(t.manual, true);
});

test("resolveTarget: reads deployment_status from the CI event file", () => {
  const fakeEvent = {
    deployment_status: {
      environment: "Preview",
      environment_url: "https://proj-git-branch.vercel.app",
      target_url: "https://vercel.com/team/proj/DEPLOY_ID",
    },
  };
  const t = resolveTarget({
    argvUrl: undefined,
    env: { GITHUB_EVENT_PATH: "/tmp/event.json", SMOKE_MANUAL: "false" },
    readFile: () => JSON.stringify(fakeEvent),
  });
  assert.equal(t.url, "https://proj-git-branch.vercel.app");
  assert.equal(t.environment, "preview");
  assert.equal(t.manual, false);
});

test("resolveTarget: no url when event has only an inspector target_url", () => {
  const t = resolveTarget({
    env: { GITHUB_EVENT_PATH: "/tmp/event.json" },
    readFile: () => JSON.stringify({ deployment_status: { target_url: "https://vercel.com/a/b/c" } }),
  });
  assert.equal(t.url, null);
});

// ---- runSmoke sends the bypass header without leaking it -------------------
test("runSmoke sends x-vercel-protection-bypass header when a token is given", async () => {
  const seen = [];
  const fetchImpl = async (url, opts) => {
    seen.push({ url, headers: opts.headers });
    if (url.includes("/api/stix")) {
      return {
        status: 200,
        headers: { get: () => "application/json" },
        json: async () => ({ type: "bundle", id: "bundle--x", objects: [] }),
      };
    }
    return { status: 200, headers: { get: () => "text/html" }, json: async () => ({}) };
  };
  const out = await runSmoke("https://proj.vercel.app", { fetchImpl, bypassToken: "SECRET123" });
  assert.equal(out.ok, true);
  for (const s of seen) {
    assert.equal(s.headers["x-vercel-protection-bypass"], "SECRET123");
  }
});

test("runSmoke omits the bypass header when no token is given", async () => {
  const seen = [];
  const fetchImpl = async (url, opts) => {
    seen.push(opts.headers || {});
    if (url.includes("/api/stix")) {
      return { status: 200, headers: { get: () => "application/json" }, json: async () => ({ type: "bundle", objects: [] }) };
    }
    return { status: 200, headers: { get: () => "text/html" }, json: async () => ({}) };
  };
  await runSmoke("https://proj.vercel.app", { fetchImpl });
  for (const h of seen) assert.equal("x-vercel-protection-bypass" in h, false);
});

test("runSmoke fails when /api/stix is a 302 (protected preview, no bypass)", async () => {
  const fetchImpl = async () => ({ status: 302, headers: { get: () => "text/html" }, json: async () => ({}) });
  const out = await runSmoke("https://proj.vercel.app", { fetchImpl });
  assert.equal(out.ok, false);
});
