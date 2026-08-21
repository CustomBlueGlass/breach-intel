#!/usr/bin/env node
/* Deterministic production/preview smoke test. Verifies a real deployment is
   actually serving the app and the /api/stix function, not just that Vercel
   reported a successful build. Checks:

     1. GET /                 -> 200            (homepage serves)
     2. GET /api/stix         -> 200            (serverless function is deployed)
     3. content-type is JSON                    (function ran, not the SPA fallback)
     4. body is a STIX bundle (type === 'bundle')
     5. bundle has an objects array

   Deployment URL resolution (Vercel + GitHub): the deployment_status event's
   `environment_url` holds the application URL; `target_url` is often the Vercel
   dashboard/inspector URL (vercel.com/...), which must never be smoke-tested.
   resolveDeploymentUrl() prefers environment_url and rejects vercel.com hosts.

   Protected Previews: Vercel Preview Deployment Protection returns 302 -> SSO
   for anonymous requests. We do not weaken protection. Instead:
     - Production deployments are public, so they are smoke-tested automatically.
     - Preview deployments are only tested when a Vercel "Protection Bypass for
       Automation" secret is provided (VERCEL_AUTOMATION_BYPASS_SECRET); it is
       sent as the x-vercel-protection-bypass header, never logged, never in the
       URL. Without it, a Preview is skipped (exit 0), not failed.

   Usage:
     node scripts/smoke-test.mjs https://your-deployment.vercel.app
     SMOKE_BASE_URL=https://... node scripts/smoke-test.mjs
     (in CI) reads the deployment_status event from GITHUB_EVENT_PATH */

import { readFileSync } from "node:fs";

// --- pure, testable helpers ------------------------------------------------

// A valid *application* URL: http(s), and NOT a Vercel dashboard/inspector host
// (vercel.com). Returns the normalized origin, or null.
export function validAppUrl(s) {
  if (!s || typeof s !== "string") return null;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  const host = u.hostname.toLowerCase();
  if (host === "vercel.com" || host.endsWith(".vercel.com")) return null;
  return u.origin;
}

// Resolve the application URL from a GitHub deployment_status payload. Prefer
// environment_url (the app URL); fall back to target_url only if it is itself a
// valid app URL (guards against the inspector URL). Returns {url, environment}.
export function resolveDeploymentUrl(deploymentStatus = {}) {
  const environment = String(deploymentStatus.environment || "").toLowerCase();
  for (const candidate of [deploymentStatus.environment_url, deploymentStatus.target_url]) {
    const url = validAppUrl(candidate);
    if (url) return { url, environment };
  }
  return { url: null, environment };
}

// Decide whether to run automatically. Manual dispatch (explicit URL) always
// runs. Production is public so it runs. Preview is protected, so it runs only
// when a bypass secret is available; otherwise it is skipped, not failed.
export function decideRun({ environment, hasBypass, manual }) {
  if (manual) return { run: true, reason: "manual dispatch" };
  const env = String(environment || "").toLowerCase();
  if (env === "production") return { run: true, reason: "production is public" };
  if (hasBypass) return { run: true, reason: "preview with bypass secret" };
  return {
    run: false,
    reason: "preview is protected and no VERCEL_AUTOMATION_BYPASS_SECRET is configured",
  };
}

// --- the smoke checks ------------------------------------------------------

export async function runSmoke(baseUrl, { fetchImpl = globalThis.fetch, bypassToken } = {}) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok: !!ok, detail: detail || "" });
    return !!ok;
  };
  // Bypass header lets the request through Vercel Preview protection. Never
  // logged: only the header value carries the secret, and we never print it.
  const headers = bypassToken ? { "x-vercel-protection-bypass": bypassToken } : {};

  if (!base) {
    check("base url provided", false, "no base URL given");
    return { ok: false, results };
  }

  // 1. homepage
  try {
    const r = await fetchImpl(`${base}/`, { redirect: "manual", headers });
    check("homepage returns 200", r.status === 200, `status ${r.status}`);
  } catch (e) {
    check("homepage returns 200", false, String(e && e.message));
  }

  // 2-5. STIX endpoint
  try {
    const r = await fetchImpl(`${base}/api/stix?limit=5`, { redirect: "manual", headers });
    check("/api/stix returns 200", r.status === 200, `status ${r.status}`);
    const ctype = r.headers && r.headers.get ? r.headers.get("content-type") || "" : "";
    check("/api/stix content-type is JSON", /application\/json/i.test(ctype), ctype);
    let body = null;
    try {
      body = await r.json();
      check("/api/stix body parses as JSON", true);
    } catch (e) {
      check("/api/stix body parses as JSON", false, String(e && e.message));
    }
    if (body) {
      check("response is a STIX bundle", body.type === "bundle", `type=${body && body.type}`);
      check("bundle contains an objects array", Array.isArray(body.objects), typeof (body && body.objects));
    }
  } catch (e) {
    check("/api/stix returns 200", false, String(e && e.message));
  }

  const ok = results.every((r) => r.ok);
  return { ok, results };
}

function report({ ok, results }, baseUrl) {
  console.log(`Smoke test: ${baseUrl}`);
  for (const r of results) {
    console.log(`  ${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  }
  console.log(ok ? "RESULT: all checks passed" : "RESULT: FAILED");
}

// Resolve the target URL + environment from CLI args, env, or the CI event.
export function resolveTarget({ argvUrl, env, readFile = readFileSync } = {}) {
  const explicit = argvUrl || env.SMOKE_BASE_URL || "";
  const manual = env.SMOKE_MANUAL === "true" || !!argvUrl;
  if (explicit) return { url: explicit.replace(/\/+$/, ""), environment: "", manual };
  if (env.GITHUB_EVENT_PATH) {
    try {
      const ev = JSON.parse(readFile(env.GITHUB_EVENT_PATH, "utf8"));
      if (ev && ev.deployment_status) {
        const r = resolveDeploymentUrl(ev.deployment_status);
        return { url: r.url, environment: r.environment, manual };
      }
    } catch {
      /* fall through to no-url */
    }
  }
  return { url: null, environment: "", manual };
}

// CLI entry (only when run directly, so the helpers stay importable for tests).
const invokedDirectly = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (invokedDirectly) {
  const { url, environment, manual } = resolveTarget({ argvUrl: process.argv[2], env: process.env });
  const hasBypass = !!process.env.VERCEL_AUTOMATION_BYPASS_SECRET;
  const decision = decideRun({ environment, hasBypass, manual });
  if (!decision.run) {
    console.log(`SKIP smoke test: ${decision.reason}`);
    process.exit(0);
  }
  if (!url) {
    console.error("FAIL smoke test: could not resolve a deployment application URL");
    process.exit(1);
  }
  const outcome = await runSmoke(url, { bypassToken: process.env.VERCEL_AUTOMATION_BYPASS_SECRET });
  report(outcome, url);
  process.exit(outcome.ok ? 0 : 1);
}
