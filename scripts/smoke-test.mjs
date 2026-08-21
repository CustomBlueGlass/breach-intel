#!/usr/bin/env node
/* Deterministic production/preview smoke test. Verifies the deployed app is
   actually serving, not just that Vercel reported a successful build. Checks:

     1. GET /                 -> 200            (homepage serves)
     2. GET /api/stix         -> 200            (serverless function is deployed)
     3. content-type is JSON                    (function ran, not the SPA fallback)
     4. body is a STIX bundle (type === 'bundle')
     5. bundle has an objects array

   Fails loudly (non-zero exit) the moment any assumption stops holding, which
   is exactly the /api/stix 404 regression this guards against. No secrets: the
   endpoints are public and read-only.

   Usage:
     node scripts/smoke-test.mjs https://your-deployment.vercel.app
     SMOKE_BASE_URL=https://... node scripts/smoke-test.mjs */

export async function runSmoke(baseUrl, fetchImpl = globalThis.fetch) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok: !!ok, detail: detail || "" });
    return !!ok;
  };

  if (!base) {
    check("base url provided", false, "no base URL given");
    return { ok: false, results };
  }

  // 1. homepage
  try {
    const r = await fetchImpl(`${base}/`, { redirect: "follow" });
    check("homepage returns 200", r.status === 200, `status ${r.status}`);
  } catch (e) {
    check("homepage returns 200", false, String(e && e.message));
  }

  // 2-5. STIX endpoint
  try {
    const r = await fetchImpl(`${base}/api/stix?limit=5`, { redirect: "follow" });
    const okStatus = check("/api/stix returns 200", r.status === 200, `status ${r.status}`);
    const ctype = r.headers.get ? r.headers.get("content-type") || "" : "";
    const okJson = check("/api/stix content-type is JSON", /application\/json/i.test(ctype), ctype);
    let body = null;
    try {
      body = await r.json();
    } catch (e) {
      check("/api/stix body parses as JSON", false, String(e && e.message));
    }
    if (body) {
      check("/api/stix body parses as JSON", true);
      check("response is a STIX bundle", body.type === "bundle", `type=${body && body.type}`);
      check("bundle contains an objects array", Array.isArray(body.objects), typeof (body && body.objects));
    }
    void okStatus; void okJson;
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

// CLI entry (only when run directly, so runSmoke stays importable for tests).
const invokedDirectly =
  process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (invokedDirectly) {
  const baseUrl = process.argv[2] || process.env.SMOKE_BASE_URL || "";
  const outcome = await runSmoke(baseUrl);
  report(outcome, baseUrl || "(none)");
  process.exit(outcome.ok ? 0 : 1);
}
