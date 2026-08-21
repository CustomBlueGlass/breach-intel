# Dependency and secret-scanning policy

Enforced by the `security` job in `.github/workflows/ci.yml`. Every check fails the
build deterministically on a finding above threshold; it does not merely warn.

## Thresholds

| Check | Tool | Scope | Fails on |
| --- | --- | --- | --- |
| Frontend runtime deps | `npm audit --omit=dev --audit-level=high` | `frontend/` production dependencies | high or critical advisories |
| Python deps | `pip-audit -r backend/requirements.txt` | collectors + maintenance | any known vulnerability |
| Secret scan | `gitleaks detect --redact --exit-code=1` | working tree + full git history | any detected secret (value redacted in logs) |

Dev-only npm advisories (build tooling such as Vite) are out of the deployed attack
surface and are not gated; runtime dependencies are.

## Remediations applied in this work package

- `starlette` 1.0.1 -> 1.3.1 (clears PYSEC-2026-248/249 and PYSEC-2026-2280/2281).
- `lxml` 5.3.0 -> 6.1.0 (clears PYSEC-2026-87). lxml parses external feeds in the
  collectors, so this is a real fix, not just a lint pass.

Both were verified to resolve and import together with `fastapi==0.133.1`.

## Accepted exceptions

**None.** `npm audit` (runtime) and `pip-audit` both report zero findings after the
remediations above.

If an exception is ever unavoidable, record it here (id, package, justification,
tracked fix) and pass it to `pip-audit` via `--ignore-vuln <ID>` so the gate stays
green only for the specific, assessed item and still fails on anything new.
