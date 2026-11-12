# Security Policy

## Reporting a vulnerability

Report privately via a GitHub security advisory on this repository, or email the
maintainer. Please include a minimal reproducer (snippet + filename) — the
engine is easy to test in isolation:

```bash
python -c "
from aegis.engine.analyzer import analyze_source
for f in analyze_source(open('repro.py').read(), 'repro.py').findings:
    print(f.rule_id, f.line, f.title)
"
```

Expect an acknowledgement within a few days. Please do not open a public issue
for unpatched vulnerabilities.

## Scope

In scope: engine false negatives on patterns a rule already claims to cover,
auth/JWT flaws in `aegis/security.py`, path-traversal or archive handling in the
upload endpoints, a way to make `repofetch` clone from a host outside the
allowlist or follow a symlink out of the clone, and anything that lets one user
read another user's scans.

Out of scope: findings the analyzer reports on *deliberately vulnerable*
material (everything under `samples/` and `tests/fixtures/`), and missing
detections for languages or rule classes not listed in `README.md`.

## Operating this tool safely

The analyzer parses untrusted text, so:

- uploads are capped (`MAX_UPLOAD_MB`, `MAX_REPO_MB`) and archives are extracted
  with an explicit zip-slip guard;
- the engine never executes, imports or evaluates the code it scans — it only
  reads it (note that this is the opposite of what `eval`-based "AI review"
  tools must do);
- repository scanning only accepts `https://` URLs on an allowlist of forges.
  If you add private repositories, expose a server-side token via
  `AEGIS_GIT_TOKEN` — never accept one from the client;
- run the dashboard behind TLS and set a real `SECRET_KEY`;
- reports redact detected secret values by design.
