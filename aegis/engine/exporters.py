"""Report exporters: SARIF 2.1.0, Markdown, self-contained HTML."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any

from .models import SEVERITIES, ScanResult
from .rules import RULES

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}
_SEV_COLOR = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}


def to_sarif(result: ScanResult, tool_uri: str = "https://github.com/Panelv4/aegisreview-ai-v2") -> dict[str, Any]:
    """SARIF 2.1.0 — uploads directly to GitHub code scanning."""
    rules_meta = []
    for rule in RULES:
        rules_meta.append(
            {
                "id": rule.id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.why},
                "help": {
                    "text": rule.fix_hint,
                    "markdown": f"**Why**\n\n{rule.why}\n\n**Fix**\n\n```\n{rule.fix_example}\n```",
                },
                "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": list(rule.tags) + ["security"],
                    "cwe": rule.cwe,
                    "owasp": rule.owasp,
                    "security-severity": SARIF_SECURITY_SEVERITY[rule.severity],
                    "precision": rule.confidence,
                },
                "helpUri": (rule.references[0] if rule.references else tool_uri),
            }
        )

    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                            "region": {
                                "startLine": max(1, f.line),
                                "startColumn": max(1, f.column),
                            },
                        },
                        "logicalLocations": [{"fullyQualifiedName": f"{f.file}:{f.line}"}],
                    }
                ],
                "partialFingerprints": {"aegis/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "snippet": f.code,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisReview",
                        "version": result.engine_version,
                        "informationUri": tool_uri,
                        "rules": rules_meta,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "properties": {
                    "score": result.score,
                    "grade": result.grade,
                    "verdict": result.verdict,
                    "counts": result.counts,
                },
            }
        ],
    }


def to_markdown(result: ScanResult, title: str = "Security Review") -> str:
    c = result.counts
    lines = [
        f"# {title}",
        "",
        f"**Score** {result.score}/100 (grade {result.grade}) · **Verdict:** {result.verdict}",
        "",
        f"`{c['critical']} critical` · `{c['high']} high` · `{c['medium']} medium` · "
        f"`{c['low']} low` · {result.total_lines} lines in {len(result.scannable_files)} files "
        f"· {result.duration_ms} ms",
        "",
    ]
    if result.findings:
        lines += ["## Findings", ""]
        for f in sorted(
            result.findings,
            key=lambda x: (SEVERITIES.index(x.severity), x.file, x.line),
        ):
            lines += [
                f"### {f.severity.upper()} · {f.title}",
                f"`{f.file}:{f.line}` · {f.rule_id} · {f.cwe} · {f.owasp}",
                "",
                "```",
                f.code,
                "```",
                "",
                f"**Why it matters** — {f.why}",
                "",
                f"**Fix** — {f.fix_hint}",
                "",
                "```diff",
                *[f"- {ln}" for ln in f.vuln_example.splitlines()],
                *[f"+ {ln}" for ln in f.fix_example.splitlines()],
                "```",
                "",
            ]
    else:
        lines += ["No findings. Nice.", ""]
    lines += [
        "---",
        f"Generated by AegisReview {result.engine_version} · "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    return "\n".join(lines)


_INLINE_CODE = re.compile(r"`([^`]{1,120})`")


def _rich(text: str) -> str:
    """Escape, then re-introduce `code` spans. Never trusts rule text as markup."""
    return _INLINE_CODE.sub(r"<code>\1</code>", html.escape(text))


def to_html(result: ScanResult, title: str = "Security Review") -> str:
    """Self-contained (no external CSS/JS) HTML report — safe to email or archive."""
    e = html.escape
    c = result.counts
    chips = "".join(
        f'<span class="chip" style="--c:{_SEV_COLOR[s]}">{c[s]} {s}</span>' for s in SEVERITIES
    )

    rows = []
    for f in sorted(result.findings, key=lambda x: (SEVERITIES.index(x.severity), x.file, x.line)):
        trace = ""
        if len(f.evidence) > 1:
            src = f.evidence[0]
            trace = (
                '<div class="trace"><span class="tag src">source</span> '
                f"<code>{e(src.code)}</code> <span class=\"arrow\">&#8594;</span> "
                f'<span class="tag sink">sink</span> line {f.line}</div>'
            )
        rows.append(
            f"""<details class="finding sev-{f.severity}">
  <summary>
    <span class="sev">{f.severity}</span>
    <span class="ftitle">{e(f.title)}</span>
    <span class="loc">{e(f.file)}:{f.line}</span>
  </summary>
  <div class="body">
    <div class="meta">{f.rule_id} · {f.cwe} · {e(f.owasp)} · confidence {f.confidence}</div>
    <pre class="code">{e(f.code)}</pre>
    {trace}
    <h4>Why it matters</h4><p>{_rich(f.why)}</p>
    <h4>Fix</h4><p>{_rich(f.fix_hint)}</p>
    <div class="diff">
      <pre class="bad">{e(f.vuln_example)}</pre>
      <pre class="good">{e(f.fix_example)}</pre>
    </div>
  </div>
</details>"""
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px; font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
         background:#0b1020; color:#e2e8f0; }}
  .wrap {{ max-width:960px; margin:0 auto; }}
  h1 {{ font-size:26px; margin:0 0 4px; letter-spacing:-.02em; }}
  .sub {{ color:#94a3b8; font-size:14px; }}
  .hero {{ display:flex; gap:24px; align-items:center; flex-wrap:wrap; margin:24px 0 8px;
           padding:20px; border:1px solid #1e293b; border-radius:14px; background:#111827; }}
  .score {{ font-size:48px; font-weight:700; line-height:1 }}
  .chip {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px;
           font-weight:600; margin:0 6px 6px 0; color:var(--c);
           border:1px solid color-mix(in srgb, var(--c) 45%, transparent);
           background:color-mix(in srgb, var(--c) 12%, transparent); }}
  .finding {{ border:1px solid #1e293b; border-radius:10px; margin:10px 0; background:#0f172a; }}
  summary {{ cursor:pointer; padding:12px 14px; display:flex; gap:12px; align-items:center; }}
  summary::-webkit-details-marker {{ display:none; }}
  .sev {{ font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.06em;
          padding:3px 8px; border-radius:6px; background:#1e293b; }}
  .sev-critical .sev {{ background:#7f1d1d; color:#fecaca; }}
  .sev-high .sev {{ background:#7c2d12; color:#fed7aa; }}
  .sev-medium .sev {{ background:#713f12; color:#fde68a; }}
  .sev-low .sev {{ background:#1e3a8a; color:#bfdbfe; }}
  .ftitle {{ flex:1; font-weight:600; }}
  .loc {{ color:#94a3b8; font-size:12px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .body {{ padding:0 14px 16px; border-top:1px solid #1e293b; }}
  .meta {{ color:#64748b; font-size:12px; margin:12px 0; font-family:ui-monospace,monospace; }}
  pre {{ margin:0; padding:12px; border-radius:8px; overflow-x:auto; font-size:13px;
         font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .code {{ background:#020617; border:1px solid #1e293b; }}
  .diff {{ display:grid; gap:8px; grid-template-columns:1fr 1fr; margin-top:8px; }}
  .bad {{ background:#2b0d0d; border:1px solid #7f1d1d; color:#fecaca; }}
  .good {{ background:#08211a; border:1px solid #065f46; color:#a7f3d0; }}
  .trace {{ margin:10px 0; font-size:13px; color:#94a3b8; }}
  .tag {{ font-size:10px; text-transform:uppercase; background:#1e293b; padding:2px 6px; border-radius:4px; }}
  .tag.sink {{ background:#7f1d1d; color:#fecaca; }}
  h4 {{ margin:16px 0 4px; font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:#94a3b8; }}
  p {{ margin:0; }}
  footer {{ margin-top:32px; color:#475569; font-size:12px; }}
  @media (max-width:640px) {{ .diff {{ grid-template-columns:1fr; }} body {{ padding:16px; }} }}
</style></head>
<body><div class="wrap">
  <h1>{e(title)}</h1>
  <div class="sub">Generated by AegisReview {result.engine_version} · {e(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</div>
  <div class="hero">
    <div><div class="score">{result.score}</div><div class="sub">score / 100 · grade {result.grade}</div></div>
    <div style="flex:1;min-width:220px">{chips}</div>
    <div class="sub">{result.verdict}<br>{len(result.scannable_files)} files · {result.total_lines} lines · {result.duration_ms} ms</div>
  </div>
  {''.join(rows) if rows else '<p>No findings.</p>'}
  <footer>AegisReview — deterministic static analysis. {result.rules_evaluated} rules evaluated.</footer>
</div></body></html>"""


def export(result: ScanResult, fmt: str, title: str = "Security Review") -> tuple[str, str]:
    """Return (content, media_type) for a format name."""
    fmt = fmt.lower()
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2), "application/sarif+json"
    if fmt == "json":
        return (
            json.dumps(
                {
                    "summary": result.summary(),
                    "findings": [f.to_dict() for f in result.findings],
                    "rule_breakdown": result.rule_breakdown(),
                },
                indent=2,
            ),
            "application/json",
        )
    if fmt == "markdown" or fmt == "md":
        return to_markdown(result, title), "text/markdown"
    return to_html(result, title), "text/html"
