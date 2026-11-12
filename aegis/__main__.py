"""CLI: scan a path, print findings, export reports, enforce a policy gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine.analyzer import ENGINE_VERSION, scan_path
from .engine.exporters import export


RED = "\033[31m"; ORANGE = "\033[38;5;208m"; YELLOW = "\033[33m"
BLUE = "\033[34m"; DIM = "\033[2m"; BOLD = "\033[1m"; GREEN = "\033[32m"; RESET = "\033[0m"
COLOR = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": BLUE, "info": DIM}


def hr(title: str = "") -> str:
    line = "-" * 72
    return f"{DIM}{line}{RESET}" if not title else f"{DIM}{title.center(72, '-')}{RESET}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="aegis",
        description="AegisReview - deterministic static security analysis.",
    )
    ap.add_argument("path", nargs="?", help="file or directory to scan")
    ap.add_argument("-f", "--format", default="text",
                    choices=["text", "json", "sarif", "markdown", "md", "html"],
                    help="output format (default: text)")
    ap.add_argument("-o", "--output", help="write report to this file instead of stdout")
    ap.add_argument("--max-critical", type=int, default=None, help="exit 1 if exceeded")
    ap.add_argument("--max-high", type=int, default=None, help="exit 1 if exceeded")
    ap.add_argument("--max-medium", type=int, default=None, help="exit 1 if exceeded")
    ap.add_argument("--min-score", type=int, default=None, help="exit 1 if score is lower")
    ap.add_argument("--include-tests", action="store_true", help="also scan test fixtures")
    ap.add_argument("--quiet", action="store_true", help="only print the summary line")
    ap.add_argument("--repo", metavar="URL",
                    help="clone and scan a remote repository (github/gitlab/bitbucket/codeberg)")
    ap.add_argument("--include-docs", action="store_true",
                    help="also scan docs/examples/vendored code")
    args = ap.parse_args(argv)

    if args.repo:
        from .repofetch import RepoError, cleanup, clone

        try:
            info = clone(args.repo)
        except RepoError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        try:
            result = scan_path(info.path, include_tests=args.include_tests,
                               include_docs=args.include_docs)
            label = info.label
        finally:
            cleanup(info)
    else:
        if not args.path:
            ap.error("a path is required (or use --repo URL)")
        target = Path(args.path)
        if not target.exists():
            print(f"error: {target} does not exist", file=sys.stderr)
            return 2
        result = scan_path(target, include_tests=args.include_tests,
                           include_docs=args.include_docs)
        label = str(target)

    if args.format != "text":
        title_name = label.rsplit("/", 1)[-1]
        content, _ = export(result, args.format, title=f"AegisReview - {title_name}")
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(content)
    else:
        if not args.quiet:
            print(hr(" AEGISREVIEW "))
            print(f"  target   {label}")
            print(f"  engine   v{ENGINE_VERSION} · {result.rules_evaluated} rules")
            print(f"  scanned  {len(result.scannable_files)} files · {result.total_lines} lines "
                  f"· {result.duration_ms} ms")
            print()
            for f in sorted(result.findings,
                            key=lambda x: (["critical", "high", "medium", "low", "info"].index(x.severity),
                                           x.file, x.line)):
                c = COLOR[f.severity]
                print(f"  {c}{f.severity.upper():8}{RESET} {BOLD}{f.title}{RESET}")
                print(f"           {DIM}{f.file}:{f.line}  {f.rule_id}  {f.cwe}{RESET}")
                print(f"           {f.code[:100]}")
                if len(f.evidence) > 1:
                    print(f"           {DIM}taint: line {f.evidence[0].line} "
                          f"({f.evidence[0].code[:60]}) -> line {f.line}{RESET}")
                print()
        c = result.counts
        bar = "  ".join(f"{COLOR[s]}{c[s]} {s}{RESET}" for s in
                        ("critical", "high", "medium", "low") if c[s])
        print(hr())
        print(f"  {BOLD}Score {result.score}/100{RESET} (grade {result.grade}) · "
              f"{result.verdict}")
        print(f"  {bar or 'no findings'}")
        print(hr())

    failed = False
    reasons = []
    c = result.counts
    if args.max_critical is not None and c["critical"] > args.max_critical:
        failed = True; reasons.append(f"{c['critical']} critical > {args.max_critical}")
    if args.max_high is not None and c["high"] > args.max_high:
        failed = True; reasons.append(f"{c['high']} high > {args.max_high}")
    if args.max_medium is not None and c["medium"] > args.max_medium:
        failed = True; reasons.append(f"{c['medium']} medium > {args.max_medium}")
    if args.min_score is not None and result.score < args.min_score:
        failed = True; reasons.append(f"score {result.score} < {args.min_score}")
    if failed:
        print(f"{RED}POLICY GATE FAILED{RESET}: " + "; ".join(reasons), file=sys.stderr)
        return 1
    if any(v is not None for v in (args.max_critical, args.max_high, args.max_medium, args.min_score)):
        print(f"{GREEN}policy gate passed{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
