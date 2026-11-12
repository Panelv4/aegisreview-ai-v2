"""
Aegis static analysis engine.

Pipeline
--------
1. mask      -- replace comments/strings with same-width blanks so patterns can't
                fire on prose or on the contents of an unrelated literal.
2. scan      -- per file, per rule, run the declarative patterns over masked lines.
3. taint     -- for rules that declare sources & sinks, build a data-flow trace so
                the finding shows *why* the value is untrusted.
4. entropy   -- language-agnostic sweep for high-entropy secret literals.
5. score     -- weighted, damped 0-100 score + grade + release verdict.

Everything is deterministic and offline: no network, no LLM, no API key.
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path

from .languages import (
    MAX_FILE_BYTES,
    SKIP_DIRS,
    SUPPORTED,
    detect_language,
    get_spec,
    is_binary_name,
    is_sample_path,
    is_test_path,
)
from .models import Evidence, FileReport, Finding, ScanResult, fingerprint
from .sanitizers import NON_SHIPPED_DIRS, is_sanitized
from .rules import (
    MANIFEST_NAMES,
    MANIFEST_ONLY_RULES,
    RULE_BY_ID,
    RULES,
    TEST_RELAXED_RULES,
)

ENGINE_VERSION = "2.0.0"

# A rule only applies to the languages it declares...
_RULE_CACHE: list[tuple] = []


def _rules_for(language: str) -> list:
    if not _RULE_CACHE:
        for rule in RULES:
            compiled = [(p, p.compiled()) for p in rule.patterns]
            taint = [
                (tp, re.compile(tp.source), re.compile(tp.sink)) for tp in rule.taint
            ]
            _RULE_CACHE.append((rule, compiled, taint))
    return [r for r in _RULE_CACHE if language in r[0].languages or "any" in r[0].languages]


# ---------------------------------------------------------------------------
# 1. Masking
# ---------------------------------------------------------------------------

def mask_source(text: str, language: str) -> tuple[list[str], list[str]]:
    """Return (masked_lines, raw_lines).

    Masked lines keep the exact character positions of the originals but have
    the *contents* of comments and string literals blanked out. Two reasons:

    1. accuracy -- a rule must never fire on prose ("never call eval()") or on a
       string that merely mentions a dangerous call;
    2. column fidelity -- the mask is width preserving, so reported columns and
       snippets still line up with the real source.

    Multi-line constructs (Python triple-quoted strings, JS template literals,
    block comments) are tracked across lines; otherwise a docstring would leak
    its contents straight back into the scan.
    """
    spec = get_spec(language)
    lines = text.splitlines()
    masked: list[str] = []

    in_block_comment = False
    block_end = ""
    in_string = False
    string_delim = ""

    for raw in lines:
        out = list(raw)
        n = len(raw)
        i = 0

        # --- continuation of a multi-line string -------------------------
        if in_string:
            end = raw.find(string_delim)
            while end > 0 and raw[end - 1] == "\\":
                end = raw.find(string_delim, end + 1)
            if end == -1:
                masked.append(" " * n)
                continue
            for j in range(0, end + len(string_delim)):
                out[j] = " "
            i = end + len(string_delim)
            in_string = False

        # --- continuation of a block comment -----------------------------
        if in_block_comment:
            end = raw.find(block_end)
            if end == -1:
                masked.append(" " * n)
                continue
            for j in range(0, end + len(block_end)):
                out[j] = " "
            i = max(i, end + len(block_end))
            in_block_comment = False

        while i < n:
            # block comment start
            if spec.block_comment and raw.startswith(spec.block_comment[0], i):
                block_end = spec.block_comment[1]
                end = raw.find(block_end, i + len(block_end))
                if end == -1:
                    for j in range(i, n):
                        out[j] = " "
                    in_block_comment = True
                    i = n
                else:
                    for j in range(i, end + len(block_end)):
                        out[j] = " "
                    i = end + len(block_end)
                continue

            # line comment
            if any(raw.startswith(lc, i) for lc in spec.line_comments):
                for j in range(i, n):
                    out[j] = " "
                i = n
                continue

            # string literal -- longest delimiter first so a triple quote wins
            matched = False
            for delim in sorted(spec.string_delims, key=len, reverse=True):
                if not raw.startswith(delim, i):
                    continue
                search_from = i + len(delim)
                end = raw.find(delim, search_from)
                while end > 0 and raw[end - 1] == "\\":
                    end = raw.find(delim, end + 1)
                if end == -1:
                    for j in range(search_from, n):
                        out[j] = " "
                    # only delimiters that can legally span lines stay open
                    if delim in ('"""', "'''", '`'):
                        in_string = True
                        string_delim = delim
                    i = n
                else:
                    for j in range(search_from, end):
                        out[j] = " "
                    i = end + len(delim)
                matched = True
                break
            if matched:
                continue
            i += 1

        masked.append("".join(out))

    return masked, lines


# ---------------------------------------------------------------------------
# 2. Entropy sweep
# ---------------------------------------------------------------------------

_SECRET_ASSIGN = re.compile(
    r"""\b[a-z_][\w.]*(?:key|secret|token|password|passwd|pass|pwd|credential|signature|salt)
    \b\s*[:=]\s*
    ["']([^"'\s]{12,120})["']""",
    re.IGNORECASE | re.VERBOSE,
)

# Things that look random but are not secrets
# Vendor prefixes that make a string a credential on sight, entropy aside
_KNOWN_PREFIX = re.compile(
    r"^(?:AKIA|ASIA|AIza|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[baprs]-|sk-|sk_live_"
    r"|sk_test_|pk_live_|rk_live_|SG\.|ya29\.|glpat-|shpat_|npm_|pypi-|doo_v1_|hf_)"
)

# Values that are statistically random but provably not credentials
_NOT_A_SECRET = (
    re.compile(r"^(?:application|text|image|audio|video|multipart)/", re.I),
    re.compile(r"^https?://|^www\."),
    re.compile(r"^[0-9]+$"),
    re.compile(r"^(?:0123456789|1234567890|abcdefghijkl|qwerty|aaaa|0000)", re.I),
    re.compile(r"^[a-z]+(?:[-_.][a-z]+)+$"),          # slug / config-ish name
    re.compile(r"^(?:Bearer|Basic|Token)\s", re.I),
    re.compile(r"^(?:null|none|true|false|undefined)$", re.I),
    # printf/format constants are not credentials
    re.compile(r"%[sdifr]|\{[^}]*\}"),
    # SCREAMING_CASE format keys / labels
    re.compile(r"^[A-Z0-9_]{12,}$"),
)


def _looks_like_placeholder(value: str) -> bool:
    return any(rx.search(value) for rx in _NOT_A_SECRET)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def entropy_secret_scan(raw_lines: list[str], path: str) -> list[tuple[int, str, float]]:
    """Find high-entropy values assigned to secret-looking names."""
    hits: list[tuple[int, str, float]] = []
    for idx, line in enumerate(raw_lines, start=1):
        if _DOC_LINE.match(line):
            continue
        if not _SECRET_ASSIGN.search(line):
            continue
        for m in _SECRET_ASSIGN.finditer(line):
            val = m.group(1)
            if _looks_like_placeholder(val):
                continue
            ent = shannon_entropy(val)
            strong_prefix = bool(_KNOWN_PREFIX.match(val))
            # tuned: random base62 of length n scores ~ log2(n)*... ; 3.4 catches
            # most real keys while ignoring slugs like "my-long-config-name"
            if ent >= 3.4 and len(val) >= 16 or strong_prefix and len(val) >= 16:
                hits.append((idx, val, round(ent, 2)))
    return hits


# ---------------------------------------------------------------------------
# 3. Core scan
# ---------------------------------------------------------------------------

# Lines that are data about vulnerabilities rather than production code
# (rule catalogs, test tables, documentation snippets).
_DOC_LINE = re.compile(
    r"^\s*(?:vuln_example|fix_example|fix_hint|regex|pattern|source|sink|why|message|"
    r"title|cwe|owasp|description)\s*=",
    re.IGNORECASE,
)

# `from x import eval`, `def eval(self, code)`, `@after_request` are declarations,
# not invocations. Flagging them is how a scanner reports a library's own API.
_DECLARATION = re.compile(r"^\s*(?:from\s+\S+\s+import|import\s|def\s|class\s|@)", re.IGNORECASE)

_SUPPRESS = re.compile(
    r"aegis:\s*ignore(?:-file)?(?:\s*[=:]\s*|\s+)([A-Z0-9,\-\s]+)?", re.IGNORECASE
)
_SUPPRESS_ANY = re.compile(r"aegis:\s*ignore(?:-file)?", re.IGNORECASE)


def _suppressions(raw_lines: list[str]) -> dict[int, set[str] | None]:
    """Map line -> set of rule ids (or None meaning "all") suppressed on that line.

    Inline:   # aegis:ignore AEGIS-SQLI-001, AEGIS-XSS-001
              # aegis:ignore            (suppresses everything on that line)
    File-wide: # aegis:ignore-file       anywhere near the top
    """
    out: dict[int, set[str] | None] = {}
    for idx, line in enumerate(raw_lines, start=1):
        if "aegis:" not in line.lower():
            continue
        if re.search(r"aegis:\s*ignore-file", line, re.IGNORECASE):
            out[0] = None
            continue
        if not _SUPPRESS_ANY.search(line):
            continue
        m = _SUPPRESS.search(line)
        if not m:
            out[idx] = None          # bare "aegis:ignore" suppresses the whole line
            continue
        ids = m.group(1)
        if ids:
            out[idx] = {i.strip().upper() for i in re.split(r"[,\s]+", ids.strip()) if i.strip()}
        else:
            out[idx] = None
    return out


def _is_suppressed(sup: dict[int, set[str] | None], line: int, rule_id: str) -> bool:
    if 0 in sup:                      # file-wide
        return True
    s = sup.get(line)
    if s is None and line in sup:
        return True
    return bool(s and rule_id in s)


_INTERP = re.compile(r"\$\{([^{}]*)\}")


# Values a browser hands to the page: the actual sources of DOM XSS.
_DOM_SOURCE = re.compile(
    r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|cookie)"
    r"|window\.name|event\.target\.value|\.value\b|URLSearchParams|getParameter"
    r"|req\.(?:query|params|body)|request\.(?:args|form|json)|\bparams\b|\broute\.params\b"
    r"|\bsearchParams\b)",
    re.IGNORECASE,
)
# Names that conventionally hold text originating from a user or the network.
# Names that strongly imply "text a user wrote or a server returned". Deliberately
# excludes generic identifiers (`data`, `value`, `name`, `path`, `id`, `result`) that
# are far more often trusted local state than attacker input.
_UNTRUSTED_NAME = re.compile(
    r"(?:^|[_.])(?:userinput|user_input|usertext|user_text|usermsg|input|rawinput|raw_input"
    r"|comment|message|msg|body|payload|bio|description|content|html|raw|title|text"
    r"|resp|response|errmsg|err_msg|errortext|flash)(?:$|[_.\d]|[A-Z])|"
    r"^[a-z]+(?:Input|Text|Msg|Message|Html|HTML|Body|Payload|Param|Arg)s?$",
    re.IGNORECASE,
)
# `el.innerHTML = someVariable;` with no escaping wrapper at all
_BARE_SINK = re.compile(
    r"\.(?:innerHTML|outerHTML)\s*\+?=\s*([A-Za-z_$][\w$.\[\]]*)\s*;?\s*$"
)


def _guard_escaped_template(raw_line: str) -> bool:
    """True => suppress.

    A DOM HTML sink is only reported when we can name where the untrusted text
    comes from: either the classic ``el.innerHTML = someVariable``, or a
    template interpolation that reads a DOM/HTTP source. Templates built from
    internal calls are assumed to render through escaping helpers -- flagging
    every ``el.innerHTML = `<div>${UI.esc(x)}</div>``` would bury real bugs.
    """
    bare = _BARE_SINK.search(raw_line)
    if bare:
        # only when the assigned identifier looks like it carries user text
        return not (_UNTRUSTED_NAME.search(bare.group(1)) or _DOM_SOURCE.search(bare.group(1)))
    exprs = _INTERP.findall(raw_line)
    if not exprs:
        return True          # a fixed string of markup cannot carry attacker input
    for expr in exprs:
        e = expr.strip()
        if _DOM_SOURCE.search(e):
            return False                      # provably untrusted source
        if re.search(r"(?:esc|escape|sanitize|encode|String)\s*\(", e):
            continue                          # explicitly escaped
        if "(" in e:
            continue                          # call result, assumed rendered safely
        if re.fullmatch(r"[\w$][\w$.\[\]'\" ]*", e):
            # bare variable: trust it only when its name suggests user text
            return not (_UNTRUSTED_NAME.search(e) or _DOM_SOURCE.search(e))
    return True


GUARDS = {
    "escaped_template": _guard_escaped_template,
}


def _logical_line(raw_lines: list[str], idx: int, max_lines: int = 120) -> str:
    """Join a statement that continues over several lines.

    Template-literal HTML sinks are almost always multi-line, so judging only
    the line that contains `innerHTML =` would always see an empty `${...}`
    set and mis-classify the file. Balance backticks/parens forwards.
    """
    line = raw_lines[idx]
    if line.count("`") % 2 == 0 and line.count("(") == line.count(")"):
        return line
    parts = [line]
    backticks = line.count("`")
    depth = line.count("(") - line.count(")")
    for j in range(idx + 1, min(len(raw_lines), idx + max_lines)):
        nxt = raw_lines[j]
        parts.append(nxt)
        backticks += nxt.count("`")
        depth += nxt.count("(") - nxt.count(")")
        if backticks % 2 == 0 and depth <= 0:
            break
    return "\n".join(parts)


def _snippet(raw: str, limit: int = 200) -> str:
    return raw.strip()[:limit]


_ASSIGN = re.compile(r"^\s*(?:let |const |var |@|\$)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.*)$")


def _find_taint_evidence(
    masked: list[str], raw_lines: list[str], rule_taint: list, hit_line: int, max_back: int = 25
) -> list[Evidence]:
    """Find the assignment that introduced untrusted data into this sink.

    Deliberately conservative: the source line must (a) be within a plausible
    window, (b) match a taint *source*, and (c) assign to an identifier that
    actually appears on the sink line. Without (c) we would "prove" flows that
    cross unrelated scopes and quietly inflate confidence.
    """
    sink_idx = hit_line - 1
    if sink_idx < 0 or sink_idx >= len(masked):
        return []
    sink_line = masked[sink_idx]
    sink_raw = raw_lines[sink_idx] if sink_idx < len(raw_lines) else sink_line
    ev: list[Evidence] = []

    for _tp, src_re, sink_re in rule_taint:
        if not sink_re.search(sink_line):
            continue
        for idx in range(sink_idx - 1, max(-1, sink_idx - 1 - max_back), -1):
            line = masked[idx]
            if not src_re.search(line):
                continue
            m = _ASSIGN.match(line)
            if not m:
                continue
            var, rhs = m.group(1), m.group(2)
            # the tainted value must actually reach the sink
            if not re.search(rf"\b{re.escape(var)}\b", sink_raw):
                continue
            ev.append(Evidence(line=idx + 1, code=_snippet(raw_lines[idx]), role="source"))
            break
        if ev:
            break
    return ev


def analyze_source(
    source: str,
    path: str,
    language: str | None = None,
    include_tests: bool = True,
) -> FileReport:
    """Analyze a single in-memory source string.

    ``include_tests=False`` returns an empty report for paths that look like
    test fixtures, which is the right default when gating a build.
    """
    lang = language or detect_language(path, source[:2048])
    if not include_tests and is_test_path(path):
        return FileReport(path=path, language=lang, lines=len(source.splitlines()),
                          skipped="test file")
    masked, raw_lines = mask_source(source, lang)
    report = FileReport(path=path, language=lang, lines=len(raw_lines))

    suppressions = _suppressions(raw_lines)
    in_tests = is_test_path(path)
    # fixture / demo / sample files intentionally contain bad code: they are the
    # input to tests and screenshots, not shipped behaviour.
    in_sample = is_sample_path(path)
    basename = path.rsplit("/", 1)[-1].lower()
    is_manifest = basename in MANIFEST_NAMES

    for rule, patterns, taint in _rules_for(lang):
        if rule.id in MANIFEST_ONLY_RULES and not is_manifest:
            continue
        if in_tests and rule.id in TEST_RELAXED_RULES:
            continue
        if in_sample:
            continue
        seen_lines: set[int] = set()
        for pat, regex in patterns:
            for idx, line in enumerate(masked, start=1):
                if idx in seen_lines:
                    continue
                raw_line = raw_lines[idx - 1]
                if _DOC_LINE.match(raw_line):
                    continue
                # declarations never execute the sink they name (secrets rules excepted:
                # a credential in a default argument is still a credential)
                if _DECLARATION.match(raw_line) and "secrets" not in rule.tags:
                    continue
                if rule.inspect_strings:
                    # keep quote characters, drop nothing else: an all-string line
                    # is documentation, not an assignment we should police
                    if not re.search(r"[A-Za-z0-9_]", line.replace('"', "").replace("'", "")):
                        continue
                    haystack = raw_lines[idx - 1]
                else:
                    haystack = line
                m = regex.search(haystack)
                if not m:
                    continue
                # false-positive guards run against the raw line
                raw = raw_lines[idx - 1]
                if pat.not_if and any(re.search(g, raw, re.IGNORECASE) for g in pat.not_if):
                    continue
                if pat.guard and GUARDS[pat.guard](_logical_line(raw_lines, idx - 1)):
                    continue
                if pat.context_re:
                    ctx_lo = max(0, idx - 1 - pat.context_window)
                    window = raw_lines[ctx_lo:idx]
                    if not any(re.search(pat.context_re, w) for w in window):
                        continue
                if pat.require_above:
                    window = raw_lines[max(0, idx - 1 - pat.window) : idx - 1]
                    if not any(
                        re.search(g, w) for g in pat.require_above for w in window
                    ):
                        continue
                if _is_suppressed(suppressions, idx, rule.id):
                    report.suppressed += 1
                    seen_lines.add(idx)
                    continue
                seen_lines.add(idx)
                code = _snippet(_mask_secret_values(raw)) if rule.id in SECRET_RULES else _snippet(raw)
                evidence: list[Evidence] = []
                # taint trace
                evidence.extend(_find_taint_evidence(masked, raw_lines, taint, idx))
                evidence.append(Evidence(line=idx, code=code, role="sink"))
                # A sink whose arguments are visibly sanitised is not a confirmed
                # vulnerability: keep it, but at reduced confidence.
                sanitized = is_sanitized(rule.id, raw)

                has_trace = sum(1 for e in evidence if e.role == "source") > 0
                if sanitized:
                    confidence = "low"
                elif taint and not has_trace and rule.confidence_without_trace:
                    # rule *can* trace data flow but no untrusted source reached
                    # this sink -> report it, but with the weaker labelled confidence
                    confidence = rule.confidence_without_trace
                elif has_trace:
                    confidence = "high"
                else:
                    confidence = rule.confidence
                report.findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=confidence,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        file=path,
                        line=idx,
                        column=m.start() + 1,
                        code=code,
                        message=pat.message,
                        why=rule.why,
                        fix_hint=rule.fix_hint,
                        vuln_example=rule.vuln_example,
                        fix_example=rule.fix_example,
                        language=lang,
                        tags=list(rule.tags),
                        references=list(rule.references),
                        evidence=evidence,
                        fingerprint=fingerprint(rule.id, path, raw),
                    )
                )

    # entropy secrets (language-agnostic, catches keys no pattern knows about)
    if not in_tests and not in_sample:
        for line_no, value, ent in entropy_secret_scan(raw_lines, path):
            if any(f.rule_id == "AEGIS-AUTH-002" and f.line == line_no for f in report.findings):
                continue
            if _is_suppressed(suppressions, line_no, "AEGIS-SECRET-001"):
                report.suppressed += 1
                continue
            rule = RULE_BY_ID["AEGIS-SECRET-001"]
            raw = raw_lines[line_no - 1]
            report.findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence="medium",
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    file=path,
                    line=line_no,
                    column=1,
                    code=_redact(raw, value),
                    message=f"High-entropy string (entropy {ent}) assigned to a secret-like name.",
                    why=rule.why,
                    fix_hint=rule.fix_hint,
                    vuln_example=rule.vuln_example,
                    fix_example=rule.fix_example,
                    language=lang,
                    tags=list(rule.tags),
                    references=list(rule.references),
                    fingerprint=fingerprint(rule.id, path, raw),
                    redacted=True,
                )
            )

    # de-duplicate identical (rule, line)
    uniq: dict[tuple[str, int], Finding] = {}
    for f in report.findings:
        key = (f.rule_id, f.line)
        if key not in uniq:
            uniq[key] = f
    report.findings = sorted(uniq.values(), key=lambda f: f.line)
    return report


SECRET_RULES = {"AEGIS-AUTH-002", "AEGIS-CRYPTO-003", "AEGIS-CONF-006", "AEGIS-SECRET-001"}

_QUOTED = re.compile(r"([\"'])([^\"']{6,120})(\1)")


def _mask_secret_values(line: str) -> str:
    """Replace the literal value in a secret-bearing line so reports never leak it."""

    def _sub(m: re.Match) -> str:
        val = m.group(2)
        if len(val) <= 8:
            return m.group(0)
        return f"{m.group(1)}{val[:2]}{'*' * 8}{val[-2:]}{m.group(3)}"

    return _QUOTED.sub(_sub, line)


def _redact(line: str, value: str) -> str:
    return line.replace(value, value[:4] + "*" * max(4, len(value) - 6) + value[-2:])


# ---------------------------------------------------------------------------
# 4. Filesystem / project scanning
# ---------------------------------------------------------------------------

def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        parts = set(p.relative_to(root).parts[:-1])
        if parts & SKIP_DIRS:
            continue
        yield p


def scan_path(root: str | Path, include_tests: bool = False, include_docs: bool = True) -> ScanResult:
    started = time.perf_counter()
    root = Path(root)
    result = ScanResult()

    for file_path in _iter_files(root):
        try:
            rel = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
        except ValueError:
            rel = file_path.name
        if is_binary_name(rel):
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                result.files.append(
                    FileReport(path=rel, language="unknown", lines=0, skipped="too large")
                )
                continue
            data = file_path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")

        lang = detect_language(rel, text[:2048])
        if lang == "unknown":
            result.files.append(
                FileReport(path=rel, language="unknown", lines=len(text.splitlines()), skipped="unsupported")
            )
            continue
        if not include_docs and NON_SHIPPED_DIRS.search(rel):
            result.files.append(
                FileReport(path=rel, language=lang, lines=len(text.splitlines()), skipped="docs/example")
            )
            continue
        if not include_tests and is_test_path(rel):
            result.files.append(
                FileReport(path=rel, language=lang, lines=len(text.splitlines()), skipped="test file")
            )
            continue
        result.files.append(analyze_source(text, rel, lang))

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    result.rules_evaluated = len(RULES)
    result.meta = {
        "languages": sorted({f.language for f in result.scannable_files}),
        "supported_languages": sorted(SUPPORTED),
    }
    return result
