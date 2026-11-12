"""
Rule catalog for the Aegis static analysis engine.

Every rule carries enough metadata to be actionable *and* to be exported to
SARIF / a human report without a second database:

  id        stable identifier (AEGIS-<AREA>-<n>) -- used for baselines & ignores
  severity  critical | high | medium | low | info
  cwe       CWE identifier, for triage against industry taxonomies
  owasp     OWASP Top 10 (2021) category
  taint     (source_regex, sink_regex) pairs -> enables data-flow traces
  fix       human remediation: why it matters + vulnerable vs. safe example

Rules are declarative on purpose: adding a check is a data edit, not a code
edit, so the catalog can grow without touching the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern as RePattern

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Pattern:
    """A single lexical matcher."""

    regex: str
    message: str
    # if any of these match the line, the hit is discarded (false-positive guard)
    not_if: tuple[str, ...] = ()
    # if any of these appear within `window` lines above, the hit is kept
    require_above: tuple[str, ...] = ()
    window: int = 0
    # the hit is kept only if this matches the line or the `context_window`
    # lines above it. Use it when a call is dangerous *in one context* and
    # routine in another (hashing a password vs. hashing an ETag).
    context_re: str | None = None
    context_window: int = 4
    # named post-detection heuristic that can veto this hit (see analyzer.GUARDS)
    guard: str | None = None

    def compiled(self) -> RePattern[str]:
        return re.compile(self.regex)


@dataclass(frozen=True)
class TaintPair:
    """Source -> sink pair used to build a data-flow trace for a finding."""

    source: str
    sink: str
    label: str


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp: str
    languages: tuple[str, ...]
    why: str
    fix_hint: str
    vuln_example: str
    fix_example: str
    patterns: tuple[Pattern, ...] = ()
    taint: tuple[TaintPair, ...] = ()
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = field(default_factory=tuple)
    # confidence to report when the rule supports taint tracking but no
    # source->sink trace could be proven (None => keep the rule's own confidence)
    confidence_without_trace: str | None = None
    # true => matches inside string literals are legitimate (secrets, URLs, cipher names)
    inspect_strings: bool = False


# ---------------------------------------------------------------------------
# Shared regex fragments
# ---------------------------------------------------------------------------

# Values that are obviously not real secrets (placeholders, env lookups, test data)
_PLACEHOLDER = (
    r"(?:xxx+|your[_-]?(?:key|token|secret|password)|change[_-]?me|placeholder"
    r"|example|dummy|test|fake|redacted|todo|\*\*\*|<[^>]+>|\$\{|process\.env|os\.environ"
    r"|os\.getenv|ENV\[|getenv|secrets?\.|config\[)"
)

# Request/user-controlled input sources, by language family
_SRC_PY = (
    r"(?:request\.(?:args|form|json|values|data|files|GET|POST|body|cookies|headers)"
    r"|input\(|sys\.argv|flask\.request|params\[|query_params)"
)
_SRC_JS = (
    r"(?:req\.(?:body|query|params|headers|cookies|url)|event\.target\.value"
    r"|location\.(?:search|hash|href)|document\.cookie|process\.argv|window\.name"
    r"|message\.data|formData\.get)"
)
_SRC_JAVA = r"(?:request\.getParameter|request\.getHeader|request\.getQueryString|@RequestParam|@PathVariable|HttpServletRequest)"
_SRC_PHP = r"(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\[)"
_SRC_GO = r"(?:r\.URL\.Query\(\)|c\.Query\(|c\.Param\(|r\.FormValue\(|r\.Body)"
_SRC_RB = r"(?:params\[|request\.(?:params|body|cookies|headers)|gets\b)"


def _sql_sink_py() -> str:
    return (
        r"(?:execute|executemany|executescript|raw|extra)\s*\(\s*"
        r"(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format)|[\"']\s*%|[\"']\s*\+)"
    )


RULES: tuple[Rule, ...] = (
    # =====================================================================
    # INJECTION
    # =====================================================================
    Rule(
        id="AEGIS-SQLI-001",
        title="SQL injection via string-formatted query",
        severity="critical",
        confidence="high",
        cwe="CWE-89",
        owasp="A01:2021 - Broken Access Control",
        languages=("python",),
        why=(
            "The query is assembled with string interpolation, so any value that "
            "reaches it becomes SQL syntax. An attacker can close the string and "
            "append their own clause to read, modify or delete arbitrary rows "
            "(`' OR '1'='1`, `'; DROP TABLE users; --`)."
        ),
        fix_hint="Pass values as bound parameters instead of formatting the SQL string.",
        vuln_example=(
            'cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")\n'
            '# or: cursor.execute("SELECT ... " + email)'
        ),
        fix_example=(
            'cursor.execute(\n'
            '    "SELECT * FROM users WHERE email = %s",\n'
            '    (email,),          # driver escapes + types the value\n'
            ')'
        ),
        patterns=(
            Pattern(
                regex=_sql_sink_py(),
                message="Query built by string interpolation is passed to the database driver.",
                not_if=(r"%s|%\(|\?|:\w+|bindparam",),
            ),
        ),
        taint=(
            TaintPair(source=_SRC_PY, sink=_sql_sink_py(), label="HTTP input -> SQL query"),
        ),
        references=("https://cwe.mitre.org/data/definitions/89.html",),
        confidence_without_trace="low",
        tags=("injection", "database"),
    ),
    Rule(
        id="AEGIS-SQLI-002",
        title="SQL injection in raw ORM expression",
        severity="critical",
        confidence="medium",
        cwe="CWE-89",
        owasp="A01:2021 - Broken Access Control",
        languages=("python",),
        why=(
            "Raw SQL escape hatches (`text()`, `.raw()`, `.extra()`) bypass the ORM's "
            "parameterisation. Building them with f-strings or `%` re-opens SQL injection "
            "even in code that otherwise never touches a cursor."
        ),
        fix_hint="Use `.filter(Model.col == value)` or bind params with `text('... = :v')`.",
        vuln_example='db.session.execute(text(f"SELECT * FROM t WHERE id={id}"))',
        fix_example='db.session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": id})',
        patterns=(
            Pattern(
                regex=r"(?:text|raw|extra)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format))",
                message="Raw SQL fragment built with string formatting.",
                not_if=(r"%s|:\w+",),
            ),
        ),
        tags=("injection", "database", "orm"),
    ),
    Rule(
        id="AEGIS-CMDI-001",
        title="OS command injection",
        severity="critical",
        confidence="high",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        languages=("python",),
        why=(
            "The shell interprets the string, so `;`, `&&`, `|`, `$( )` and backticks in "
            "user input run as extra commands. This is usually full remote code execution "
            "as the application's OS user."
        ),
        fix_hint="Pass an argument list with shell=False, or use a dedicated library.",
        vuln_example='os.system(f"convert {filename} out.png")',
        fix_example=(
            'subprocess.run(["convert", filename, "out.png"], shell=False, check=True)'
        ),
        patterns=(
            Pattern(
                regex=r"\bos\.(?:system|popen|spawn\w*)\s*\(",
                message="`os.system`-family call executes through a shell.",
            ),
            Pattern(
                regex=r"subprocess\.\w+\s*\([^)]*\bshell\s*=\s*True",
                message="`shell=True` hands the command line to /bin/sh.",
            ),
            Pattern(
                regex=r"commands\.get(?:status)?output\s*\(",
                message="Legacy `commands` module always uses a shell.",
            ),
            Pattern(
                regex=r"subprocess\.\w+\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format))",
                message="Shell string built with user-controlled interpolation.",
                not_if=(r"shell\s*=\s*False",),
            ),
        ),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
        tags=("injection", "rce"),
    ),
    Rule(
        id="AEGIS-CODE-001",
        title="Dynamic code execution (eval / exec)",
        severity="critical",
        confidence="high",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        languages=("python",),
        why=(
            "`eval`/`exec` run arbitrary Python with the application's privileges. If any "
            "part of the expression originates from a request, a config file or a template, "
            "an attacker can execute any code the process can."
        ),
        fix_hint="Replace with an explicit mapping/lookup table or `ast.literal_eval` for literals.",
        vuln_example="result = eval(request.args['expr'])",
        fix_example=(
            "ALLOWED = {'sum': sum, 'len': len}\n"
            "result = ALLOWED[request.args['op']](values)   # no code parsing"
        ),
        patterns=(
            Pattern(
                regex=r"(?<![\w.])(?:eval|exec)\s*\(",
                message="Arbitrary code evaluation.",
                not_if=(r"ast\.literal_eval|\.executemany",),
            ),
            Pattern(
                regex=r"\bcompile\s*\([^)]*[\"']exec[\"']",
                message="`compile(..., 'exec')` builds executable code at runtime.",
            ),
        ),
        tags=("injection", "rce"),
    ),
    Rule(
        id="AEGIS-DESER-001",
        title="Unsafe deserialization",
        severity="critical",
        confidence="high",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
        languages=("python",),
        why=(
            "`pickle`, `marshal`, `dill` and `shelve` reconstruct arbitrary objects by "
            "design — a crafted payload executes code during `loads()`, before any validation "
            "you might add afterwards. The same applies to `yaml.load` without a safe loader."
        ),
        fix_hint="Use JSON or msgpack for data; if pickle is unavoidable, sign and verify payloads.",
        vuln_example="user = pickle.loads(request.data)",
        fix_example='user = json.loads(request.data)   # or yaml.safe_load(...)',
        patterns=(
            Pattern(
                regex=r"\b(?:pickle|dill|cPickle|marshal|shelve)\.(?:load|loads|Unpickler)\s*\(",
                message="Deserializing untrusted bytes can execute code.",
            ),
            Pattern(
                regex=r"\byaml\.(?:load|unsafe_load)\s*\(",
                message="`yaml.load` builds arbitrary Python objects — use `yaml.safe_load`.",
                not_if=(r"safe_load|SafeLoader|FullLoader",),
            ),
            Pattern(
                regex=r"\bjsonpickle\.decode\s*\(",
                message="jsonpickle decodes arbitrary object graphs.",
            ),
        ),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
        tags=("deserialization", "rce"),
    ),
    Rule(
        id="AEGIS-XSS-001",
        title="Unescaped output rendered as HTML (XSS)",
        severity="high",
        confidence="high",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        languages=("javascript", "typescript"),
        why=(
            "Assigning a string to `innerHTML` (or `document.write`) makes the browser parse "
            "it as markup. Text from a URL, a stored comment or an API response can therefore "
            "inject `<img onerror=...>` and run script in your origin, stealing session tokens."
        ),
        fix_hint="Use `textContent` for text, or sanitize with DOMPurify before HTML insertion.",
        vuln_example="el.innerHTML = `<p>${comment}</p>`;",
        fix_example=(
            "el.textContent = comment;\n"
            "// or, when markup is required:\n"
            "el.innerHTML = DOMPurify.sanitize(comment);"
        ),
        patterns=(
            Pattern(
                regex=r"\.(?:innerHTML|outerHTML)\s*\+?=\s*",
                message="String assigned to innerHTML is parsed as markup.",
                not_if=(r"DOMPurify\.sanitize|sanitizeHtml|escapeHtml|textContent"
                        r"|UI\.esc|escapeHtml\(|\bsafeHtml\b",),
                guard="escaped_template",
            ),
            Pattern(
                regex=r"document\.write(?:ln)?\s*\(",
                message="`document.write` parses its argument as HTML.",
            ),
            Pattern(
                regex=r"dangerouslySetInnerHTML",
                message="React escape hatch renders raw HTML.",
                not_if=(r"DOMPurify|sanitize",),
            ),
            Pattern(
                regex=r"\$\(\s*(?:location\.(?:hash|search|href)|document\.(?:URL|referrer|location))",
                message="jQuery HTML sink fed from the URL (DOM XSS).",
            ),
        ),
        taint=(
            TaintPair(
                source=_SRC_JS,
                sink=r"\.(?:innerHTML|outerHTML)\s*\+?=",
                label="untrusted input -> HTML sink",
            ),
        ),
        tags=("xss", "browser"),
    ),
    Rule(
        id="AEGIS-XSS-002",
        title="Cross-site scripting via server-side template",
        severity="high",
        confidence="high",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        languages=("python", "java", "php", "ruby"),
        why=(
            "Autoescaping is what stops an attacker's `<script>` from being rendered verbatim. "
            "Disabling it, or piping through `safe`/`raw`, opts that one expression out of the "
            "protection for every request."
        ),
        fix_hint="Keep autoescaping on and escape at render time (`markupsafe.escape`).",
        vuln_example="{{ user_bio | safe }}",
        fix_example="{{ user_bio }}   {# autoescaped by Jinja2 #}",
        patterns=(
            Pattern(
                regex=r"\|\s*safe\b|{%\s*autoescape\s+false\s*%}|mark_safe\s*\(",
                message="Output is marked safe / autoescape disabled.",
                # A framework calling mark_safe() on value it just escaped is correct
                # usage; require user-facing input in scope before reporting.
                context_re=r"(?i)request\.|req\.|user_?input|\bform\b|POST\[|GET\[|params\[|\bquery\b",
                context_window=5,
            ),
        ),
        tags=("xss", "ssti"),
    ),
    Rule(
        id="AEGIS-PATH-001",
        title="Path traversal in file access",
        severity="high",
        confidence="medium",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go"),
        why=(
            "A filename joined onto a base directory can contain `../` sequences, letting a "
            "request read or overwrite files outside the intended folder — configuration, "
            "other tenants' uploads, or `/etc/passwd`."
        ),
        fix_hint="Resolve the path and verify it is still inside the base directory.",
        vuln_example='return send_file(os.path.join(UPLOADS, request.args["name"]))',
        fix_example=(
            "base = Path(UPLOADS).resolve()\n"
            "target = (base / name).resolve()\n"
            "if not target.is_relative_to(base):\n"
            "    abort(404)\n"
            "return send_file(target)"
        ),
        patterns=(
            Pattern(
                regex=r"(?:open|send_file|send_from_directory|readFile\w*|File\.read|unlink|rmtree|writeFile\w*)\s*\(\s*(?:os\.path\.join\s*\(|[\w.]+/\s*\+|\+\s*[\w.]+$)",
                message="File path assembled from variables without containment check.",
                not_if=(r"is_relative_to|realpath|resolve\(\)|secure_filename|commonpath",),
            ),
            Pattern(
                regex=r"\.\./|\\\\\.\.\\\\",
                message="Literal parent-directory traversal in a path.",
                not_if=(r"^\s*(?:#|//|\*)|\.\./\.\./\.\./\.\./\.\.",),
            ),
        ),
        taint=(
            TaintPair(
                source=_SRC_PY,
                sink=r"(?:open|send_file|read|unlink)\s*\(",
                label="request input -> filesystem path",
            ),
        ),
        tags=("filesystem",),
    ),
    Rule(
        id="AEGIS-REDIR-001",
        title="Open redirect",
        severity="medium",
        confidence="medium",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
        languages=("python", "javascript", "typescript", "php", "ruby"),
        why=(
            "Redirecting to a URL taken from the request lets attackers craft links on your "
            "trusted domain that bounce victims to a phishing or malware site. It also "
            "undermines OAuth flows that trust the redirect target."
        ),
        fix_hint="Allow only relative paths or an explicit allowlist of hosts.",
        vuln_example='return redirect(request.args.get("next"))',
        fix_example=(
            'target = request.args.get("next", "/")\n'
            'if not target.startswith("/") or target.startswith("//"):\n'
            '    target = "/"\n'
            "return redirect(target)"
        ),
        patterns=(
            Pattern(
                regex=r"(?:redirect|RedirectResponse|res\.redirect|header\s*\(\s*[\"']Location)\s*\(?\s*(?:request\.|req\.|\$_|\$|params)",
                message="Redirect target comes from the request.",
                not_if=(r"startswith|is_safe_url|url_has_allowed_host|allowlist|whitelist",),
            ),
        ),
        tags=("redirect",),
    ),
    Rule(
        id="AEGIS-SSTI-001",
        title="Server-side template injection",
        severity="critical",
        confidence="medium",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
        languages=("python",),
        why=(
            "Compiling a template from user-controlled text lets an attacker evaluate "
            "expressions (`{{7*7}}`) and often reach Python internals for RCE."
        ),
        fix_hint="Render a fixed template file and pass user data as context variables.",
        vuln_example="return render_template_string(request.args['tpl'])",
        fix_example="return render_template('page.html', tpl=request.args['tpl'])",
        patterns=(
            Pattern(
                # NOTE: stdlib `string.Template` is deliberately NOT matched --
                # it performs $var substitution, not expression evaluation.
                regex=r"\brender_template_string\s*\(",
                message="Template constructed from a runtime string.",
            ),
        ),
        tags=("injection", "ssti"),
    ),
    Rule(
        id="AEGIS-LDAP-001",
        title="LDAP filter injection",
        severity="high",
        confidence="medium",
        cwe="CWE-90",
        owasp="A03:2021 - Injection",
        languages=("python", "java", "javascript"),
        why="Concatenating input into an LDAP filter allows auth bypass with `*)(uid=*` style payloads.",
        fix_hint="Escape special characters with the library's escape filter helper.",
        vuln_example='conn.search(BASE, f"(uid={username})")',
        fix_example='conn.search(BASE, "(uid=%s)" % escape_filter_chars(username))',
        patterns=(
            Pattern(
                regex=r"\((?:uid|cn|mail|sAMAccountName)=\s*(?:\{|[\"']\s*\+|f[\"'])",
                message="LDAP filter built with interpolation.",
            ),
        ),
        tags=("injection",),
    ),
    Rule(
        id="AEGIS-XPATH-001",
        title="XPath injection",
        severity="high",
        confidence="medium",
        cwe="CWE-643",
        owasp="A03:2021 - Injection",
        languages=("python", "java", "php"),
        why="User text spliced into an XPath expression can alter the query and bypass authentication checks.",
        fix_hint="Use parameterised XPath variables instead of string concatenation.",
        vuln_example='tree.xpath("//user[login/text()=\'" + user + "\']")',
        fix_example='tree.xpath("//user[login/text()=$u]", u=user)',
        patterns=(
            Pattern(
                regex=r"xpath\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:\+|%))",
                message="XPath built by concatenation.",
            ),
        ),
        tags=("injection",),
    ),

    # =====================================================================
    # AUTHENTICATION / AUTHORIZATION
    # =====================================================================
    Rule(
        id="AEGIS-AUTH-001",
        title="Weak password hashing",
        severity="critical",
        confidence="high",
        cwe="CWE-916",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go"),
        why=(
            "MD5/SHA-1 are fast by design: a GPU tries billions of candidates per second, so a "
            "leaked table is cracked in hours. They are also unsalted, making rainbow tables "
            "effective. Password storage needs a deliberately slow, salted KDF."
        ),
        fix_hint="Use argon2id, bcrypt or scrypt (e.g. `argon2-cffi` / `bcrypt`).",
        vuln_example='hash = hashlib.md5(password.encode()).hexdigest()',
        fix_example=(
            "from argon2 import PasswordHasher\n"
            "ph = PasswordHasher()\n"
            "hash = ph.hash(password)          # salted, tunable, memory-hard"
        ),
        patterns=(
            Pattern(
                regex=r"(?:hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)|Crypto\.createHash\s*\(\s*[\"'](?:md5|sha1)|md5\s*\(|sha1\s*\()",
                message="Fast, unsalted digest used where a password KDF is required.",
                not_if=(r"cache|etag|checksum|fixture|nonce|hmac|signature|dedup|\.png|fingerprint"
                        r"|_lazy_|\.digest\s*\(\s*\)\s*$",),
                # md5/sha1 is everywhere; only report it in a password context
                context_re=r"(?i)passw|passwd|\bpwd\b|credential|login|user_?auth|salt",
                context_window=6,
            ),
        ),
        tags=("crypto", "authentication"),
    ),
    Rule(
        id="AEGIS-AUTH-002",
        title="Hardcoded credential in source",
        severity="high",
        confidence="medium",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        languages=(
            "python", "javascript", "typescript", "java", "php", "ruby", "go",
            "c", "cpp", "csharp", "kotlin", "swift", "yaml", "json", "toml", "ini", "env",
        ),
        why=(
            "Credentials committed to source live forever in git history, appear in CI logs, "
            "and are shared with everyone who can read the repo. Rotation requires a code "
            "change, so they tend to stay valid for years."
        ),
        fix_hint="Load from the environment or a secrets manager; rotate the exposed value.",
        vuln_example='DB_PASSWORD = "sup3rs3cret!"',
        fix_example='DB_PASSWORD = os.environ["DB_PASSWORD"]   # injected at deploy time',
        patterns=(
            Pattern(
                regex=r"(?i)(?<![a-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|db[_-]?pass)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
                message="Credential assigned a literal value.",
                not_if=(_PLACEHOLDER,
                        r"DEMO_|EXAMPLE_|SAMPLE_|FIXTURE_|getenv|env\.|os\.environ|process\.env"
                        r"|settings\.|config\.|\.env\b|%\(|%s|\{[\w]*\}|\bf\"|\bformat\("),
            ),
        ),
        inspect_strings=True,
        tags=("secrets", "owasp-a07"),
    ),
    Rule(
        id="AEGIS-AUTH-003",
        title="JWT verified with 'none' or without signature check",
        severity="critical",
        confidence="high",
        cwe="CWE-347",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "go"),
        why=(
            "Decoding a JWT without verifying its signature (or accepting `alg: none`) lets "
            "anyone forge a token claiming to be any user, including an admin."
        ),
        fix_hint="Always pass an explicit algorithm allowlist and verify the signature.",
        vuln_example='jwt.decode(token, options={"verify_signature": False})',
        fix_example='jwt.decode(token, SECRET, algorithms=["HS256"], audience=API_AUD)',
        patterns=(
            Pattern(
                regex=r"verify_signature[\"']?\s*:\s*False|\"verify\"\s*:\s*False|algorithms\s*=\s*\[\s*[\"']none|alg\w*\s*[:=]\s*[\"']none",
                message="JWT signature verification is disabled.",
            ),
            Pattern(
                regex=r"jwt\.decode\s*\(\s*[^,)]+\s*\)",
                message="JWT decoded without key/algorithm options.",
                not_if=(r"algorithms",),
            ),
        ),
        tags=("crypto", "authentication"),
        inspect_strings=True,
    ),
    Rule(
        id="AEGIS-AUTH-004",
        title="Insecure token / session generation",
        severity="high",
        confidence="high",
        cwe="CWE-338",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "ruby"),
        why=(
            "`random`/`Math.random` are deterministic PRNGs seeded predictably. Tokens, "
            "password-reset codes and session ids built from them can be recovered by "
            "observing a few outputs."
        ),
        fix_hint="Use the platform CSPRNG: `secrets`, `crypto.randomUUID()`, `random_bytes`.",
        vuln_example='reset_token = "".join(random.choice(CHARS) for _ in range(32))',
        fix_example="import secrets\nreset_token = secrets.token_urlsafe(32)",
        patterns=(
            Pattern(
                regex=r"\brandom\.(?:random|randint|choice|choices|sample|getrandbits|randrange)\s*\(",
                message="Non-cryptographic PRNG used.",
                # only when the value is used for a credential/session decision
                context_re=r"(?i)passw|token|session|reset|csrf|nonce|secret|otp|verif|auth|pin\b|code\b",
                context_window=6,
                not_if=(r"secrets\.|SystemRandom|#\s*nosec|jitter|backoff|retry|shuffle|test|sample_size|random_state|np\.random|numpy",),
            ),
            Pattern(
                regex=r"\bMath\.random\s*\(",
                message="`Math.random` is not suitable for security tokens.",
                # context_re already scopes this to security-sensitive values, so
                # the not_if list stays minimal (styling / animation jitter only)
                not_if=(r"animation|particle|colour|color|jitter|joke|mock|offset|duration",),
                context_re=r"(?i)token|session|passw|secret|reset|csrf|nonce|otp|auth|uuid|pin\b",
                context_window=3,
            ),
        ),
        tags=("crypto", "randomness"),
    ),
    Rule(
        id="AEGIS-AUTH-005",
        title="Missing authorization check on object access (IDOR)",
        severity="medium",
        confidence="low",
        cwe="CWE-639",
        owasp="A01:2021 - Broken Access Control",
        languages=("python", "javascript", "typescript", "php", "ruby", "java"),
        why=(
            "Looking a record up by an id taken straight from the request, without also "
            "filtering on the owner, lets one user read another user's data by changing a "
            "number in the URL."
        ),
        fix_hint="Scope the query to the authenticated principal: `filter(owner_id == user.id)`.",
        vuln_example="doc = Document.query.get(request.args['id'])",
        fix_example="doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()",
        patterns=(
            Pattern(
                regex=r"\.(?:get|findById|find_by_id|findOne|find)\s*\(\s*(?:request\.|req\.(?:params|query|body)|\$_(?:GET|POST)|params\[)",
                message="Record fetched by request-supplied id with no ownership scoping.",
                not_if=(r"owner|user_id|current_user|tenant|account_id|organization|authorize|permission",),
            ),
        ),
        tags=("access-control", "idor"),
    ),
    Rule(
        id="AEGIS-AUTH-006",
        title="Authorization enforced with `assert`",
        severity="medium",
        confidence="high",
        cwe="CWE-617",
        owasp="A01:2021 - Broken Access Control",
        languages=("python",),
        why=(
            "`assert` statements are stripped when Python runs with `-O`, which production "
            "deployments often enable. An auth check written as an assert silently disappears."
        ),
        fix_hint="Raise an explicit exception (HTTPException/PermissionError) instead.",
        vuln_example="assert user.is_admin, 'admins only'",
        fix_example="if not user.is_admin:\n    raise HTTPException(403, 'admins only')",
        patterns=(
            Pattern(
                # must be a privilege check: assert user.is_admin / assert role == 'admin'
                regex=r"^\s*assert\s+(?:not\s+)?[\w.\[\]'\"]*(?:is_admin|is_staff|is_superuser"
                      r"|has_perm|can_\w+|is_authenticated|is_authorized|is_allowed|logged_in"
                      r"|allowed|authorized|owner|permission|role)[\w.\[\]'\"]*\s*(?:[,)]|$|==|!=|is\b)",
                message="Security decision depends on an assert (removed under -O).",
            ),
        ),
        tags=("access-control",),
    ),
    Rule(
        id="AEGIS-AUTH-007",
        title="Timing-unsafe secret comparison",
        severity="medium",
        confidence="medium",
        cwe="CWE-208",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "go", "ruby"),
        why=(
            "Comparing a MAC, signature or token with `==` returns as soon as a byte differs, "
            "leaking how much of the guess was correct and enabling byte-by-byte recovery."
        ),
        fix_hint="Use a constant-time comparison (`hmac.compare_digest`, `crypto.timingSafeEqual`).",
        vuln_example="if provided_token == stored_token:",
        fix_example="import hmac\nif hmac.compare_digest(provided_token, stored_token):",
        patterns=(
            Pattern(
                # A variable merely *named* ``token`` is usually a lexer/parser token,
                # so require a security-flavoured identifier and a value that could
                # plausibly be a secret (not a string/int literal).
                regex=r"\b[\w.]*(?:api_?key|access_?token|auth_?token|csrf_?token|session_?token"
                      r"|signature|hmac|digest|secret|checksum)[\w.]*\s*==\s*(?!['\"\d])([A-Za-z_][\w.]*)",
                not_if=(r"compare_digest|timingSafeEqual|\blength\b|len\(|is None|is not None"
                        r"|== None|is_empty|TOKEN_TYPE|token_type|\btype\b",),
                message="Secret compared with `==` (non-constant time).",
            ),
        ),
        tags=("crypto", "timing"),
    ),

    # =====================================================================
    # CRYPTOGRAPHY / TRANSPORT
    # =====================================================================
    Rule(
        id="AEGIS-CRYPTO-001",
        title="TLS certificate verification disabled",
        severity="high",
        confidence="high",
        cwe="CWE-295",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "go", "ruby"),
        why=(
            "Disabling verification makes every HTTPS call vulnerable to a man-in-the-middle, "
            "regardless of how strong the cipher is — the client will accept any certificate."
        ),
        fix_hint="Remove the bypass; fix the trust store instead.",
        vuln_example="requests.get(url, verify=False)",
        fix_example="requests.get(url, timeout=10)   # verify defaults to True",
        patterns=(
            Pattern(
                regex=r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CERT_NONE|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED|curl\s+-k|--insecure",
                message="Certificate verification turned off.",
                not_if=(r"get_ciphers|_create_ssl_context|DEFAULT_CIPHERS|cipher_names|#",),
            ),
        ),
        tags=("crypto", "tls"),
    ),
    Rule(
        id="AEGIS-CRYPTO-002",
        title="Weak or broken cipher",
        severity="high",
        confidence="high",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go", "c", "cpp"),
        why=(
            "DES/3DES/RC4/Blowfish have practical breaks or tiny block sizes; ECB mode leaks "
            "structure because identical plaintext blocks encrypt identically."
        ),
        fix_hint="Use AES-GCM (authenticated) or ChaCha20-Poly1305 with a random nonce.",
        vuln_example="cipher = AES.new(key, AES.MODE_ECB)",
        fix_example="cipher = AES.new(key, AES.MODE_GCM)\nciphertext, tag = cipher.encrypt_and_digest(data)",
        patterns=(
            Pattern(
                regex=r"\b(?:DES|DES3|Blowfish|ARC4|RC2|RC4)\b|MODE_ECB|aes-\d+-ecb|[\"']des-ede|createCipher\s*\(",
                message="Broken/weak algorithm or ECB mode in use.",
                not_if=(r"#|//|deprecat|legacy.*(?:migrat|read)",),
            ),
        ),
        inspect_strings=True,
        tags=("crypto",),
    ),
    Rule(
        id="AEGIS-CRYPTO-003",
        title="Static / hardcoded encryption key or IV",
        severity="high",
        confidence="high",
        cwe="CWE-321",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "go", "c", "cpp"),
        why=(
            "A key embedded in source is not a secret. A fixed IV/nonce is worse: reusing it "
            "with GCM or CTR catastrophically leaks plaintext relationships."
        ),
        fix_hint="Load keys from a KMS/secrets manager and generate a fresh random nonce per message.",
        vuln_example='key = b"0123456789abcdef"\niv = b"0000000000000000"',
        fix_example=(
            "key = keyring.load()                  # from KMS / secret store\n"
            "nonce = os.urandom(12)                # fresh for every encryption"
        ),
        patterns=(
            Pattern(
                # NOTE: `salt` is deliberately excluded - a salt is public domain
                # separation, not a secret. Salt *generation* is covered by CRYPTO-005.
                regex=r"(?i)\b(?:aes_?key|encryption_?key|secret_?key|iv|nonce)\b\s*[:=]\s*(?:b[\"'][^\"']{8,}[\"']|[\"'][0-9a-fA-F]{16,}[\"'])",
                message="Cryptographic key/IV hardcoded.",
                not_if=(_PLACEHOLDER, r"test|spec|fixture|example|len\(|length"),
            ),
        ),
        inspect_strings=True,
        tags=("crypto", "secrets"),
    ),
    Rule(
        id="AEGIS-CRYPTO-004",
        title="Insufficient key length",
        severity="medium",
        confidence="medium",
        cwe="CWE-326",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "java", "php", "go"),
        why="RSA below 2048 bits and symmetric keys below 128 bits fall to modern factoring and brute force.",
        fix_hint="RSA >= 3072 bits, AES-256, EC P-256+.",
        vuln_example="rsa.generate_private_key(public_exponent=65537, key_size=1024)",
        fix_example="rsa.generate_private_key(public_exponent=65537, key_size=3072)",
        patterns=(
            Pattern(
                regex=r"key_size\s*=\s*(?:512|1024)\b|RSA(?:_generate)?\w*\s*\(\s*(?:512|1024)\b|modulusLength\s*:\s*(?:512|1024)\b",
                message="Key length below current guidance.",
            ),
        ),
        tags=("crypto",),
    ),
    Rule(
        id="AEGIS-CRYPTO-005",
        title="Insecure randomness for salts / keys",
        severity="medium",
        confidence="medium",
        cwe="CWE-330",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "php", "ruby"),
        why="Salts and keys must be unpredictable; a predictable salt enables precomputed attacks.",
        fix_hint="Use `secrets.token_bytes(16)` / `crypto.randomBytes(16)`.",
        vuln_example="salt = md5(str(time.time())).hexdigest()[:16]",
        fix_example="salt = secrets.token_bytes(16)",
        patterns=(
            Pattern(
                regex=r"salt\s*=\s*(?:str\(\s*time\.time|md5|sha1|random\.|Math\.random|uniqid)",
                message="Salt derived from time or a weak PRNG.",
            ),
        ),
        tags=("crypto", "randomness"),
    ),

    # =====================================================================
    # CONFIGURATION / EXPOSURE
    # =====================================================================
    Rule(
        id="AEGIS-CONF-001",
        title="Debug mode enabled",
        severity="high",
        confidence="high",
        cwe="CWE-489",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python", "javascript", "php", "ruby", "yaml", "json", "toml", "ini", "env"),
        why=(
            "Debug mode exposes stack traces, environment variables and an interactive "
            "debugger. In Flask/Werkzeug the console allows arbitrary code execution."
        ),
        fix_hint="Drive debug from an env var that is off in production.",
        vuln_example="app.run(debug=True)",
        fix_example='app.run(debug=os.getenv("FLASK_DEBUG") == "1")',
        patterns=(
            Pattern(
                regex=r"(?:app\.run|debug\s*=\s*)\(?\s*[^)]*debug\s*=\s*True|DEBUG\s*=\s*True|debug\s*:\s*true",
                message="Debug mode hardcoded on.",
                not_if=(r"getenv|environ|process\.env|settings\.|config\.|is_dev|development",),
            ),
        ),
        tags=("configuration",),
    ),
    Rule(
        id="AEGIS-CONF-002",
        title="Permissive CORS policy",
        severity="medium",
        confidence="high",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python", "javascript", "typescript", "java", "php", "go"),
        why=(
            "Allowing any origin while sending credentials lets any website read authenticated "
            "responses. `*` with `allow_credentials` is rejected by browsers, which pushes "
            "developers to reflect the Origin header — the same hole with extra steps."
        ),
        fix_hint="List explicit trusted origins; never combine `*` with credentials.",
        vuln_example='Access-Control-Allow-Origin: *',
        fix_example='Access-Control-Allow-Origin: https://app.example.com',
        patterns=(
            Pattern(
                regex=r"Access-Control-Allow-Origin[\"']?\s*[,:=]\s*[\"']?\*|allow_origins\s*=\s*\[\s*[\"']\*|cors\s*\(\s*\)|origin\s*:\s*(?:[\"']\*[\"']|true)",
                message="CORS allows any origin.",
                not_if=(r"test|local|dev",),
            ),
        ),
        inspect_strings=True,
        tags=("configuration", "cors"),
    ),
    Rule(
        id="AEGIS-CONF-003",
        title="Binding to all network interfaces",
        severity="medium",
        confidence="medium",
        cwe="CWE-1327",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python", "javascript", "go"),
        why="A dev server bound to 0.0.0.0 is reachable from the whole network, not just your machine.",
        fix_hint="Bind to 127.0.0.1 locally; use a reverse proxy in production.",
        vuln_example='app.run(host="0.0.0.0", port=5000)',
        fix_example='app.run(host="127.0.0.1", port=5000)',
        patterns=(
            Pattern(
                regex=r"host\s*=\s*[\"']0\.0\.0\.0[\"']|listen\s*\(\s*[\"']0\.0\.0\.0",
                message="Server listens on every interface.",
                not_if=(r"docker|container|prod",),
            ),
        ),
        tags=("configuration", "network"),
    ),
    Rule(
        id="AEGIS-CONF-005",
        title="Wildcard TLS verification / insecure URL scheme",
        severity="low",
        confidence="medium",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go"),
        why="Plain `http://` endpoints transmit credentials and tokens in clear text.",
        fix_hint="Use https:// and HSTS.",
        vuln_example='API = "http://api.example.com/v1"',
        fix_example='API = "https://api.example.com/v1"',
        patterns=(
            Pattern(
                regex=r"[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas\.|www\.w3\.org|xmlns|example\.com|test)[\w.-]+",
                message="Hardcoded cleartext HTTP endpoint.",
                not_if=(r"#|//|comment|doc|readme|xmlns|w3\.org",),
            ),
        ),
        inspect_strings=True,
        tags=("configuration", "tls"),
    ),
    Rule(
        id="AEGIS-CONF-006",
        title="Flask secret key default / weak",
        severity="medium",
        confidence="high",
        cwe="CWE-798",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python",),
        why="A default or short `SECRET_KEY` lets attackers forge session cookies and signed tokens.",
        fix_hint="Generate 32+ random bytes; require it from the environment at startup.",
        vuln_example='app.secret_key = "dev"',
        fix_example='app.secret_key = os.environ["SECRET_KEY"]   # fail fast if unset',
        patterns=(
            Pattern(
                regex=r"SECRET_KEY\s*=\s*[\"'][^\"']+[\"']",
                message="Secret key set to a literal.",
                not_if=(_PLACEHOLDER, r"getenv|environ"),
            ),
            Pattern(
                regex=r"secret_key\s*=\s*[\"']\w{1,15}[\"']",
                message="Secret key is a short literal.",
                not_if=(_PLACEHOLDER,),
            ),
        ),
        inspect_strings=True,
        tags=("configuration", "secrets"),
    ),

    # =====================================================================
    # DATA HANDLING / PRIVACY
    # =====================================================================
    Rule(
        id="AEGIS-LOG-001",
        title="Sensitive data written to logs",
        severity="medium",
        confidence="medium",
        cwe="CWE-532",
        owasp="A09:2021 - Security Logging and Monitoring Failures",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go"),
        why=(
            "Logs are copied to aggregation systems, kept for months and read by people who "
            "should not see credentials or PII. A password in a log line is a leaked password."
        ),
        fix_hint="Log an identifier or a redacted form, never the raw secret.",
        vuln_example='logger.info(f"login {email} password={password}")',
        fix_example='logger.info("login attempt", extra={"user_id": user.id})',
        patterns=(
            Pattern(
                regex=r"(?:log(?:ger)?|console)\.(?:debug|info|warn(?:ing)?|error|log|exception|critical)\s*\([^)]*(?:password|passwd|secret|token|api_?key|authorization|credit_?card|cvv|ssn)",
                message="Secret/PII passed to a log sink.",
                not_if=(r"redact|mask|\*\*\*|hash|\[REDACTED\]|has_password|is_valid",),
            ),
        ),
        tags=("logging", "pii"),
    ),
    Rule(
        id="AEGIS-DATA-001",
        title="Sensitive data stored in client-side storage",
        severity="medium",
        confidence="medium",
        cwe="CWE-922",
        owasp="A07:2021 - Identification and Authentication Failures",
        languages=("javascript", "typescript"),
        why=(
            "`localStorage`/`sessionStorage` are readable by any script on the origin, so a "
            "single XSS exfiltrates the token and keeps it valid offline. Cookies with "
            "HttpOnly+Secure are not readable from JS."
        ),
        fix_hint="Store session tokens in HttpOnly, Secure, SameSite cookies.",
        vuln_example="localStorage.setItem('token', accessToken);",
        fix_example="// server sets: Set-Cookie: sid=...; HttpOnly; Secure; SameSite=Strict",
        patterns=(
            Pattern(
                regex=r"localStorage\.setItem\s*\(\s*[\"'][^\"']*(?:token|jwt|auth|session|secret|key)",
                message="Auth material persisted to localStorage.",
                not_if=(r"theme|lang|locale|consent|debug|#",),
            ),
        ),
        tags=("storage", "session"),
    ),
    Rule(
        id="AEGIS-DATA-002",
        title="Mass assignment from request body",
        severity="high",
        confidence="medium",
        cwe="CWE-915",
        owasp="A01:2021 - Broken Access Control",
        languages=("python", "javascript", "typescript", "php", "ruby"),
        why=(
            "Passing the whole request body into a model lets a client set fields you never "
            "meant to expose — `is_admin`, `role`, `credits`, `owner_id`."
        ),
        fix_hint="Explicitly whitelist the mutable fields with a schema.",
        vuln_example="User(**request.json)",
        fix_example=(
            "data = UserSchema.load(request.json)   # only declared fields\n"
            "user = User(full_name=data['full_name'])"
        ),
        patterns=(
            Pattern(
                regex=r"(?:User|Account|Model|\.objects\.create|new\s+\w+)\s*\(\s*(?:\*\*\s*request\.(?:json|form|data)|req\.body\s*\)|\.\.\.\s*req\.body)",
                message="Request body spread into a model constructor.",
            ),
        ),
        tags=("access-control", "validation"),
    ),
    Rule(
        id="AEGIS-VAL-001",
        title="Unvalidated file upload",
        severity="high",
        confidence="medium",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
        languages=("python", "javascript", "typescript", "php", "java", "ruby"),
        why=(
            "Saving an upload without checking its type or name can drop a `.php`/`.jsp` "
            "webshell into the web root, or traverse out of the upload folder via `../`."
        ),
        fix_hint="Validate extension + magic bytes, randomise the stored name, store outside the webroot.",
        vuln_example='f.save(os.path.join(UPLOAD_DIR, f.filename))',
        fix_example=(
            "name = secure_filename(f.filename)\n"
            "if not allowed_type(f): abort(400)\n"
            "f.save(os.path.join(UPLOAD_DIR, uuid4().hex))\n"
            "# serve from a separate origin / with Content-Disposition: attachment"
        ),
        patterns=(
            Pattern(
                regex=r"\.save\s*\(\s*(?:os\.path\.join\s*\([^)]*filename|.*filename\s*\)|[\w.]*\.filename\s*\()",
                message="File saved using the client-supplied filename.",
                not_if=(r"secure_filename|uuid|hash|sanitiz",),
            ),
        ),
        tags=("upload", "filesystem"),
    ),
    Rule(
        id="AEGIS-VAL-002",
        title="Zip extraction without path validation",
        severity="high",
        confidence="high",
        cwe="CWE-409",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python", "javascript", "java", "php", "ruby", "go"),
        why=(
            "A crafted archive can contain `../../.ssh/authorized_keys` (zip-slip) or thousands "
            "of nested entries (zip bomb), overwriting files anywhere the process can write."
        ),
        fix_hint="Validate each member resolves inside the target directory and cap total size.",
        vuln_example="zipfile.ZipFile(path).extractall(dest)",
        fix_example=(
            "for m in zf.infolist():\n"
            "    t = (dest / m.filename).resolve()\n"
            "    if not t.is_relative_to(dest.resolve()): raise BadZipFile\n"
            "    zf.extract(m, dest)"
        ),
        patterns=(
            Pattern(
                regex=r"\.extractall\s*\(|tarfile\.open[^)]*\)\.extract|unzip\s+\S+\s+-d\s+/",
                message="Archive extracted without entry validation.",
                not_if=(r"is_relative_to|sanitiz|validate|commonpath|realpath",),
            ),
        ),
        tags=("filesystem", "upload"),
    ),
    Rule(
        id="AEGIS-VAL-003",
        title="XML parsing with external entities enabled",
        severity="high",
        confidence="medium",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python", "java", "php", "ruby"),
        why="XXE can read local files, reach internal services (SSRF) and, with parameter entities, exfiltrate them.",
        fix_hint="Use `defusedxml` or explicitly disable DTDs and external entities.",
        vuln_example="root = ET.fromstring(request.data)",
        fix_example="from defusedxml import ElementTree as ET\nroot = ET.fromstring(request.data)",
        patterns=(
            Pattern(
                regex=r"\b(?:ET|ElementTree|minidom|lxml\.etree|xml\.sax)\b[^\n]*(?:parse|fromstring)\s*\(",
                message="Standard XML parser used on untrusted input (XXE risk).",
                not_if=(r"defusedxml|resolve_entities\s*=\s*False|no_network|FEATURE_SECURE",),
            ),
        ),
        tags=("xml", "ssrf"),
    ),
    Rule(
        id="AEGIS-SSRF-001",
        title="Server-side request forgery",
        severity="high",
        confidence="medium",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go"),
        why=(
            "Fetching a URL supplied by the user lets an attacker reach internal services "
            "(169.254.169.254 cloud metadata, Redis, admin panels) from inside your network."
        ),
        fix_hint="Allowlist schemes/hosts, block private IP ranges, disable redirects.",
        vuln_example="requests.get(request.args['url'], timeout=5)",
        fix_example=(
            "if urlparse(url).hostname not in ALLOWED_HOSTS: abort(400)\n"
            "requests.get(url, timeout=5, allow_redirects=False)"
        ),
        patterns=(
            Pattern(
                regex=r"(?:requests\.(?:get|post|put)|httpx\.\w+|urllib\.request\.urlopen|axios\.\w+|fetch|http\.get|Net::HTTP)\s*\(\s*(?:request\.|req\.|params\[|\$_|\$url|url\s*[,)])",
                message="Outbound request to a user-supplied URL.",
                not_if=(r"allowlist|whitelist|ALLOWED|validate_url|ALLOWED_HOSTS|is_safe",),
            ),
        ),
        confidence_without_trace="low",
        tags=("ssrf", "network"),
    ),

    # =====================================================================
    # C / C++
    # =====================================================================
    Rule(
        id="AEGIS-MEM-001",
        title="Unbounded string copy (buffer overflow)",
        severity="critical",
        confidence="medium",
        cwe="CWE-120",
        owasp="A06:2021 - Vulnerable and Outdated Components",
        languages=("c", "cpp"),
        why=(
            "`strcpy`/`strcat`/`sprintf`/`gets` write as much data as the source holds, with no "
            "knowledge of the destination size. A longer input smashes the stack, corrupting "
            "the return address — the classic route to code execution."
        ),
        fix_hint="Use the bounded variants and check the return value.",
        vuln_example="strcpy(buf, user_input);",
        fix_example=(
            'if (snprintf(buf, sizeof buf, "%s", user_input) >= (int)sizeof buf)\n'
            "    return -1;   /* truncated */"
        ),
        patterns=(
            Pattern(
                regex=r"\b(?:strcpy|strcat|sprintf|vsprintf|gets|stpcpy|wcscpy)\s*\(",
                message="Unbounded C string function.",
            ),
        ),
        references=("https://cwe.mitre.org/data/definitions/120.html",),
        tags=("memory", "cpp"),
    ),
    Rule(
        id="AEGIS-MEM-002",
        title="Format string vulnerability",
        severity="high",
        confidence="medium",
        cwe="CWE-134",
        owasp="A03:2021 - Injection",
        languages=("c", "cpp"),
        why="Passing user data as the format string lets `%n`/`%s` read and write arbitrary memory.",
        fix_hint='Always use a literal format: printf("%s", user).',
        vuln_example="printf(user_input);",
        fix_example='printf("%s", user_input);',
        patterns=(
            Pattern(
                regex=r"\b(?:printf|fprintf|syslog|snprintf)\s*\(\s*(?:[A-Za-z_]\w*|argv\[\d+\])\s*\)",
                message="Variable used directly as a format string.",
                not_if=(r"[\"']",),
            ),
        ),
        tags=("memory", "cpp"),
    ),
    Rule(
        id="AEGIS-MEM-003",
        title="Use of `system()` / `popen()`",
        severity="high",
        confidence="high",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        languages=("c", "cpp"),
        why="Shell invocation from C inherits the full shell grammar; any interpolated value is an injection point.",
        fix_hint="Use `execve`/`posix_spawn` with an argv array.",
        vuln_example='system("ping -c1 " );  /* + user host */',
        fix_example='char *argv[] = {"ping", "-c1", host, NULL};\nposix_spawn(&pid, "/bin/ping", NULL, NULL, argv, environ);',
        patterns=(
            Pattern(regex=r"\b(?:system|popen)\s*\(", message="Shell command executed from native code."),
        ),
        tags=("memory", "injection"),
    ),
    Rule(
        id="AEGIS-MEM-004",
        title="Unsafe memory allocation size",
        severity="high",
        confidence="medium",
        cwe="CWE-190",
        owasp="A04:2021 - Insecure Design",
        languages=("c", "cpp"),
        why="`malloc(n * size)` can overflow to a small number, after which the copy writes out of bounds (heap overflow).",
        fix_hint="Use `calloc` or check for overflow before multiplying.",
        vuln_example="char *p = malloc(count * sizeof(*p));",
        fix_example="if (count > SIZE_MAX / sizeof(*p)) return NULL;\nchar *p = calloc(count, sizeof(*p));",
        patterns=(
            Pattern(
                regex=r"\bmalloc\s*\([^;]*\*\s*(?:sizeof|len|count|n)",
                message="Multiplication inside malloc can overflow.",
            ),
        ),
        tags=("memory", "integer"),
    ),

    # =====================================================================
    # JAVA / JVM
    # =====================================================================
    Rule(
        id="AEGIS-JAVA-001",
        title="Insecure Java deserialization",
        severity="critical",
        confidence="high",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
        languages=("java", "kotlin"),
        why="`ObjectInputStream.readObject` on untrusted bytes is the root of most Java RCE gadget chains (Commons Collections, etc.).",
        fix_hint="Use a serialization filter (`ObjectInputFilter`) or switch to JSON with an allowlist.",
        vuln_example="new ObjectInputStream(in).readObject();",
        fix_example='ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.app.dto.*;!*"));\nObject o = ois.readObject();',
        patterns=(
            Pattern(
                regex=r"new\s+ObjectInputStream|\.readObject\s*\(\s*\)",
                message="Java native deserialization of a stream.",
                not_if=(r"ObjectInputFilter|filter",),
            ),
        ),
        tags=("deserialization", "java"),
    ),
    Rule(
        id="AEGIS-JAVA-002",
        title="XML parser XXE exposure",
        severity="high",
        confidence="medium",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("java", "kotlin"),
        why="Default `DocumentBuilderFactory` resolves external entities, allowing file disclosure and SSRF.",
        fix_hint='Disable `http://apache.org/xml/features/disallow-doctype-decl`.',
        vuln_example="DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(input);",
        fix_example=(
            "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'
        ),
        patterns=(
            Pattern(
                regex=r"DocumentBuilderFactory\.newInstance\s*\(|SAXParserFactory\.newInstance\s*\(",
                message="XML factory created without hardening.",
                not_if=(r"disallow-doctype-decl|setFeature|SECURE_PROCESSING",),
            ),
        ),
        tags=("xml", "java"),
    ),
    Rule(
        id="AEGIS-JAVA-003",
        title="Expression language injection",
        severity="critical",
        confidence="medium",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
        languages=("java", "kotlin"),
        why="Evaluating user text through SpEL/OGNL/UEL grants code execution inside the JVM.",
        fix_hint="Never evaluate user input as an expression; map to a fixed set of operations.",
        vuln_example='parser.parseExpression(request.getParameter("exp")).getValue();',
        fix_example="switch (op) {\n  case \"add\": return a + b;\n  default: throw new IllegalArgumentException();\n}",
        patterns=(
            Pattern(
                regex=r"parseExpression\s*\(|Ognl\.\w+|MVEL\.eval",
                message="Expression parsed from a runtime string.",
            ),
        ),
        tags=("injection", "java"),
    ),

    # =====================================================================
    # PHP / RUBY / GO / C#
    # =====================================================================
    Rule(
        id="AEGIS-PHP-001",
        title="PHP code execution sink",
        severity="critical",
        confidence="high",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        languages=("php",),
        why="`eval`, `assert`, `create_function` and `preg_replace /e` execute arbitrary PHP from a string.",
        fix_hint="Remove dynamic evaluation; use a whitelist dispatch table.",
        vuln_example="eval('$x = ' . $_GET['expr'] . ';');",
        fix_example="$allowed = ['inc' => fn($v) => $v + 1];\nreturn $allowed[$_GET['op']]($value);",
        patterns=(
            Pattern(
                regex=r"\b(?:eval|create_function)\s*\(|preg_replace\s*\([^)]*/e|assert\s*\(\s*\$",
                message="Dynamic PHP evaluation.",
            ),
        ),
        tags=("injection", "php"),
    ),
    Rule(
        id="AEGIS-PHP-002",
        title="PHP file inclusion from input",
        severity="critical",
        confidence="high",
        cwe="CWE-98",
        owasp="A03:2021 - Injection",
        languages=("php",),
        why="Including a path derived from input allows Local/Remote File Inclusion — reading `/etc/passwd` or executing a remote shell.",
        fix_hint="Map a key to a fixed file; never build an include path from user data.",
        vuln_example='include $_GET["page"] . ".php";',
        fix_example="$pages = ['home' => 'home.php'];\ninclude $pages[$_GET['page']] ?? 'home.php';",
        patterns=(
            Pattern(
                regex=r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$",
                message="Include path derived from a variable.",
                not_if=(r"__DIR__|dirname|#",),
            ),
        ),
        tags=("injection", "php"),
    ),
    Rule(
        id="AEGIS-RB-001",
        title="Ruby command execution / mass assignment",
        severity="high",
        confidence="high",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        languages=("ruby",),
        why="Backtick strings, `system`, `%x`, and `eval` execute code; `params.permit!` disables strong parameters.",
        fix_hint="Use array-form `system` and explicit `permit(:a, :b)`.",
        vuln_example="`convert #{params[:file]}`",
        fix_example='system("convert", params[:file])',
        patterns=(
            Pattern(regex=r"`[^`]*#\{", message="Backtick shell with interpolation."),
            Pattern(regex=r"\b(?:eval|instance_eval|class_eval)\s*\(", message="Ruby eval of a runtime string."),
            Pattern(regex=r"params\.permit!", message="Strong parameters bypassed."),
        ),
        tags=("injection", "ruby"),
    ),
    Rule(
        id="AEGIS-GO-001",
        title="Ignored error and unchecked input in Go",
        severity="medium",
        confidence="low",
        cwe="CWE-703",
        owasp="A04:2021 - Insecure Design",
        languages=("go",),
        why="Dropping errors from DB/file operations hides failures and can leave partially-initialised state that later checks trust.",
        fix_hint="Handle or explicitly log every returned error.",
        vuln_example="_ = json.NewDecoder(r.Body).Decode(&u)",
        fix_example="if err := json.NewDecoder(r.Body).Decode(&u); err != nil {\n    http.Error(w, \"bad request\", 400)\n    return\n}",
        patterns=(
            Pattern(
                regex=r"_\s*=\s*(?:json\.NewDecoder|db\.\w+|os\.\w+|exec\.Command)",
                message="Error from a security-relevant call discarded.",
            ),
        ),
        tags=("robustness", "go"),
    ),

    # =====================================================================
    # JS / NODE SPECIFIC
    # =====================================================================
    Rule(
        id="AEGIS-JS-001",
        title="Node child_process with shell",
        severity="critical",
        confidence="high",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        languages=("javascript", "typescript"),
        why="`exec`/`execSync` run through `/bin/sh`, so metacharacters in interpolated values run as commands.",
        fix_hint="Use `execFile`/`spawn` with an argv array.",
        vuln_example='exec(`tar -czf out.tgz ${dir}`);',
        fix_example='execFile("tar", ["-czf", "out.tgz", dir], { timeout: 5000 });',
        patterns=(
            Pattern(
                regex=r"child_process[\"']?\)?[^\n]*\.(?:exec|execSync)\s*\(|(?<![\w.])exec(?:Sync)?\s*\(\s*(?:`|[\"'][^\"']*[\"']\s*\+)",
                message="Shell command built from a runtime string.",
                not_if=(r"execFile|spawn|#|//",),
            ),
        ),
        tags=("injection", "node"),
    ),
    Rule(
        id="AEGIS-JS-002",
        title="Prototype pollution sink",
        severity="high",
        confidence="medium",
        cwe="CWE-1321",
        owasp="A08:2021 - Software and Data Integrity Failures",
        languages=("javascript", "typescript"),
        why="Deep-merging attacker JSON can write to `Object.prototype`, altering behaviour of every object in the process.",
        fix_hint="Reject `__proto__`/`constructor`/`prototype` keys and use `Object.create(null)`.",
        vuln_example="Object.assign(target, req.body);",
        fix_example="if (['__proto__','constructor','prototype'].some(k => k in body)) throw new Error('bad key');",
        patterns=(
            Pattern(
                regex=r"(?:Object\.assign|_\.merge|_\.defaultsDeep|lodash\.merge)\s*\(\s*\w+\s*,\s*(?:req\.body|request\.body|JSON\.parse)",
                message="Untrusted object deep-merged without key filtering.",
            ),
        ),
        tags=("validation", "node"),
    ),
    Rule(
        id="AEGIS-JS-003",
        title="Cookie/session weakness",
        severity="medium",
        confidence="medium",
        cwe="CWE-1004",
        owasp="A07:2021 - Identification and Authentication Failures",
        languages=("javascript", "typescript"),
        why="A cookie without `httpOnly`/`secure`/`sameSite` can be read by injected script or sent over cleartext and cross-site requests.",
        fix_hint="Set httpOnly: true, secure: true, sameSite: 'strict'.",
        vuln_example="res.cookie('sid', token, { });",
        fix_example="res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 900000 });",
        patterns=(
            Pattern(
                regex=r"\.cookie\s*\(\s*[\"'][^\"']+[\"']",
                message="Cookie set without reviewing security flags.",
                not_if=(r"httpOnly|http_only|#|//",),
            ),
            Pattern(
                regex=r"httpOnly\s*:\s*false|secure\s*:\s*false",
                message="Cookie security flag explicitly disabled.",
            ),
        ),
        tags=("session", "node"),
    ),
    Rule(
        id="AEGIS-REGEX-001",
        title="Catastrophic backtracking (ReDoS)",
        severity="medium",
        confidence="low",
        cwe="CWE-1333",
        owasp="A05:2021 - Security Misconfiguration",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go"),
        why="Nested quantifiers like `(a+)+$` match in exponential time, so a short crafted string can pin a CPU core.",
        fix_hint="Anchor and bound the pattern; use a RE2-based engine for untrusted input.",
        vuln_example="re.match(r'^(\\w+\\s?)*$', user_input)",
        fix_example="re.match(r'^\\w{1,64}$', user_input)   # bounded, no nesting",
        patterns=(
            Pattern(
                regex=r"\([^()\n]*[+*][^()\n]*\)\s*[+*]",
                message="Nested quantifier — potential exponential backtracking.",
                not_if=(r"#|//",),
            ),
        ),
        inspect_strings=True,
        tags=("dos",),
    ),
    Rule(
        id="AEGIS-DEPS-001",
        title="Unpinned / wildcard dependency",
        severity="low",
        confidence="medium",
        cwe="CWE-1104",
        owasp="A06:2021 - Vulnerable and Outdated Components",
        languages=("python", "javascript", "typescript", "ruby", "php", "go"),
        why="`*`/latest ranges make builds non-reproducible and silently pull in unreviewed versions.",
        fix_hint="Pin exact or `~=` versions and enable a dependency scanner.",
        vuln_example="requests\nflask>=2",
        fix_example="requests==2.32.3\nflask==3.0.3",
        patterns=(
            Pattern(
                regex=r"[\"'](?:[\w@/.-]+)[\"']\s*:\s*[\"'](?:\*|latest)[\"']",
                message="Wildcard version range in a dependency manifest.",
                not_if=(r"private|workspace|devDependencies.*\*",),
            ),
        ),
        inspect_strings=True,
        tags=("supply-chain",),
        # only checked in manifests; the analyzer gates on filename
    ),

    Rule(
        id="AEGIS-SECRET-001",
        title="High-entropy secret literal detected",
        severity="critical",
        confidence="medium",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        languages=("python", "javascript", "typescript", "java", "php", "ruby", "go",
                   "csharp", "kotlin", "swift", "rust", "yaml", "json", "toml", "ini", "env",
                   "shell", "html", "vue", "terraform", "c", "cpp"),
        why=(
            "This value has the statistical signature of a machine-generated credential: "
            "high Shannon entropy (near-random character distribution) bound to a "
            "secret-like identifier. That combination is almost never a coincidence — "
            "and once committed, the key is in every clone, fork and CI log."
        ),
        fix_hint="Move it to a secret store, rotate the value, and add a pre-commit secret scan.",
        vuln_example='STRIPE_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY"',
        fix_example='STRIPE_KEY = os.environ["STRIPE_KEY"]   # injected by the platform',
        patterns=(),
        references=("https://cwe.mitre.org/data/definitions/798.html",),
        tags=("secrets", "entropy"),
        inspect_strings=True,
    ),
)


# Filenames that should never carry a "dependency pin" finding
MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "pipfile",
    "gemfile", "composer.json", "go.mod",
}

# Rule ids that only make sense inside manifest files
MANIFEST_ONLY_RULES = {"AEGIS-DEPS-001"}

# Rule ids skipped entirely inside test fixtures (they intentionally contain bad code)
TEST_RELAXED_RULES = {
    "AEGIS-AUTH-002",   # hardcoded creds
    "AEGIS-CRYPTO-003", # static keys
    "AEGIS-CONF-006",   # flask secret key
}

RULE_BY_ID = {rule.id: rule for rule in RULES}
