"""
Sanitizer detection — the difference between an analyzer and a regex scanner.

A call to ``eval``/``exec``/``os.system`` is not a vulnerability, it is a *sink*.
It becomes a vulnerability when an untrusted value reaches it. Libraries wrap
exactly these sinks for legitimate reasons and sanitise the input first:

    eval(compile(f.read(), path, "exec"), ns)   # runs *local* config files

Firing on the sink alone produces confident-sounding noise on every CLI and
plugin loader in the ecosystem, which is how security tools get switched off.

So: when a sink's arguments can be traced to a sanitising operation, the finding
is reported at reduced confidence (``low``) instead of being dropped — the code
still deserves a look, but it is not presented as a confirmed vulnerability.
"""

from __future__ import annotations

import re

# Calls that make their result safe for a given sink class.
SANITIZERS: dict[str, tuple[str, ...]] = {
    # dynamic code execution
    "AEGIS-CODE-001": (
        r"\bcompile\s*\(",          # compile() of a local, fixed file
        r"literal_eval\s*\(",
        r"\bast\.parse\s*\(",
        r"\bglobals\s*\(\s*\)",     # explicit namespace
        r"\.read\s*\(",             # reading from a path we control
        # exec/eval of an already-compiled code object cannot run new source
        r"\b(?:eval|exec)\s*\(\s*(?:code|code_obj|codeobject|code_object|compiled|bytecode|co)\b",
        # an attribute that holds a compiled code object
        r"\b(?:eval|exec)\s*\(\s*self\.\w*code\w*\s*[,)]",
        r"\b(?:eval|exec)\s*\(\s*\w+\.(?:f_code|co_code)\b",
    ),
    # shell
    "AEGIS-CMDI-001": (
        r"shlex\.quote\s*\(",
        r"pipes\.quote\s*\(",
        r"\bescape\s*\(",
        r"shell\s*=\s*False",
    ),
    # SQL
    "AEGIS-SQLI-001": (
        r"quote\s*\(",
        r"escape_string\s*\(",
        r"real_escape_string\s*\(",
        r"bindparam\s*\(",
    ),
    # HTML
    "AEGIS-XSS-001": (
        r"DOMPurify\.sanitize\s*\(",
        r"\besc\s*\(",
        r"escapeHtml\s*\(",
        r"encodeURIComponent\s*\(",
        r"textContent\s*=",
    ),
    # filesystem
    "AEGIS-PATH-001": (
        r"secure_filename\s*\(",
        r"is_relative_to\s*\(",
        r"commonpath\s*\(",
        r"realpath\s*\(",
        r"\.resolve\s*\(\s*\)",
        r"basename\s*\(",
    ),
}


def is_sanitized(rule_id: str, argument_text: str) -> bool:
    """True when the sink's arguments pass through a known sanitising call."""
    patterns = SANITIZERS.get(rule_id)
    if not patterns:
        return False
    return any(re.search(p, argument_text) for p in patterns)


# Files that are documentation, examples or vendored/third-party code. These
# carry vulnerabilities we cannot fix and did not write.
NON_SHIPPED_DIRS = re.compile(
    r"(^|/)(?:docs?|examples?|benchmarks?|scripts|contrib|third[_-]?party|vendor"
    r"|_vendor|site-packages)(/|$)",
    re.IGNORECASE,
)
