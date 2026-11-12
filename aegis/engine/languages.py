"""Language detection and per-language lexing rules."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

EXT_MAP: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".rs": "rust",
    ".scala": "scala",
    ".sql": "sql",
    ".sh": "shell", ".bash": "shell",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini",
    ".env": "env",
    ".html": "html", ".htm": "html",
    ".vue": "vue",
    ".tf": "terraform",
}

LANGUAGE_LABELS: dict[str, str] = {
    "python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
    "java": "Java", "c": "C", "cpp": "C++", "csharp": "C#", "php": "PHP",
    "ruby": "Ruby", "go": "Go", "kotlin": "Kotlin", "swift": "Swift",
    "rust": "Rust", "scala": "Scala", "sql": "SQL", "shell": "Shell",
    "yaml": "YAML", "json": "JSON", "toml": "TOML", "ini": "INI", "env": "Dotenv",
    "html": "HTML", "vue": "Vue", "terraform": "Terraform", "unknown": "Unknown",
}

# Languages where the engine has real rule coverage (used for the UI stat)
SUPPORTED = {
    "python", "javascript", "typescript", "java", "c", "cpp", "csharp", "php",
    "ruby", "go", "kotlin", "swift", "rust", "shell", "yaml", "json", "toml",
    "ini", "env", "html", "vue", "terraform",
}

# Directories that are noise, not signal.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "out", "target", "vendor", "site-packages", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".next", ".nuxt", "coverage", ".idea", ".vscode",
    "bower_components", ".tox", ".gradle", "Pods", ".terraform",
}

# Files whose *name* implies test/example content.
TEST_PATTERNS = re.compile(
    # a directory that means "tests live here"
    r"(^|/)(?:tests?|specs?|__tests__|__mocks__|testing|fixtures?)(/|$)"
    # or a filename that means it
    r"|(^|/)(?:test_[^/]+\.py|conftest\.py|[^/]*_test\.go|test_[^/]+\.go)$"
    r"|\.(?:test|spec)\.[jt]sx?$"
    # or a fixture/demo stem
    r"|(^|[._-])(?:fixture|fixtures|mock|mocks|vulnerable)([._-]|$)",
    re.IGNORECASE,
)

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
    ".gz", ".tar", ".bz2", ".7z", ".lock", ".pyc", ".so", ".dylib", ".dll",
    ".exe", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav", ".map",
    ".min.js", ".min.css", ".db", ".sqlite",
}

MAX_FILE_BYTES = 1_500_000


@dataclass(frozen=True)
class LanguageSpec:
    name: str
    line_comments: tuple[str, ...]
    block_comment: tuple[str, str] | None
    string_delims: tuple[str, ...]


SPECS: dict[str, LanguageSpec] = {
    "python": LanguageSpec("python", ("#",), None, ('"""', "'''", '"', "'")),
    "javascript": LanguageSpec("javascript", ("//",), ("/*", "*/"), ('"', "'", "`")),
    "typescript": LanguageSpec("typescript", ("//",), ("/*", "*/"), ('"', "'", "`")),
    "java": LanguageSpec("java", ("//",), ("/*", "*/"), ('"', "'")),
    "c": LanguageSpec("c", ("//",), ("/*", "*/"), ('"', "'")),
    "cpp": LanguageSpec("cpp", ("//",), ("/*", "*/"), ('"', "'")),
    "csharp": LanguageSpec("csharp", ("//",), ("/*", "*/"), ('"', "'")),
    "php": LanguageSpec("php", ("//", "#"), ("/*", "*/"), ('"', "'")),
    "ruby": LanguageSpec("ruby", ("#",), None, ('"', "'")),
    "go": LanguageSpec("go", ("//",), ("/*", "*/"), ('"', "'", "`")),
    "kotlin": LanguageSpec("kotlin", ("//",), ("/*", "*/"), ('"', "'")),
    "swift": LanguageSpec("swift", ("//",), ("/*", "*/"), ('"', "'")),
    "rust": LanguageSpec("rust", ("//",), ("/*", "*/"), ('"', "'")),
    "shell": LanguageSpec("shell", ("#",), None, ('"', "'")),
    "yaml": LanguageSpec("yaml", ("#",), None, ('"', "'")),
    "sql": LanguageSpec("sql", ("--",), ("/*", "*/"), ("'", '"')),
    "html": LanguageSpec("html", (), ("<!--", "-->"), ('"', "'")),
    "vue": LanguageSpec("vue", ("//",), ("/*", "*/"), ('"', "'", "`")),
}
DEFAULT_SPEC = LanguageSpec("unknown", ("#", "//"), ("/*", "*/"), ('"', "'"))


def detect_language(path: str, content_first_kb: str = "") -> str:
    base = os.path.basename(path).lower()
    if base == "dockerfile" or base.startswith("dockerfile."):
        return "shell"
    if base in {"makefile", "gemfile", "rakefile", "procfile"}:
        return "shell"
    if base.startswith(".env") or base.endswith(".env") or base == ".env.example":
        return "env"
    if base in {"package.json", "composer.json", "tsconfig.json"}:
        return "json"
    if base in {"requirements.txt", "constraints.txt", "pipfile.lock"}:
        return "python"
    _, ext = os.path.splitext(base)
    if ext in EXT_MAP:
        return EXT_MAP[ext]
    # shebang fallback
    first = content_first_kb.lstrip()
    if first.startswith("#!"):
        line = first.splitlines()[0].lower()
        if "python" in line:
            return "python"
        if "node" in line:
            return "javascript"
        if "ruby" in line:
            return "ruby"
        if "bash" in line or "/sh" in line:
            return "shell"
    return "unknown"


def get_spec(language: str) -> LanguageSpec:
    return SPECS.get(language, DEFAULT_SPEC)


def is_skipped_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".") and name not in {".env"}


def is_binary_name(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in BINARY_EXT)


# Paths that exist to demonstrate or exercise vulnerabilities.
SAMPLE_PATTERNS = re.compile(
    r"(^|/)(samples?|fixtures?|examples?|demo|demos|testdata|test_data|"
    r"vulnerable[-_]?app|insecure)(/|$)",
    re.IGNORECASE,
)


def is_sample_path(path: str) -> bool:
    return bool(SAMPLE_PATTERNS.search(path.replace("\\", "/")))


def is_test_path(path: str) -> bool:
    return bool(TEST_PATTERNS.search(path.replace("\\", "/")))
