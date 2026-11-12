"""
Clone a remote repository for analysis — carefully.

Cloning an attacker-supplied URL is remote-code-adjacent territory: ``git`` has
transports that execute commands (``ext::``), repositories can contain symlinks
that escape the working tree, and an archive can be arbitrarily large. Every
one of those is closed here rather than trusted:

* **URL allowlist** — only https URLs on known forges are accepted; schemes like
  ``file://``, ``ssh://``, ``ext::`` and ``git://`` are rejected outright, which
  also rules out using the server as an SSRF probe or an internal-host cloner.
* **No prompt** — ``GIT_TERMINAL_PROMPT=0`` so a private repo fails fast instead
  of hanging on a credential prompt.
* **Symlinks disabled** — ``core.symlinks=false`` writes a symlink as a plain
  file containing its target path, so ``link -> /etc/passwd`` cannot be followed
  by the scanner.
* **Hard limits** — shallow clone, wall-clock timeout, and a post-clone size and
  file-count cap.
* **No shell** — argv list only, never ``shell=True``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Forges we are willing to clone from. Extend deliberately.
ALLOWED_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
}

MAX_REPO_MB = 60
MAX_FILES = 12_000
CLONE_TIMEOUT_S = 90

_REPO_PATH = re.compile(r"^/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


class RepoError(ValueError):
    """A repository URL that we refuse to fetch, with a user-facing reason."""


@dataclass
class RepoInfo:
    url: str
    host: str
    owner: str
    name: str
    path: Path
    size_mb: float
    files: int

    @property
    def label(self) -> str:
        return f"{self.host}/{self.owner}/{self.name}"


def parse_repo_url(url: str) -> tuple[str, str, str]:
    """Validate a repository URL and return (host, owner, name)."""
    raw = (url or "").strip()
    if not raw:
        raise RepoError("A repository URL is required")

    if "://" not in raw:
        raw = "https://" + raw  # bare "github.com/owner/repo"

    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise RepoError(
            f"Only https:// repository URLs are supported (got '{parsed.scheme}')."
        )
    if parsed.username or parsed.password:
        raise RepoError("Credentials in the URL are not accepted; use a server-side token.")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        allowed = ", ".join(sorted(ALLOWED_HOSTS))
        raise RepoError(f"Unsupported host '{host}'. Allowed: {allowed}.")
    if parsed.port not in (None, 443):
        raise RepoError("Non-standard ports are not supported.")

    m = _REPO_PATH.match(parsed.path)
    if not m:
        raise RepoError("Expected a URL like https://github.com/owner/repository")
    owner, name = m.group(1), m.group(2)
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        raise RepoError("Expected a URL like https://github.com/owner/repository")
    return host, owner, name


def _dir_size_mb(path: Path) -> float:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
    return round(total / (1024 * 1024), 2)


def _count_files(path: Path) -> int:
    n = 0
    for _root, _dirs, files in os.walk(path):
        n += len(files)
        if n > MAX_FILES:
            return n
    return n


def clone(url: str, *, workdir: Path | None = None) -> RepoInfo:
    """Shallow-clone a validated repository into a temporary directory.

    The caller owns ``RepoInfo.path`` and is responsible for removing it
    (``shutil.rmtree(info.path.parent)``); ``cleanup()`` does this for you.
    """
    host, owner, name = parse_repo_url(url)
    target_parent = Path(workdir or tempfile.mkdtemp(prefix="aegis_repo_"))
    dest = target_parent / "repo"

    argv = [
        "git",
        "-c", "core.symlinks=false",       # symlink escape guard
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.ext.allow=never",  # no ext:: command transport
        "-c", "protocol.file.allow=never", # no local path transport
        "-c", "advice.detachedHead=false",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--quiet",
        f"https://{host}/{owner}/{name}.git",
        str(dest),
    ]

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",      # never block on credentials
        "GIT_ASKPASS": "/bin/echo",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(target_parent),      # no user gitconfig
        "LC_ALL": "C",
    }
    # Optional server-side token for private repositories (never from user input)
    token = os.environ.get("AEGIS_GIT_TOKEN")
    if token:
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = f"url.https://x-access-token:{token}@{host}/.insteadOf"
        env["GIT_CONFIG_VALUE_0"] = f"https://{host}/"

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_S,
            env=env,
            cwd=str(target_parent),
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(target_parent, ignore_errors=True)
        raise RepoError(
            f"Clone timed out after {CLONE_TIMEOUT_S}s. The repository may be too large."
        ) from None
    except FileNotFoundError:
        shutil.rmtree(target_parent, ignore_errors=True)
        raise RepoError("git is not installed on this server.") from None

    if proc.returncode != 0:
        shutil.rmtree(target_parent, ignore_errors=True)
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else "unknown error"
        # keep remote errors short and free of URLs with embedded credentials
        reason = re.sub(r"https://[^@\s]*@", "https://", reason)[:200]
        raise RepoError(f"Could not clone repository: {reason}")

    # Drop the git database before scanning: we analyse a snapshot of the working
    # tree, not packfiles, and this reclaims most of the footprint.
    shutil.rmtree(dest / ".git", ignore_errors=True)

    size_mb = _dir_size_mb(dest)
    if size_mb > MAX_REPO_MB:
        shutil.rmtree(target_parent, ignore_errors=True)
        raise RepoError(
            f"Repository is {size_mb} MB after clone; the limit is {MAX_REPO_MB} MB."
        )
    files = _count_files(dest)
    if files > MAX_FILES:
        shutil.rmtree(target_parent, ignore_errors=True)
        raise RepoError(
            f"Repository contains more than {MAX_FILES} files; the limit is {MAX_FILES}."
        )

    return RepoInfo(
        url=f"https://{host}/{owner}/{name}",
        host=host,
        owner=owner,
        name=name,
        path=dest,
        size_mb=size_mb,
        files=files,
    )


def cleanup(info: RepoInfo) -> None:
    """Remove the clone's temporary parent directory."""
    shutil.rmtree(info.path.parent, ignore_errors=True)
