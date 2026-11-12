"""Baseline files: accept the findings you already have, so a gate only fails
on what is new.

The hard part of adopting a scanner on an existing codebase is not finding the
bugs, it is the 400 findings you inherit on day one. A baseline records the
fingerprints you have triaged as known, and every gate then evaluates only the
delta. Fingerprints are ``rule + path + normalised code``, so a baselined
finding keeps its identity when lines move or surrounding code is edited.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASELINE_VERSION = 1


class BaselineError(ValueError):
    """Raised when a baseline file cannot be read or is not a baseline."""


@dataclass
class BaselineEntry:
    """One accepted finding, keyed by fingerprint."""

    fingerprint: str
    rule_id: str
    file: str
    line: int
    title: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "title": self.title,
            "reason": self.reason,
        }


@dataclass
class BaselineFile:
    entries: dict[str, BaselineEntry]
    created: str = ""
    tool_version: str = "2.0.0"
    source: str = ""

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self.entries

    # -- construction ------------------------------------------------------
    @classmethod
    def from_result(cls, result: Any, source: str = "", min_severity: str = "low",
                    reason: str = "") -> "BaselineFile":
        """Snapshot every finding at or above ``min_severity``."""
        order = ["critical", "high", "medium", "low", "info"]
        floor = order.index(min_severity) if min_severity in order else order.index("low")
        entries: dict[str, BaselineEntry] = {}
        for f in result.findings:
            if order.index(f.severity) > floor:
                continue
            entries[f.fingerprint] = BaselineEntry(
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                file=f.file,
                line=f.line,
                title=f.title,
                reason=reason,
            )
        return cls(entries=entries, source=source)

    # -- io ----------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": BASELINE_VERSION,
            "tool": "aegisreview",
            "tool_version": self.tool_version,
            "created": self.created or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": self.source,
            "count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries.values()],
        }

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> "BaselineFile":
        p = Path(path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise BaselineError(f"baseline not found: {p}") from None
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"cannot read baseline {p}: {exc}") from None

        if not isinstance(raw, dict) or "entries" not in raw:
            raise BaselineError(
                f"{p} is not an AegisReview baseline (no 'entries' key)"
            )
        version = raw.get("version")
        if version != BASELINE_VERSION:
            raise BaselineError(
                f"{p} has baseline version {version!r}; this build understands {BASELINE_VERSION}"
            )

        entries: dict[str, BaselineEntry] = {}
        for item in raw.get("entries") or []:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("fingerprint") or "")
            if not fp:
                continue
            entries[fp] = BaselineEntry(
                fingerprint=fp,
                rule_id=str(item.get("rule_id", "")),
                file=str(item.get("file", "")),
                line=int(item.get("line") or 0),
                title=str(item.get("title", "")),
                reason=str(item.get("reason", "")),
            )
        return cls(
            entries=entries,
            created=str(raw.get("created", "")),
            tool_version=str(raw.get("tool_version", "")),
            source=str(raw.get("source", "")),
        )


def apply_baseline(findings: list[Any], baseline: BaselineFile) -> tuple[list[Any], list[Any]]:
    """Split findings into ``(new, baselined)`` preserving order."""
    new, known = [], []
    for f in findings:
        (known if f.fingerprint in baseline else new).append(f)
    return new, known
