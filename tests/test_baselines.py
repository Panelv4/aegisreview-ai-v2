"""Baseline files: the accept-what-you-have workflow."""

import json

import pytest

from aegis.engine.analyzer import analyze_source, scan_path
from aegis.engine.baselines import (
    BASELINE_VERSION,
    BaselineEntry,
    BaselineError,
    BaselineFile,
    apply_baseline,
)

SNIPPET = "import os\n\ndef f(cmd):\n    os.system(cmd)\n"


@pytest.fixture()
def result():
    return analyze_source(SNIPPET, "app/run.py")


class TestBaselineFile:
    def test_snapshot_captures_every_finding(self, result):
        bl = BaselineFile.from_result(result, source="demo")
        assert len(bl) == len(result.findings)
        assert all(f.fingerprint in bl for f in result.findings)

    def test_min_severity_filters(self, result):
        crit_only = BaselineFile.from_result(result, min_severity="critical")
        assert len(crit_only) == sum(1 for f in result.findings if f.severity == "critical")
        assert len(crit_only) <= len(BaselineFile.from_result(result))

    def test_reason_is_stored(self, result):
        bl = BaselineFile.from_result(result, reason="legacy, SEC-123")
        assert {e.reason for e in bl.entries.values()} == {"legacy, SEC-123"}

    def test_round_trip(self, result, tmp_path):
        path = tmp_path / "b.json"
        BaselineFile.from_result(result, source="demo").save(path)
        loaded = BaselineFile.load(path)
        assert len(loaded) == len(result.findings)
        assert loaded.source == "demo"
        for f in result.findings:
            assert f.fingerprint in loaded

    def test_file_is_reviewable_json(self, result, tmp_path):
        path = tmp_path / "b.json"
        BaselineFile.from_result(result).save(path)
        raw = json.loads(path.read_text())
        assert raw["version"] == BASELINE_VERSION
        assert raw["tool"] == "aegisreview"
        assert raw["count"] == len(raw["entries"])
        assert {"fingerprint", "rule_id", "file", "line"} <= set(raw["entries"][0])

    def test_creates_missing_parent_dirs(self, result, tmp_path):
        path = tmp_path / "nested" / "dir" / "b.json"
        BaselineFile.from_result(result).save(path)
        assert path.exists()

    def test_empty_result_gives_empty_baseline(self, tmp_path):
        clean = analyze_source("x = 1\n", "ok.py")
        bl = BaselineFile.from_result(clean)
        assert len(bl) == 0
        path = tmp_path / "b.json"
        bl.save(path)
        assert BaselineFile.load(path).entries == {}

    def test_duplicate_fingerprints_collapse(self):
        entries = [
            BaselineEntry(fingerprint="abc", rule_id="R", file="a.py", line=1),
            BaselineEntry(fingerprint="abc", rule_id="R", file="a.py", line=2),
        ]
        bl = BaselineFile(entries={e.fingerprint: e for e in entries})
        assert len(bl) == 1


class TestBaselineErrors:
    def test_missing_file(self, tmp_path):
        with pytest.raises(BaselineError, match="not found"):
            BaselineFile.load(tmp_path / "nope.json")

    def test_not_json(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text("this is not json {{{")
        with pytest.raises(BaselineError, match="cannot read baseline"):
            BaselineFile.load(p)

    def test_json_but_not_a_baseline(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text(json.dumps({"findings": []}))
        with pytest.raises(BaselineError, match="not an AegisReview baseline"):
            BaselineFile.load(p)

    def test_future_version_is_rejected_not_ignored(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text(json.dumps({"version": 99, "entries": []}))
        with pytest.raises(BaselineError, match="version 99"):
            BaselineFile.load(p)

    def test_malformed_entries_are_skipped(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text(json.dumps({"version": BASELINE_VERSION, "entries": [
            {"fingerprint": "keepme", "rule_id": "R", "file": "a.py", "line": 3},
            {"rule_id": "no-fingerprint"},
            "not-a-dict",
            {"fingerprint": ""},
        ]}))
        bl = BaselineFile.load(p)
        assert list(bl.entries) == ["keepme"]


class TestApplyBaseline:
    def test_splits_new_from_known(self, result, tmp_path):
        bl = BaselineFile.from_result(result)
        new, known = apply_baseline(result.findings, bl)
        assert new == []
        assert len(known) == len(result.findings)

    def test_unseen_finding_is_new(self, result):
        bl = BaselineFile(entries={})
        new, known = apply_baseline(result.findings, bl)
        assert len(new) == len(result.findings)
        assert known == []

    def test_survives_line_shift(self, tmp_path):
        """A baselined finding stays baselined when lines move above it."""
        before = analyze_source(SNIPPET, "app/run.py")
        bl = BaselineFile.from_result(before)
        after = analyze_source("# pad\n# pad\n# pad\n" + SNIPPET, "app/run.py")
        assert [f.line for f in after.findings] != [f.line for f in before.findings]
        new, known = apply_baseline(after.findings, bl)
        assert new == [], "line shift must not resurrect an accepted finding"
        assert len(known) == len(before.findings)

    def test_edited_code_is_treated_as_new(self):
        """Changing the vulnerable line is a new finding, not the old one."""
        before = analyze_source(SNIPPET, "app/run.py")
        bl = BaselineFile.from_result(before)
        changed = analyze_source("import os\n\ndef f(cmd):\n    os.system('rm ' + cmd)\n", "app/run.py")
        new, _ = apply_baseline(changed.findings, bl)
        assert new, "a rewritten sink should not inherit the waiver"


class TestBaselineEndToEnd:
    def test_write_then_scan_reports_nothing(self, tmp_path, capsys):
        from aegis.__main__ import main

        target = tmp_path / "app"
        target.mkdir()
        (target / "run.py").write_text(SNIPPET)

        baseline = tmp_path / "baseline.json"
        assert main([str(target), "--write-baseline", str(baseline)]) == 0
        assert baseline.exists()

        assert main([str(target), "--baseline", str(baseline),
                     "--max-critical", "0", "--quiet"]) == 0
        out = capsys.readouterr().out
        assert "hidden by baseline" in out

    def test_new_bug_still_fails_the_gate(self, tmp_path, capsys):
        from aegis.__main__ import main

        target = tmp_path / "app"
        target.mkdir()
        (target / "run.py").write_text(SNIPPET)
        baseline = tmp_path / "baseline.json"
        main([str(target), "--write-baseline", str(baseline)])

        (target / "new.py").write_text("import os\n\ndef g(c):\n    os.system(c)\n")
        code = main([str(target), "--baseline", str(baseline),
                     "--max-critical", "0", "--quiet"])
        assert code == 1, "a vulnerability added after the baseline must fail the build"
        assert "POLICY GATE FAILED" in capsys.readouterr().err

    def test_bad_baseline_exits_2(self, tmp_path, capsys):
        from aegis.__main__ import main

        target = tmp_path / "app"
        target.mkdir()
        (target / "run.py").write_text(SNIPPET)
        bad = tmp_path / "bad.json"
        bad.write_text("{}")
        assert main([str(target), "--baseline", str(bad)]) == 2
        assert "not an AegisReview baseline" in capsys.readouterr().err

    def test_machine_formats_respect_the_baseline(self, tmp_path):
        import subprocess
        import sys

        target = tmp_path / "app"
        target.mkdir()
        (target / "run.py").write_text(SNIPPET)
        baseline = tmp_path / "baseline.json"
        subprocess.run([sys.executable, "-m", "aegis", str(target),
                        "--write-baseline", str(baseline)], check=True,
                       capture_output=True)
        proc = subprocess.run([sys.executable, "-m", "aegis", str(target),
                               "--baseline", str(baseline), "-f", "json"],
                              capture_output=True, text=True, check=True)
        report = json.loads(proc.stdout)
        assert report["summary"]["counts"]["critical"] == 0

    def test_dogfood_scan_is_still_clean(self):
        """The engine's own source must stay at 100 with no baseline needed."""
        result = scan_path("aegis")
        assert result.score == 100
        assert result.findings == []
