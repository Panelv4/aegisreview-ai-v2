"""Engine accuracy tests: true positives, false-positive guards, scoring, exports."""

from __future__ import annotations

import json
import textwrap

import pytest

from aegis.engine.analyzer import (
    analyze_source,
    entropy_secret_scan,
    mask_source,
    scan_path,
    shannon_entropy,
)
from aegis.engine.exporters import to_html, to_markdown, to_sarif
from aegis.engine.models import ScanResult
from aegis.engine.policy import Baseline, Policy


def rules_hit(code: str, path: str = "app.py", language: str | None = None) -> set[str]:
    report = analyze_source(textwrap.dedent(code), path, language)
    return {f.rule_id for f in report.findings}


def findings(code: str, path: str = "app.py", language: str | None = None):
    return analyze_source(textwrap.dedent(code), path, language).findings


# --------------------------------------------------------------------------- #
# True positives
# --------------------------------------------------------------------------- #
class TestDetection:
    def test_sql_injection_fstring(self):
        assert "AEGIS-SQLI-001" in rules_hit('''
            def get(email):
                cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
        ''')

    def test_sql_injection_concatenation(self):
        assert "AEGIS-SQLI-001" in rules_hit('''
            cur.execute("SELECT * FROM users WHERE id = " + user_id)
        ''')

    def test_parameterised_query_is_clean(self):
        assert "AEGIS-SQLI-001" not in rules_hit('''
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        ''')

    def test_command_injection(self):
        assert "AEGIS-CMDI-001" in rules_hit('''
            import os
            os.system("ping " + host)
        ''')

    def test_subprocess_shell_true(self):
        assert "AEGIS-CMDI-001" in rules_hit('''
            import subprocess
            subprocess.run(cmd, shell=True)
        ''')

    def test_subprocess_list_is_clean(self):
        assert "AEGIS-CMDI-001" not in rules_hit('''
            subprocess.run(["ping", host], shell=False, check=True)
        ''')

    def test_eval(self):
        assert "AEGIS-CODE-001" in rules_hit("result = eval(request.args['x'])")

    def test_literal_eval_is_clean(self):
        assert "AEGIS-CODE-001" not in rules_hit("import ast\nval = ast.literal_eval(data)")

    def test_pickle(self):
        assert "AEGIS-DESER-001" in rules_hit("import pickle\ndata = pickle.loads(body)")

    def test_yaml_load(self):
        assert "AEGIS-DESER-001" in rules_hit("import yaml\ncfg = yaml.load(stream)")

    def test_yaml_safe_load_is_clean(self):
        assert "AEGIS-DESER-001" not in rules_hit("import yaml\ncfg = yaml.safe_load(stream)")

    def test_xss_innerhtml(self):
        assert "AEGIS-XSS-001" in rules_hit(
            "el.innerHTML = `<p>${comment}</p>`;", "app.js", "javascript")

    def test_textcontent_is_clean(self):
        assert "AEGIS-XSS-001" not in rules_hit(
            "el.textContent = comment;", "app.js", "javascript")

    def test_dompurify_is_clean(self):
        assert "AEGIS-XSS-001" not in rules_hit(
            "el.innerHTML = DOMPurify.sanitize(html);", "app.js", "javascript")

    def test_path_traversal(self):
        assert "AEGIS-PATH-001" in rules_hit('''
            return send_file(os.path.join(UPLOADS, request.args["name"]))
        ''')

    def test_weak_password_hash(self):
        assert "AEGIS-AUTH-001" in rules_hit('h = hashlib.md5(password.encode()).hexdigest()')

    def test_digest_outside_password_context_is_clean(self):
        # hashing a cache key or an ETag with md5/sha1 is not a password problem
        assert "AEGIS-AUTH-001" not in rules_hit("etag = hashlib.md5(body).hexdigest()")
        assert "AEGIS-AUTH-001" not in rules_hit("cache_key = hashlib.sha1(payload).hexdigest()")

    def test_bcrypt_is_clean(self):
        assert "AEGIS-AUTH-001" not in rules_hit("h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())")

    def test_hardcoded_password(self):
        assert "AEGIS-AUTH-002" in rules_hit('DB_PASSWORD = "hunter2hunter2"')

    def test_env_password_is_clean(self):
        assert "AEGIS-AUTH-002" not in rules_hit('DB_PASSWORD = os.environ["DB_PASSWORD"]')

    def test_jwt_none_algorithm(self):
        assert "AEGIS-AUTH-003" in rules_hit(
            'jwt.decode(token, options={"verify_signature": False})')

    def test_insecure_random_token(self):
        assert "AEGIS-AUTH-004" in rules_hit(
            "reset_token = ''.join(random.choice(CHARS) for _ in range(32))")

    def test_random_outside_security_context_is_clean(self):
        # jinja's `random` filter and UI jitter are not credentials
        assert "AEGIS-AUTH-004" not in rules_hit("return random.choice(seq)")
        assert "AEGIS-AUTH-004" not in rules_hit("const top = Math.random() * 100;",
                                                 "ui.js", "javascript")

    def test_secrets_token_is_clean(self):
        assert "AEGIS-AUTH-004" not in rules_hit("tok = secrets.token_urlsafe(32)")

    def test_tls_verify_false(self):
        assert "AEGIS-CRYPTO-001" in rules_hit("requests.get(url, verify=False, timeout=5)")

    def test_ecb_mode(self):
        assert "AEGIS-CRYPTO-002" in rules_hit("c = AES.new(key, AES.MODE_ECB)")

    def test_buffer_overflow(self):
        assert "AEGIS-MEM-001" in rules_hit("strcpy(dst, src);", "x.c", "c")

    def test_format_string(self):
        assert "AEGIS-MEM-002" in rules_hit("printf(input);", "x.c", "c")

    def test_csharp_and_java_languages_are_recognised(self):
        assert "AEGIS-JAVA-001" in rules_hit(
            "Object o = new ObjectInputStream(in).readObject();", "A.java", "java")

    def test_php_code_execution(self):
        assert "AEGIS-PHP-001" in rules_hit("<?php eval($code);", "a.php", "php")

    def test_go_ignored_error(self):
        assert "AEGIS-GO-001" in rules_hit(
            "_ = json.NewDecoder(r.Body).Decode(&u)", "main.go", "go")

    def test_debug_true(self):
        assert "AEGIS-CONF-001" in rules_hit("app.run(debug=True)")

    def test_ssrf(self):
        assert "AEGIS-SSRF-001" in rules_hit("requests.get(request.args['url'], timeout=5)")

    def test_open_redirect(self):
        assert "AEGIS-REDIR-001" in rules_hit('return redirect(request.args.get("next"))')

    def test_mass_assignment(self):
        assert "AEGIS-DATA-002" in rules_hit("user = User(**request.json)")

    def test_zip_slip(self):
        assert "AEGIS-VAL-002" in rules_hit("zipfile.ZipFile(p).extractall(dest)")

    def test_xxe(self):
        assert "AEGIS-VAL-003" in rules_hit("root = ET.fromstring(request.data)")

    def test_prototype_pollution(self):
        assert "AEGIS-JS-002" in rules_hit("Object.assign(target, req.body);", "a.js", "javascript")

    def test_redos(self):
        assert "AEGIS-REGEX-001" in rules_hit(r"re.match(r'^(\w+\s?)*$', s)")

    def test_timing_unsafe_compare(self):
        assert "AEGIS-AUTH-007" in rules_hit(
            "if api_key == stored_key:\n    return True")
        assert "AEGIS-AUTH-007" in rules_hit("if csrf_token == provided:")
        assert "AEGIS-AUTH-007" in rules_hit("return signature == expected_sig")

    def test_bare_token_variable_is_not_a_secret(self):
        # a variable named `token` is usually a lexer/parser token
        assert "AEGIS-AUTH-007" not in rules_hit('if token.value == "filter":')
        assert "AEGIS-AUTH-007" not in rules_hit('if token_type == "name":')


# --------------------------------------------------------------------------- #
# False-positive guards
# --------------------------------------------------------------------------- #
class TestFalsePositives:
    def test_comment_is_ignored(self):
        assert "AEGIS-CODE-001" not in rules_hit("# never call eval(user_input) here")

    def test_string_literal_is_ignored(self):
        assert "AEGIS-CODE-001" not in rules_hit('msg = "do not use eval(x)"')

    def test_block_comment_is_ignored(self):
        assert "AEGIS-CMDI-001" not in rules_hit('''
            /* os.system("rm -rf /") is never acceptable */
            x = 1
        ''', "a.c", "c")

    def test_placeholder_secret_is_ignored(self):
        assert "AEGIS-AUTH-002" not in rules_hit('API_KEY = "your-key-here"')
        assert "AEGIS-AUTH-002" not in rules_hit('API_KEY = "changeme"')

    def test_clean_application_is_clean(self):
        code = '''
            import os
            from argon2 import PasswordHasher
            from flask import Flask, request

            app = Flask(__name__)
            app.secret_key = os.environ["SECRET_KEY"]
            ph = PasswordHasher()

            @app.post("/login")
            def login():
                pw = request.form["password"]
                return {"hash": ph.hash(pw)}

            if __name__ == "__main__":
                app.run(host="127.0.0.1", debug=os.getenv("DEV") == "1")
        '''
        got = rules_hit(code)
        assert got == set(), f"unexpected findings: {got}"

    def test_masking_preserves_columns(self):
        src = 'x = "hello"  # comment with os.system("x")'
        masked, raw = mask_source(src, "python")
        assert len(masked[0]) == len(raw[0])
        assert "os.system" not in masked[0]
        assert "os.system" in raw[0]


# --------------------------------------------------------------------------- #
# Taint / evidence
# --------------------------------------------------------------------------- #
class TestTaint:
    def test_source_to_sink_trace(self):
        code = '''
            from flask import request
            def handler():
                email = request.args.get("email")
                cur.execute(f"SELECT * FROM u WHERE e = '{email}'")
        '''
        f = [x for x in findings(code) if x.rule_id == "AEGIS-SQLI-001"][0]
        roles = [e.role for e in f.evidence]
        assert "sink" in roles
        assert "source" in roles
        assert f.confidence == "high"
        assert "request.args" in f.evidence[0].code

    def test_no_source_means_lower_confidence(self):
        f = [x for x in findings('cur.execute(f"SELECT {col}")') if x.rule_id == "AEGIS-SQLI-001"][0]
        # the rule supports taint tracking but no untrusted source reached the sink
        assert f.confidence == "low"


# --------------------------------------------------------------------------- #
# Secrets by entropy
# --------------------------------------------------------------------------- #
class TestEntropy:
    def test_shannon(self):
        assert shannon_entropy("aaaaaaaa") == 0.0
        assert shannon_entropy("abcdefgh") > 2.9

    @pytest.mark.parametrize("line", [
        'STRIPE_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY"',
        'aws_secret_key: "wJalrXUtnFEMI/K7MDENGbPxRfiCYEXAMPLEKEY"',
        'auth_token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"',
    ])
    def test_detects_high_entropy_secret(self, line):
        assert entropy_secret_scan([line], "config.py"), line

    @pytest.mark.parametrize("line", [
        'content_type = "application/json"',
        'key = "hello-world-name"',
        'token = "short"',
        'url = "https://api.example.com/v1"',
    ])
    def test_ignores_non_secrets(self, line):
        assert not entropy_secret_scan([line], "config.py"), line

    def test_value_is_redacted_in_finding(self):
        f = [x for x in findings('stripe_key = "sk_live_EXAMPLE_NOT_A_REAL_KEY"')
             if x.rule_id == "AEGIS-SECRET-001"][0]
        assert f.redacted
        assert "9fJ2kLmN8pQrS4tV6wXyZ0aBcDeFgHiJ" not in f.code
        assert "****" in f.code

    def test_named_secret_patterns_also_redact(self):
        f = [x for x in findings('DB_PASSWORD = "hunter2hunter2"')
             if x.rule_id == "AEGIS-AUTH-002"][0]
        assert "hunter2hunter2" not in f.code
        assert "****" in f.code


# --------------------------------------------------------------------------- #
# Suppression
# --------------------------------------------------------------------------- #
class TestSuppression:
    def test_inline_ignore_specific_rule(self):
        rep = analyze_source(
            'os.system("ls " + x)  # aegis:ignore AEGIS-CMDI-001\n'
            'os.system("rm " + y)\n',
            "a.py",
        )
        assert len(rep.findings) == 1
        assert rep.suppressed == 1

    def test_inline_ignore_all(self):
        rep = analyze_source('eval(x)  # aegis:ignore\n', "a.py")
        assert rep.findings == []
        assert rep.suppressed == 1

    def test_file_level_ignore(self):
        rep = analyze_source(
            "# aegis:ignore-file\nimport os\nos.system(x)\neval(y)\n", "a.py")
        assert rep.findings == []


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
class TestScoring:
    def test_clean_scores_100(self):
        r = ScanResult(files=[analyze_source("x = 1\n", "a.py")])
        assert r.score == 100 and r.grade == "A+" and r.verdict == "Clean"

    def test_critical_lowers_score(self):
        r = ScanResult(files=[analyze_source("import os\nos.system(x)\n", "a.py")])
        assert r.score < 100
        assert r.verdict == "Block release"

    def test_more_findings_score_lower(self):
        one = ScanResult(files=[analyze_source("eval(a)\n", "a.py")])
        many = ScanResult(files=[analyze_source(
            "eval(a)\neval(b)\neval(c)\nimport os\nos.system(d)\nos.system(e)\n", "b.py")])
        assert many.score < one.score

    def test_score_bounded(self):
        code = "eval(a)\n" * 200
        r = ScanResult(files=[analyze_source(code, "a.py")])
        assert 0 <= r.score <= 100

    def test_fingerprint_is_stable_across_line_moves(self):
        a = analyze_source("x = 1\neval(payload)\n", "a.py").findings[0]
        b = analyze_source("x = 1\ny = 2\neval(payload)\n", "a.py").findings[0]
        assert a.fingerprint == b.fingerprint
        assert a.line != b.line


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
@pytest.fixture()
def sample_result():
    return scan_path("samples/vulnerable-app")


class TestExports:
    def test_sarif_shape(self, sample_result):
        sarif = to_sarif(sample_result)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "AegisReview"
        assert len(run["results"]) == len(sample_result.findings)
        r0 = run["results"][0]
        assert r0["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert "security-severity" in run["tool"]["driver"]["rules"][0]["properties"]
        json.dumps(sarif)  # must be serialisable

    def test_markdown_has_findings(self, sample_result):
        md = to_markdown(sample_result)
        assert "Score" in md
        assert "SQL injection" in md
        assert md.count("###") >= 5

    def test_html_is_self_contained(self, sample_result):
        html = to_html(sample_result)
        assert "<!DOCTYPE html>" in html
        assert "<link" not in html and "<script" not in html
        assert "@import" not in html


# --------------------------------------------------------------------------- #
# Policy gate + baseline
# --------------------------------------------------------------------------- #
class TestPolicy:
    def test_blocks_critical(self, sample_result):
        ok, reasons = Policy(max_critical=0).evaluate(sample_result)
        assert not ok and "critical" in reasons[0]

    def test_allows_generous_budget(self, sample_result):
        ok, _ = Policy(max_critical=99, max_high=99, max_medium=99).evaluate(sample_result)
        assert ok

    def test_min_score(self):
        r = ScanResult(files=[analyze_source("eval(x)\n", "a.py")])
        ok, reasons = Policy(min_score=99).evaluate(r)
        assert not ok
        assert any("below the required minimum" in r for r in reasons)

    def test_regression_gate(self):
        r = ScanResult(files=[analyze_source("eval(x)\n", "a.py")])
        ok, reasons = Policy(max_critical=9, max_high=9, max_score_drop=5).evaluate(r, baseline_score=100)
        assert not ok and "dropped" in reasons[0]

    def test_baseline_marks_new_findings(self, sample_result):
        baseline = Baseline.from_findings([f.to_dict() for f in sample_result.findings])
        assert all(not baseline.is_new(f.fingerprint) for f in sample_result.findings)
        assert baseline.is_new("never-seen-fingerprint")


# --------------------------------------------------------------------------- #
# Path scanning
# --------------------------------------------------------------------------- #
class TestScanPath:
    def test_scans_all_languages_in_sample(self, sample_result):
        langs = {f.language for f in sample_result.scannable_files}
        assert {"python", "javascript", "c", "php", "yaml"} <= langs

    def test_skips_node_modules(self, tmp_path):
        (tmp_path / "node_modules" / "dep").mkdir(parents=True)
        (tmp_path / "node_modules" / "dep" / "index.js").write_text("eval(x)")
        (tmp_path / "app.py").write_text("eval(y)")
        result = scan_path(tmp_path)
        assert all("node_modules" not in f.path for f in result.files)

    def test_binary_files_are_skipped(self, tmp_path):
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
        (tmp_path / "app.py").write_text("x = 1\n")
        result = scan_path(tmp_path)
        assert not any(f.path.endswith(".png") for f in result.files)

    def test_duration_recorded(self, sample_result):
        assert sample_result.duration_ms >= 0
        assert sample_result.rules_evaluated >= 50


# --------------------------------------------------------------------------- #
# Precision regressions — each of these once produced a false positive while
# dogfooding the engine against its own source.
# --------------------------------------------------------------------------- #
class TestPrecisionRegressions:
    def test_docstring_contents_are_masked(self):
        code = '''
            def helper():
                """
                Never do this: eval(user_input) or os.system(cmd)
                """
                return 1
        '''
        assert rules_hit(code) == set()

    def test_cross_scope_variable_is_not_a_taint_trace(self):
        # `hash` is assigned on another line and is unrelated to the sink
        code = '''
            from flask import request
            def a():
                const_hash = location.hash
            def b():
                el.innerHTML = `<span>static</span>`;
        '''
        f = [x for x in findings(code, "x.js", "javascript") if x.rule_id == "AEGIS-XSS-001"]
        assert all(not any(e.role == "source" for e in x.evidence) for x in f)

    def test_static_markup_in_innerhtml_is_clean(self):
        assert "AEGIS-XSS-001" not in rules_hit("el.innerHTML = '<b>loading</b>';", "x.js", "javascript")

    def test_escaped_interpolation_is_clean(self):
        assert "AEGIS-XSS-001" not in rules_hit(
            "el.innerHTML = `<p>${UI.esc(name)}</p>`;", "x.js", "javascript")

    def test_untrusted_interpolation_is_caught_with_high_confidence(self):
        f = [x for x in findings("el.innerHTML = `<p>${comment.body}</p>`;", "x.js", "javascript")
             if x.rule_id == "AEGIS-XSS-001"]
        assert f and f[0].confidence == "high"

    def test_rule_catalog_quotes_are_not_code(self):
        # a rule file documenting a vulnerable example must not flag itself
        code = '''
            Rule(
                vuln_example='cipher = DES.new(key)',
                fix_example='cipher = AES.new(key, AES.MODE_GCM)',
            )
        '''
        assert "AEGIS-CRYPTO-002" not in rules_hit(code)

    def test_sample_and_fixture_paths_are_never_flagged(self):
        report = analyze_source('os.system(x)\n', "samples/vulnerable-app/app.py")
        assert report.findings == []
        report = analyze_source('os.system(x)\n', "tests/fixtures/bad.py")
        assert report.findings == []

    def test_self_scan_is_clean(self):
        """The project must pass its own gate — if this fails, precision regressed."""
        result = scan_path("aegis")
        assert result.findings == [], [
            f"{f.file}:{f.line} {f.rule_id} {f.code[:60]}" for f in result.findings
        ]
        assert result.score == 100
