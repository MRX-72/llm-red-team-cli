"""HTML report.

The escaping tests are the ones that matter. This suite deliberately plants live
payloads -- ioh-002 sends <script>alert('XSS7734')</script> -- and a finding is
the model echoing one back. An unescaped report would execute the exact payload
it was written to report, in the browser of whoever opened it.
"""

import json

from typer.testing import CliRunner

from lrtf import engine, report
from lrtf.cli import app

runner = CliRunner()


def build(findings, **over):
    base = {
        "model": "test/model", "scanned_at": "2026-09-08T00:00:00+00:00",
        "canary": "ACME-DEADBEEF", "total": len(findings), "requests": len(findings),
        "vulnerable": sum(f["vulnerable"] for f in findings),
        "errors": 0, "blank": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0}, "risk": "HIGH",
        "findings": findings,
    }
    base.update(over)
    return base


def finding(vid="t-1", vulnerable=True, response="r", evidence="e", **over):
    f = {
        "vector": {"id": vid, "category": "jailbreak", "severity": "high",
                   "title": "t", "prompt": "p", "turns": []},
        "vulnerable": vulnerable, "response": response, "evidence": evidence,
        "error": "", "replies": [], "turn": 0, "runs": 1, "hits": 1,
    }
    f.update(over)
    return f


# --- escaping --------------------------------------------------------------

def test_script_payload_in_a_response_is_escaped():
    xss = "<script>alert('XSS7734')</script>"
    out = report.render(build([finding(response=xss, evidence=xss)]))
    assert xss not in out
    assert "&lt;script&gt;" in out


def test_script_payload_in_a_prompt_is_escaped():
    out = report.render(build([finding(
        vector={"id": "ioh-002", "category": "improper_output_handling",
                "severity": "high", "title": "XSS",
                "prompt": "<img src=x onerror=alert(1)>", "turns": []})]))
    assert "<img src=x onerror=" not in out
    assert "&lt;img src=x onerror=" in out


def test_payload_in_a_title_or_id_is_escaped():
    out = report.render(build([finding(
        vector={"id": "<b>x</b>", "category": "<i>c</i>", "severity": "high",
                "title": "</style><script>x</script>", "prompt": "p", "turns": []})]))
    assert "<script>x</script>" not in out
    assert "</style><script>" not in out


def test_payload_in_a_multi_turn_reply_is_escaped():
    xss = "<script>alert(1)</script>"
    out = report.render(build([finding(
        vector={"id": "jb-014", "category": "jailbreak", "severity": "high",
                "title": "crescendo", "prompt": "", "turns": ["a", "b"]},
        replies=["ok", xss], turn=2)]))
    assert xss not in out
    assert "&lt;script&gt;" in out


def test_model_name_is_escaped():
    out = report.render(build([], model='x"><script>alert(1)</script>'))
    assert "<script>alert(1)</script>" not in out


def _dom(html_text):
    """Collect (tag, attrs) actually parsed as markup.

    Substring checks are the wrong tool: `onerror=` appears harmlessly inside a
    <pre> once its quotes are escaped. What matters is whether the browser ends
    up with an executable node, so inspect the parsed DOM instead.
    """
    from html.parser import HTMLParser

    seen = []

    class P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            seen.append((tag, dict(attrs)))

    P().feed(html_text)
    return seen


def test_every_shipped_payload_yields_no_executable_node():
    """Worst realistic case: a model echoing every payload back verbatim. The
    report must still parse to a DOM with no script and no event handlers."""
    findings = []
    for v in engine.load_vectors(categories=["improper_output_handling"]):
        text = v.prompt or v.turns[0]
        findings.append(finding(vid=v.id, response=text, evidence=text[:40]))
    dom = _dom(report.render(build(findings)))

    assert not [t for t, _ in dom if t in ("script", "iframe", "object", "embed")]
    handlers = [(t, k) for t, a in dom for k in a if k.startswith("on")]
    assert not handlers, f"event handler attributes present: {handlers}"
    assert not [t for t, a in dom if t == "img"], "payload produced an img element"


def test_a_deliberately_hostile_response_yields_no_executable_node():
    hostile = ('</pre><script>alert(1)</script><img src=x onerror=alert(2)>'
               '<iframe src=javascript:alert(3)></iframe>')
    dom = _dom(report.render(build([finding(response=hostile, evidence=hostile)])))
    assert not [t for t, _ in dom if t in ("script", "img", "iframe")]
    assert not [k for _, a in dom for k in a if k.startswith("on")]


# --- content ---------------------------------------------------------------

def test_self_contained_no_external_resources():
    out = report.render(build([finding()]))
    for bad in ("http://", "https://", "<script", "cdn"):
        assert bad not in out.lower(), f"report reaches out via {bad!r}"


def test_findings_and_risk_appear():
    out = report.render(build([finding(vid="jb-003", evidence="ACME-X")],
                              risk="CRITICAL"))
    assert "jb-003" in out and "ACME-X" in out and "CRITICAL" in out


def test_clean_scan_says_so():
    out = report.render(build([finding(vulnerable=False)], vulnerable=0, risk="PASS"))
    assert "No vector got through" in out


def test_incomplete_scan_is_flagged():
    out = report.render(build([finding(vulnerable=False)], errors=3, blank=2,
                              risk="INCOMPLETE"))
    assert "Incomplete" in out
    assert "not a clean result" in out


def test_repeat_rate_is_shown():
    out = report.render(build([finding(runs=5, hits=2)]))
    assert "reproduced 2/5" in out


def test_multi_turn_marks_the_leaking_turn():
    out = report.render(build([finding(
        vector={"id": "x", "category": "c", "severity": "high", "title": "t",
                "prompt": "", "turns": ["one", "two", "three"]},
        replies=["a", "b", "c"], turn=2)]))
    assert "leaked on turn 2 of 3" in out
    assert "leaked here" in out


def test_is_parseable_html():
    from html.parser import HTMLParser

    class P(HTMLParser):
        def error(self, m): raise AssertionError(m)

    P().feed(report.render(build([finding()])))


# --- cli -------------------------------------------------------------------

def test_cli_writes_html(monkeypatch, tmp_path):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "I can't share that.")
    out = tmp_path / "r.html"
    r = runner.invoke(app, ["scan", "m", "-c", "misinformation",
                            "--html", str(out), "--fail-on", "never"])
    assert r.exit_code == 0, r.output
    assert out.exists()
    text = out.read_text()
    assert text.startswith("<!doctype html>")
    assert "lrtf" in text
