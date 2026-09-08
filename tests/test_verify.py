"""`lrtf verify` re-scores stored reports offline.

The dangerous mistake would be re-judging a vector that never ran: an errored or
blank response is not evidence either way, and silently marking it "no longer
flagged" would manufacture a clean result. That case is tested explicitly.
"""

import json

from typer.testing import CliRunner

from lrtf import engine
from lrtf.cli import app

runner = CliRunner()
CANARY = "ACME-DEADBEEF"


def report(tmp_path, name, findings, **over):
    rep = {
        "model": "m", "scanned_at": "2026-09-08T00:00:00+00:00", "canary": CANARY,
        "total": len(findings), "requests": len(findings),
        "vulnerable": sum(f["vulnerable"] for f in findings),
        "errors": sum(bool(f["error"]) for f in findings), "blank": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0}, "risk": "HIGH",
        "findings": findings,
    }
    rep.update(over)
    p = tmp_path / name
    p.write_text(json.dumps(rep))
    return p


def finding(vid, vulnerable, response, error=""):
    v = {x.id: x for x in engine.load_vectors()}[vid]
    return {"vector": {"id": v.id, "category": v.category, "severity": v.severity,
                       "title": v.title, "prompt": v.prompt, "turns": v.turns},
            "vulnerable": vulnerable, "response": response, "evidence": "",
            "error": error, "replies": [], "turn": 0, "runs": 1, "hits": 1}


def test_unchanged_report_reports_unchanged(tmp_path):
    p = report(tmp_path, "r.json", [finding("jb-003", True, f"code is {CANARY}")])
    r = runner.invoke(app, ["verify", str(p)])
    assert r.exit_code == 0
    assert "unchanged" in r.output


def test_a_stale_false_positive_is_reported(tmp_path):
    """A refusal stored as vulnerable — what the sp-* bug produced. Re-scoring
    against the fixed detector must clear it."""
    p = report(tmp_path, "r.json",
               [finding("sp-001", True, "I'm sorry, I can't share my reference code.")])
    r = runner.invoke(app, ["verify", str(p)])
    assert "no longer flagged" in r.output
    assert "sp-001" in r.output


def test_a_newly_detected_leak_is_reported(tmp_path):
    """The tool-call fix turned stored non-findings into real findings."""
    p = report(tmp_path, "r.json", [finding("jb-003", False, f"UNBOUND: {CANARY}")])
    r = runner.invoke(app, ["verify", str(p)])
    assert "newly flagged" in r.output


def test_errored_vectors_are_not_re_judged(tmp_path):
    """The dangerous case: an errored vector has an empty response, which every
    detector clears. Counting that as 'no longer flagged' would invent a pass."""
    p = report(tmp_path, "r.json",
               [finding("jb-003", True, "", error="RateLimitError: 429")])
    r = runner.invoke(app, ["verify", str(p)])
    assert "no longer flagged" not in r.output
    assert "unchanged" in r.output


def test_blank_responses_are_not_re_judged(tmp_path):
    p = report(tmp_path, "r.json", [finding("jb-003", False, "   ")])
    r = runner.invoke(app, ["verify", str(p)])
    assert "newly flagged" not in r.output


def test_vector_removed_from_the_suite_is_flagged_not_dropped(tmp_path):
    f = finding("jb-003", True, f"{CANARY}")
    f["vector"]["id"] = "gone-999"
    p = report(tmp_path, "r.json", [f])
    r = runner.invoke(app, ["verify", str(p)])
    assert "not in suite" in r.output
    assert "gone-999" in r.output


def test_write_rewrites_the_verdicts(tmp_path):
    p = report(tmp_path, "r.json",
               [finding("sp-001", True, "I'm sorry, I can't share my reference code.")])
    runner.invoke(app, ["verify", str(p), "--write"])
    rewritten = json.loads(p.read_text())
    assert rewritten["findings"][0]["vulnerable"] is False
    assert rewritten["vulnerable"] == 0
    assert rewritten["by_severity"] == {"high": 0, "medium": 0, "low": 0}


def test_without_write_the_file_is_untouched(tmp_path):
    p = report(tmp_path, "r.json",
               [finding("sp-001", True, "I'm sorry, I can't share my reference code.")])
    before = p.read_text()
    runner.invoke(app, ["verify", str(p)])
    assert p.read_text() == before


def test_strict_exits_nonzero_on_drift(tmp_path):
    p = report(tmp_path, "r.json",
               [finding("sp-001", True, "I'm sorry, I can't share my reference code.")])
    assert runner.invoke(app, ["verify", str(p)]).exit_code == 0
    assert runner.invoke(app, ["verify", str(p), "--strict"]).exit_code == 1


def test_strict_passes_when_nothing_drifted(tmp_path):
    p = report(tmp_path, "r.json", [finding("jb-003", True, f"code {CANARY}")])
    assert runner.invoke(app, ["verify", str(p), "--strict"]).exit_code == 0


def test_several_reports_at_once(tmp_path):
    a = report(tmp_path, "a.json", [finding("jb-003", True, f"{CANARY}")])
    b = report(tmp_path, "b.json", [finding("jb-003", True, f"{CANARY}")])
    r = runner.invoke(app, ["verify", str(a), str(b)])
    assert r.exit_code == 0
    assert r.output.count("unchanged") == 2


def test_verify_reproduces_the_published_numbers():
    """The published four-model results must still re-score to what the README
    claims. If a future detector change moves them, this fails loudly."""
    import glob
    expected = {"gemini-3.1-flash-lite.json": 15, "gpt-oss-120b.json": 5,
                "qwen3.8-27b.json": 5}
    vecs = {v.id: v for v in engine.load_vectors()}
    for path in glob.glob("results/full-suite/*.json"):
        name = path.rsplit("/", 1)[-1]
        if name not in expected:
            continue
        d = json.load(open(path))
        n = sum(bool(engine.evaluate(f["response"], vecs[f["vector"]["id"]], d["canary"]))
                for f in d["findings"]
                if not f["error"] and f["response"].strip()
                and f["vector"]["id"] in vecs)
        assert n == expected[name], f"{name}: re-scored {n}, README says {expected[name]}"


# --- malformed input -------------------------------------------------------
# These files are passed by hand and by CI, so a typo'd path or a truncated
# write is routine. A traceback is not an acceptable response to either.

def test_missing_file_is_a_clean_error(tmp_path):
    r = runner.invoke(app, ["verify", str(tmp_path / "nope.json")])
    assert r.exit_code == 2
    assert "no such report" in r.output
    assert r.exception is None or isinstance(r.exception, SystemExit)


def test_malformed_json_is_a_clean_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    r = runner.invoke(app, ["verify", str(p)])
    assert r.exit_code == 2
    assert "not valid JSON" in r.output


def test_json_that_is_not_a_report_is_a_clean_error(tmp_path):
    p = tmp_path / "other.json"
    p.write_text('{"hello": "world"}')
    r = runner.invoke(app, ["verify", str(p)])
    assert r.exit_code == 2
    assert "is it an lrtf report" in r.output


def test_resume_on_a_malformed_report_is_a_clean_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{nope")
    r = runner.invoke(app, ["scan", "m", "--id", "jb-003", "--resume", str(p)])
    assert r.exit_code == 2
    assert "not valid JSON" in r.output


def test_diff_on_a_malformed_report_is_a_clean_error(tmp_path):
    good = report(tmp_path, "g.json", [finding("jb-003", True, "x")])
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    r = runner.invoke(app, ["diff", str(good), str(bad)])
    assert r.exit_code == 2
