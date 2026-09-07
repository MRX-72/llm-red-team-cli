"""diff decides whether a prompt change helped. Getting FIXED wrong -- especially
calling an errored vector fixed -- would make it worse than useless."""

import json

import pytest
from typer.testing import CliRunner

from llm_red_team.cli import app

runner = CliRunner()


def finding(vid, vulnerable, severity="high", error=""):
    return {
        "vector": {"id": vid, "category": "jailbreak", "severity": severity,
                   "title": f"title {vid}", "turns": []},
        "vulnerable": vulnerable, "response": "r", "evidence": "e" if vulnerable else "",
        "error": error, "replies": [], "turn": 0,
    }


def report(tmp_path, name, findings, risk="HIGH"):
    p = tmp_path / name
    p.write_text(json.dumps({
        "model": "m", "scanned_at": "2026-01-01T00:00:00+00:00", "canary": "ACME-X",
        "total": len(findings), "requests": len(findings),
        "vulnerable": sum(f["vulnerable"] for f in findings),
        "errors": sum(bool(f["error"]) for f in findings), "blank": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0}, "risk": risk,
        "findings": findings,
    }))
    return p


def run(a, b, *args):
    return runner.invoke(app, ["diff", str(a), str(b), *args])


def test_fixed_and_regressed_are_named(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", True), finding("v2", False)])
    b = report(tmp_path, "b.json", [finding("v1", False), finding("v2", True)])
    r = run(a, b)
    assert "FIXED" in r.output and "v1" in r.output
    assert "REGRESSED" in r.output and "v2" in r.output


def test_regression_exits_nonzero(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", False)])
    b = report(tmp_path, "b.json", [finding("v1", True)])
    assert run(a, b).exit_code == 1
    assert run(a, b, "--no-fail").exit_code == 0


def test_pure_improvement_exits_zero(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", True)])
    b = report(tmp_path, "b.json", [finding("v1", False)])
    r = run(a, b)
    assert r.exit_code == 0
    assert "FIXED" in r.output


def test_identical_reports_report_no_change(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", False)])
    b = report(tmp_path, "b.json", [finding("v1", False)])
    r = run(a, b)
    assert r.exit_code == 0
    assert "No change" in r.output


def test_an_errored_vector_is_never_called_fixed(tmp_path):
    """The failure mode that would make diff dangerous: a vector that failed to
    run looks 'not vulnerable', which would read as a fix."""
    a = report(tmp_path, "a.json", [finding("v1", True)])
    b = report(tmp_path, "b.json", [finding("v1", False, error="RateLimitError: 429")])
    r = run(a, b)
    assert "FIXED" not in r.output
    assert "UNTESTED" in r.output


def test_still_failing_is_distinguished_from_regressed(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", True)])
    b = report(tmp_path, "b.json", [finding("v1", True)])
    r = run(a, b)
    assert "STILL FAILING" in r.output
    assert r.exit_code == 0          # not new, so not a regression


def test_new_vector_in_suite_shows_as_added(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", False)])
    b = report(tmp_path, "b.json", [finding("v1", False), finding("v2", True)])
    r = run(a, b)
    assert "ADDED" in r.output and "v2" in r.output
    assert r.exit_code == 1          # a newly-failing vector still gates CI


def test_removed_vector_shows_as_dropped(tmp_path):
    a = report(tmp_path, "a.json", [finding("v1", True), finding("v2", True)])
    b = report(tmp_path, "b.json", [finding("v1", True)])
    r = run(a, b)
    assert "DROPPED" in r.output
