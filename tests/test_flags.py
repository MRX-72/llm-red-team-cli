"""The flags added for selection, execution control and provider routing."""

import json
import time

import pytest
from conftest import flat
from typer.testing import CliRunner

from lrtf import engine
from lrtf.cli import app
from lrtf.engine import Vector

runner = CliRunner()
HELD = "I'm sorry, I don't have that information and I'm not able to verify it. " \
       "I can only answer questions about ACME products and support."


# --- selection -------------------------------------------------------------

def test_ids_selects_exactly_those():
    vs = engine.load_vectors(ids=["jb-003", "pi-001"])
    assert sorted(v.id for v in vs) == ["jb-003", "pi-001"]


def test_unknown_id_is_an_error_not_an_empty_scan():
    """Silently scanning nothing then reporting PASS is the failure mode this
    whole tool exists to avoid."""
    with pytest.raises(ValueError, match="no such vector: nope-999"):
        engine.load_vectors(ids=["jb-003", "nope-999"])


def test_cli_rejects_an_unknown_id():
    r = runner.invoke(app, ["scan", "m", "--id", "nope-999"])
    assert r.exit_code == 2
    assert "no such vector" in flat(r.output)


def test_exclude_drops_a_category():
    vs = engine.load_vectors(exclude=["unbounded_consumption"])
    assert not [v for v in vs if v.category == "unbounded_consumption"]
    assert len(vs) == 300 - 30


def test_exclude_drops_an_id():
    assert "jb-003" not in {v.id for v in engine.load_vectors(exclude=["jb-003"])}


def test_exclude_wins_over_id():
    assert engine.load_vectors(ids=["jb-003"], exclude=["jb-003"]) == []


# --- sampling --------------------------------------------------------------

def test_sample_returns_the_requested_size():
    assert len(engine.sample(engine.load_vectors(), 30, seed=1)) == 30


def test_sample_is_reproducible_with_a_seed():
    a = [v.id for v in engine.sample(engine.load_vectors(), 25, seed=7)]
    b = [v.id for v in engine.sample(engine.load_vectors(), 25, seed=7)]
    assert a == b


def test_sample_differs_without_a_shared_seed():
    a = [v.id for v in engine.sample(engine.load_vectors(), 25, seed=1)]
    b = [v.id for v in engine.sample(engine.load_vectors(), 25, seed=2)]
    assert a != b


def test_sample_covers_every_category():
    """A flat random draw can miss whole categories, which makes a smoke test
    quietly useless."""
    picked = engine.sample(engine.load_vectors(), 30, seed=3)
    assert len({v.category for v in picked}) == 10


def test_sample_larger_than_the_suite_returns_everything():
    vs = engine.load_vectors(categories=["jailbreak"])
    assert engine.sample(vs, 999) == vs


# --- fail fast -------------------------------------------------------------

def test_fail_fast_stops_early(monkeypatch):
    calls = {"n": 0}

    def leak(*a, **k):
        calls["n"] += 1
        time.sleep(0.001)          # any real probe yields; an instant one hides the race
        return "ACME-DEADBEEF"

    monkeypatch.setattr(engine, "probe", leak)
    vectors = engine.load_vectors(severities=["high"])
    results, _ = engine.run_scan("m", vectors, canary="ACME-DEADBEEF",
                                 workers=1, fail_fast=True)
    assert calls["n"] < len(vectors), "fail_fast did not cut the run short"
    assert any(r.vulnerable for r in results)


def test_fail_fast_runs_to_completion_when_nothing_leaks(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: HELD)
    vectors = engine.load_vectors(categories=["jailbreak"])
    results, _ = engine.run_scan("m", vectors, workers=2, fail_fast=True)
    assert len(results) == len(vectors)


def test_fail_fast_ignores_medium_and_low(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "ACME-DEADBEEF")
    vectors = engine.load_vectors(categories=["jailbreak"], severities=["low"])
    results, _ = engine.run_scan("m", vectors, canary="ACME-DEADBEEF",
                                 workers=1, fail_fast=True)
    assert len(results) == len(vectors)


# --- provider routing ------------------------------------------------------

@pytest.mark.parametrize("flag,key,value", [
    ("--api-base", "api_base", "https://vllm.internal.example.com/v1"),
    ("--api-key", "api_key", "sk-local-123"),
    ("--timeout", "timeout", 45.0),
    ("--max-tokens", "max_tokens", 256),
])
def test_provider_options_reach_the_call(monkeypatch, flag, key, value):
    seen = {}
    monkeypatch.setattr(engine, "probe",
                        lambda *a, **k: (seen.update(k), HELD)[1])
    r = runner.invoke(app, ["scan", "m", "--id", "jb-003", flag, str(value),
                            "--fail-on", "never"])
    assert r.exit_code == 0, flat(r.output)
    assert seen[key] == value


def test_headers_are_parsed_into_a_dict(monkeypatch):
    seen = {}
    monkeypatch.setattr(engine, "probe",
                        lambda *a, **k: (seen.update(k), HELD)[1])
    r = runner.invoke(app, ["scan", "m", "--id", "jb-003", "--fail-on", "never",
                            "-H", "X-Tenant: acme", "-H", "X-Trace: 99"])
    assert r.exit_code == 0, flat(r.output)
    assert seen["extra_headers"] == {"X-Tenant": "acme", "X-Trace": "99"}


def test_malformed_header_is_rejected():
    r = runner.invoke(app, ["scan", "m", "--id", "jb-003", "-H", "nocolon"])
    assert r.exit_code == 2
    assert "Name: value" in flat(r.output)


# --- canary ----------------------------------------------------------------

def test_pinned_canary_is_used(monkeypatch):
    seen = {}
    monkeypatch.setattr(engine, "probe",
                        lambda m, sys, p, **k: (seen.update(system=sys), HELD)[1])
    runner.invoke(app, ["scan", "m", "--id", "jb-003", "--canary", "ACME-PINNED",
                        "--fail-on", "never"])
    assert "ACME-PINNED" in seen["system"]


# --- quiet -----------------------------------------------------------------

def test_quiet_prints_one_line(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: HELD)
    r = runner.invoke(app, ["scan", "m", "-c", "jailbreak", "-q", "--fail-on", "never"])
    assert r.exit_code == 0
    assert len([l for l in flat(r.output).strip().splitlines() if l.strip()]) == 1
    assert "PASS" in flat(r.output)


def test_quiet_still_gates(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "ACME-X")
    r = runner.invoke(app, ["scan", "m", "--id", "jb-003", "-q", "--canary", "ACME-X"])
    assert r.exit_code == 1


# --- resume ----------------------------------------------------------------

def _partial(tmp_path, monkeypatch):
    """A scan where half the vectors errored, written to disk."""
    calls = {"n": 0}

    def half(*a, **k):
        calls["n"] += 1
        if calls["n"] % 2:
            raise RuntimeError("429 rate limit")
        return HELD

    monkeypatch.setattr(engine, "probe", half)
    out = tmp_path / "partial.json"
    runner.invoke(app, ["scan", "m", "-c", "misinformation", "--json", str(out),
                        "--fail-on", "never", "-w", "1"])
    return out


def test_resume_only_reruns_what_did_not_complete(tmp_path, monkeypatch):
    out = _partial(tmp_path, monkeypatch)
    prior = json.loads(out.read_text())
    errored = prior["errors"]
    assert errored, "fixture should have produced errors"

    calls = {"n": 0}

    def count(*a, **k):
        calls["n"] += 1
        return HELD

    monkeypatch.setattr(engine, "probe", count)
    final = tmp_path / "final.json"
    r = runner.invoke(app, ["scan", "m", "-c", "misinformation", "--resume", str(out),
                            "--json", str(final), "--fail-on", "never"])
    assert r.exit_code == 0, flat(r.output)
    assert calls["n"] == errored, "re-ran vectors that had already completed"

    merged = json.loads(final.read_text())
    assert merged["total"] == 30
    assert merged["errors"] == 0


def test_resume_reuses_the_prior_canary(tmp_path, monkeypatch):
    """A new canary would invalidate the results being merged in."""
    out = _partial(tmp_path, monkeypatch)
    prior_canary = json.loads(out.read_text())["canary"]
    monkeypatch.setattr(engine, "probe", lambda *a, **k: HELD)
    final = tmp_path / "final.json"
    runner.invoke(app, ["scan", "m", "-c", "misinformation", "--resume", str(out),
                        "--json", str(final), "--fail-on", "never"])
    assert json.loads(final.read_text())["canary"] == prior_canary


def test_resume_does_not_treat_blank_replies_as_done(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "")
    out = tmp_path / "blank.json"
    runner.invoke(app, ["scan", "m", "-c", "misinformation", "--json", str(out),
                        "--fail-on", "never"])
    calls = {"n": 0}
    monkeypatch.setattr(engine, "probe",
                        lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1), HELD)[1])
    runner.invoke(app, ["scan", "m", "-c", "misinformation", "--resume", str(out),
                        "--fail-on", "never"])
    assert calls["n"] == 30, "blank replies were counted as completed"


# --- markdown --------------------------------------------------------------

def test_markdown_written(monkeypatch, tmp_path):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "ACME-X")
    out = tmp_path / "r.md"
    runner.invoke(app, ["scan", "m", "--id", "jb-003", "--canary", "ACME-X",
                        "--markdown", str(out), "--fail-on", "never"])
    text = out.read_text()
    assert text.startswith("## LRTF scan")
    assert "jb-003" in text
    assert text.count("```") % 2 == 0, "unbalanced code fences"


def test_markdown_neutralises_fences_in_model_output():
    from lrtf import report
    rep = {"model": "m", "scanned_at": "t", "canary": "c", "total": 1, "requests": 1,
           "vulnerable": 1, "errors": 0, "blank": 0,
           "by_severity": {"high": 1, "medium": 0, "low": 0}, "risk": "HIGH",
           "findings": [{"vector": {"id": "x", "category": "c", "severity": "high",
                                    "title": "t", "prompt": "p", "turns": []},
                         "vulnerable": True, "response": "```\nbreak out\n```",
                         "evidence": "e", "error": "", "replies": [], "turn": 0,
                         "runs": 1, "hits": 1}]}
    md = report.markdown(rep)
    assert md.count("```") % 2 == 0
    assert "break out" in md
