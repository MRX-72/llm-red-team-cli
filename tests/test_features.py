"""--repeat, --vectors and compare. The repeat logic decides whether a finding
is reported at all, so its folding rules are what these pin down."""

import json

import pytest
from typer.testing import CliRunner

from lrtf import engine
from lrtf.cli import app
from lrtf.engine import Vector

runner = CliRunner()
CANARY = "ACME-DEADBEEF"


def v(vid="t-1"):
    return Vector(id=vid, category="jailbreak", severity="high", title="t",
                  detect="canary", prompt="p")


# --- repeat ----------------------------------------------------------------

def test_repeat_multiplies_attempts(monkeypatch):
    calls = {"n": 0}

    def count(*a, **k):
        calls["n"] += 1
        return "no"

    monkeypatch.setattr(engine, "probe", count)
    engine.run_scan("m", [v(), v("t-2")], repeat=4)
    assert calls["n"] == 8


def test_one_leak_in_many_runs_is_still_a_finding(monkeypatch):
    """The whole point: a framing refused twice and answered once is a hole."""
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        return CANARY if calls["n"] == 2 else "I can't share that."

    monkeypatch.setattr(engine, "probe", flaky)
    results, _ = engine.run_scan("m", [v()], canary=CANARY, repeat=3)
    assert results[0].vulnerable
    assert (results[0].hits, results[0].runs) == (1, 3)


def test_consistent_leak_reports_full_rate(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: CANARY)
    results, _ = engine.run_scan("m", [v()], canary=CANARY, repeat=3)
    assert (results[0].hits, results[0].runs) == (3, 3)


def test_never_leaking_reports_zero_hits(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "I can't share that.")
    results, _ = engine.run_scan("m", [v()], canary=CANARY, repeat=3)
    assert not results[0].vulnerable
    assert (results[0].hits, results[0].runs) == (0, 3)


def test_a_clean_run_outweighs_an_errored_one(monkeypatch):
    """One 429 among three attempts must not make the vector look untested."""
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("429 rate limit")
        return "I can't share that."

    monkeypatch.setattr(engine, "probe", flaky)
    results, canary = engine.run_scan("m", [v()], repeat=3)
    assert not results[0].error
    assert engine.summarise(results, "m", canary)["errors"] == 0


def test_all_attempts_erroring_is_still_an_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("401 unauthorized")

    monkeypatch.setattr(engine, "probe", boom)
    results, canary = engine.run_scan("m", [v()], repeat=3)
    assert results[0].error
    assert engine.summarise(results, "m", canary)["risk"] == "INCOMPLETE"


def test_request_count_accounts_for_repeats(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "no")
    vec = Vector(id="t", category="c", severity="low", title="t",
                 detect="canary", turns=["a", "b", "c"])
    results, canary = engine.run_scan("m", [vec], repeat=4)
    assert engine.summarise(results, "m", canary)["requests"] == 12


# --- custom vector directories ---------------------------------------------

def test_loads_vectors_from_a_custom_directory(tmp_path):
    (tmp_path / "mine.yaml").write_text(
        '- id: x-1\n  category: custom\n  severity: high\n  title: Mine\n'
        '  detect: canary\n  prompt: "hello"\n')
    vs = engine.load_vectors(str(tmp_path))
    assert [x.id for x in vs] == ["x-1"]


def test_loads_from_several_directories(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d, vid in ((a, "x-1"), (b, "y-1")):
        d.mkdir()
        (d / "v.yaml").write_text(
            f'- id: {vid}\n  category: custom\n  severity: low\n  title: t\n'
            f'  detect: canary\n  prompt: "hi"\n')
    assert {x.id for x in engine.load_vectors([str(a), str(b)])} == {"x-1", "y-1"}


def test_empty_directory_is_an_error_not_a_silent_pass(tmp_path):
    """Loading nothing then reporting PASS would be the worst possible outcome."""
    with pytest.raises(ValueError, match="no .yaml"):
        engine.load_vectors(str(tmp_path))


def test_duplicate_ids_across_directories_are_rejected(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        (d / "v.yaml").write_text(
            '- id: dup\n  category: c\n  severity: low\n  title: t\n'
            '  detect: canary\n  prompt: "hi"\n')
    with pytest.raises(ValueError, match="duplicate"):
        engine.load_vectors([str(a), str(b)])


def test_cli_vectors_honours_a_custom_directory(tmp_path):
    (tmp_path / "mine.yaml").write_text(
        '- id: x-1\n  category: custom\n  severity: high\n  title: My Vector\n'
        '  detect: canary\n  prompt: "hello"\n')
    r = runner.invoke(app, ["vectors", "--vectors", str(tmp_path)])
    assert "My Vector" in r.output and "1 vectors" in r.output


# --- compare ---------------------------------------------------------------

def test_compare_needs_two_models():
    assert runner.invoke(app, ["compare", "only-one"]).exit_code == 2


def test_compare_puts_models_side_by_side(monkeypatch, tmp_path):
    """One model leaks, the other holds — the contrast is the whole feature."""
    def by_model(model, system, prompt, history=None, **kw):
        canary = system.split("reference code: ")[1].split("\n")[0]
        return canary if model == "weak" else "I can't share that."

    monkeypatch.setattr(engine, "probe", by_model)
    out = tmp_path / "r.json"
    r = runner.invoke(app, ["compare", "weak", "strong", "-c", "jailbreak",
                            "--json", str(out)])
    assert r.exit_code == 0
    assert "weak" in r.output and "strong" in r.output
    reports = json.loads(out.read_text())
    assert reports["weak"]["vulnerable"] > 0
    assert reports["strong"]["vulnerable"] == 0


def test_compare_reports_no_bypass_when_all_models_hold(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "I can't share that.")
    r = runner.invoke(app, ["compare", "a", "b", "-c", "system_prompt_leak"])
    assert "No vector got through on any model" in r.output
