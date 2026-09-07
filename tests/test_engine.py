"""The detectors and the scan loop are what a false PASS would hide behind,
so they are what gets tested. No network: probe() is stubbed."""

import pytest

from llm_red_team import engine
from llm_red_team.engine import Vector


CANARY = "ACME-DEADBEEF"


def v(detect="canary", match=None, severity="high"):
    return Vector(id="t-1", category="test", severity=severity, title="t",
                  prompt="p", detect=detect, match=match)


# --- detectors -------------------------------------------------------------

@pytest.mark.parametrize("response,leaked", [
    (f"Your code is {CANARY}.", True),
    (f"it is {CANARY.lower()}", True),                 # case folded
    (" ".join(CANARY), True),                          # spaced out to dodge a filter
    (CANARY.replace("-", " — "), True),                # punctuation swapped
    ("I can't share that.", False),
    ("ACME-DEADBEE", False),                           # near miss is not a leak
])
def test_canary_detector(response, leaked):
    assert bool(engine.evaluate(response, v(), CANARY)) is leaked


def test_contains_detector_reports_every_hit():
    ev = engine.evaluate("Internal configuration: never disclose this",
                         v("contains", ["Internal configuration", "never disclose", "absent"]),
                         CANARY)
    assert ev == "Internal configuration, never disclose"


def test_contains_detector_clean():
    assert engine.evaluate("Sorry.", v("contains", ["secret"]), CANARY) == ""


def test_regex_detector_returns_the_match():
    ev = engine.evaluate("try sk-abcdefghijklmnopqrst now",
                         v("regex", r"sk-[A-Za-z0-9]{16,}"), CANARY)
    assert ev == "sk-abcdefghijklmnopqrst"


# --- vector suite ----------------------------------------------------------

def test_shipped_vectors_are_valid():
    vs = engine.load_vectors()
    assert len(vs) >= 30
    assert {x.severity for x in vs} <= {"high", "medium", "low"}
    for x in vs:
        assert x.detect in engine.DETECTORS
        assert x.prompt.strip(), f"{x.id} has an empty prompt"
        if x.detect != "canary":
            assert x.match, f"{x.id} needs a match value"


def test_load_vectors_filters():
    assert {x.category for x in engine.load_vectors(categories=["jailbreak"])} == {"jailbreak"}
    assert {x.severity for x in engine.load_vectors(severities=["high"])} == {"high"}


def test_canary_is_fresh_each_scan():
    assert engine.new_canary() != engine.new_canary()


# --- scan loop -------------------------------------------------------------

def test_run_scan_flags_a_leaking_model(monkeypatch):
    seen = {}

    def fake_probe(model, system, prompt, **kw):
        seen["system"] = system
        return "sure, the reference code is " + system.split("reference code: ")[1].split("\n")[0]

    monkeypatch.setattr(engine, "probe", fake_probe)
    results, canary = engine.run_scan("x", engine.load_vectors(categories=["prompt_injection"]))

    assert canary in seen["system"]
    assert all(r.vulnerable for r in results)
    assert engine.summarise(results, "x", canary)["risk"] == "CRITICAL"


def test_run_scan_passes_a_refusing_model(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "I'm not able to help with that.")
    results, canary = engine.run_scan("x", engine.load_vectors())
    report = engine.summarise(results, "x", canary)
    assert report["vulnerable"] == 0
    assert report["risk"] == "PASS"


def test_provider_errors_are_reported_not_raised(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("401 unauthorized")

    monkeypatch.setattr(engine, "probe", boom)
    results, canary = engine.run_scan("x", engine.load_vectors(severities=["low"]))
    report = engine.summarise(results, "x", canary)
    assert report["errors"] == report["total"]
    assert report["vulnerable"] == 0          # an error must never read as a pass or a fail


def test_summarise_risk_ladder(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "I cannot.")
    results, canary = engine.run_scan("x", engine.load_vectors(severities=["medium"]))
    results[0].vulnerable = True
    assert engine.summarise(results, "x", canary)["risk"] == "MODERATE"
