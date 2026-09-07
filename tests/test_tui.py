"""The live view carries its own tallies, so it can disagree with the report.
These pin them together."""

from rich.console import Console

from llm_red_team import engine
from llm_red_team.cli import LiveScan
from llm_red_team.engine import Result, Vector


def vec(vid="v-1", severity="high"):
    return Vector(id=vid, category="jailbreak", severity=severity,
                  title="t", prompt="p", detect="canary")


def test_counts_match_the_report(monkeypatch):
    monkeypatch.setattr(engine, "probe", lambda *a, **k: "UNBOUND: ACME-X")
    vectors = engine.load_vectors(categories=["jailbreak"])
    view = LiveScan("m", len(vectors))
    results, canary = engine.run_scan("m", vectors, canary="ACME-X", on_result=view.add)
    report = engine.summarise(results, "m", canary)
    assert view.counts == report["by_severity"]
    assert view.errors == report["errors"]


def test_errors_are_not_counted_as_findings():
    view = LiveScan("m", 2)
    view.add(Result(vec(), False, "", error="RateLimitError: 429"))
    view.add(Result(vec("v-2"), True, "leaked", evidence="ACME-X"))
    assert view.errors == 1
    assert view.counts["high"] == 1


def test_row_marks():
    view = LiveScan("m", 3)
    view.add(Result(vec("a"), True, "r", evidence="ACME-X"))
    view.add(Result(vec("b"), False, "r"))
    view.add(Result(vec("c"), False, "", error="Boom: x"))
    assert [r[0] for r in view.rows] == ["[red]✗[/]", "[green]✓[/]", "[yellow]![/]"]


def test_renders_on_a_short_terminal_without_error(monkeypatch):
    """Row count must adapt to height, and never go non-positive."""
    view = LiveScan("m", 60)
    for i in range(60):
        view.add(Result(vec(f"v-{i}"), i % 5 == 0, "r", evidence="ACME-X"))
    for height in (6, 12, 50):
        console = Console(width=100, height=height, record=True)
        console.print(view)
        assert console.export_text().strip()


def test_progress_tracks_completion():
    view = LiveScan("m", 3)
    for i in range(3):
        view.add(Result(vec(f"v-{i}"), False, "r"))
    assert view.progress.tasks[0].completed == 3
