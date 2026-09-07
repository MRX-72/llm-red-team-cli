"""Command line interface."""

from __future__ import annotations

import json
import pathlib
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import engine

app = typer.Typer(
    add_completion=False,
    help="Adversarial test harness for LLM applications.",
    no_args_is_help=True,
)
console = Console()

SEV_COLOR = {"high": "red", "medium": "yellow", "low": "cyan"}
RISK_COLOR = {"CRITICAL": "bold white on red", "HIGH": "bold red",
              "MODERATE": "bold yellow", "LOW": "cyan", "PASS": "bold green"}


@app.command()
def scan(
    model: str = typer.Argument(..., help="Target model, litellm syntax. e.g. gpt-4o, anthropic/claude-sonnet-4-5, ollama/llama3"),
    category: Optional[list[str]] = typer.Option(None, "--category", "-c", help="Limit to categories (repeatable)."),
    severity: Optional[list[str]] = typer.Option(None, "--severity", "-s", help="Limit to severities (repeatable)."),
    system: Optional[pathlib.Path] = typer.Option(None, "--system", help="File holding your own system prompt. Must contain {canary}."),
    workers: int = typer.Option(4, "--workers", "-w", help="Parallel requests."),
    temperature: float = typer.Option(0.0, "--temperature", help="Lower is more reproducible."),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write the full report here."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at this severity or above: high|medium|low|never."),
    show_responses: bool = typer.Option(False, "--show-responses", help="Print the model reply for each finding."),
):
    """Run the adversarial suite against a model and report what got through."""
    vectors = engine.load_vectors(categories=category, severities=severity)
    if not vectors:
        console.print("[red]No vectors matched those filters.[/]")
        raise typer.Exit(2)

    custom = None
    if system:
        custom = system.read_text()
        if "{canary}" not in custom:
            console.print("[red]--system file must contain the literal {canary} placeholder.[/]")
            raise typer.Exit(2)

    console.print(Panel(f"[bold]{model}[/]\n{len(vectors)} vectors · "
                        f"{len({v.category for v in vectors})} categories",
                        title="LLM Red Team", border_style="blue"))

    results = []
    with console.status("[blue]probing…") as status:
        def tick(r):
            results.append(r)
            status.update(f"[blue]probing… {len(results)}/{len(vectors)}  ({r.vector.id})")
        results_, canary = engine.run_scan(
            model, vectors, system=custom, workers=workers,
            on_result=tick, temperature=temperature,
        )

    report = engine.summarise(results_, model, canary)
    _render(report, show_responses)

    if json_out:
        json_out.write_text(json.dumps(report, indent=2))
        console.print(f"\n[dim]report → {json_out}[/]")

    thresholds = {"high": ["high"], "medium": ["high", "medium"],
                  "low": ["high", "medium", "low"], "never": []}
    if fail_on not in thresholds:
        console.print(f"[red]--fail-on must be one of {list(thresholds)}[/]")
        raise typer.Exit(2)
    if any(report["by_severity"].get(s) for s in thresholds[fail_on]):
        raise typer.Exit(1)


@app.command()
def vectors(
    category: Optional[list[str]] = typer.Option(None, "--category", "-c"),
):
    """List the attack vectors in the suite without calling any model."""
    table = Table(box=None, pad_edge=False)
    for col in ("ID", "SEVERITY", "CATEGORY", "TITLE"):
        table.add_column(col)
    vs = engine.load_vectors(categories=category)
    for v in vs:
        table.add_row(v.id, f"[{SEV_COLOR.get(v.severity,'white')}]{v.severity}[/]",
                      v.category, v.title)
    console.print(table)
    console.print(f"\n[dim]{len(vs)} vectors[/]")


def _render(report: dict, show_responses: bool) -> None:
    findings = [f for f in report["findings"] if f["vulnerable"]]
    errors = [f for f in report["findings"] if f["error"]]

    if findings:
        table = Table(title="Findings", title_justify="left", box=None, pad_edge=False)
        for col in ("ID", "SEVERITY", "CATEGORY", "TITLE", "EVIDENCE"):
            table.add_column(col, overflow="fold")
        for f in findings:
            v = f["vector"]
            table.add_row(v["id"], f"[{SEV_COLOR.get(v['severity'],'white')}]{v['severity'].upper()}[/]",
                          v["category"], v["title"], f["evidence"][:60])
        console.print()
        console.print(table)

    by_cat: dict[str, list[int]] = {}
    for f in report["findings"]:
        c = by_cat.setdefault(f["vector"]["category"], [0, 0])
        c[1] += 1
        c[0] += f["vulnerable"]

    summary = Table(box=None, pad_edge=False)
    for col in ("CATEGORY", "RESULT"):
        summary.add_column(col)
    for cat, (bad, total) in sorted(by_cat.items()):
        mark = "[green]✓ passed[/]" if not bad else f"[red]✗ {bad}/{total} bypassed[/]"
        summary.add_row(cat, mark)
    console.print()
    console.print(summary)

    s = report["by_severity"]
    console.print(Panel(
        f"[{RISK_COLOR.get(report['risk'],'white')}] {report['risk']} [/]   "
        f"{report['vulnerable']}/{report['total']} vectors succeeded"
        f"   ([red]{s['high']} high[/] · [yellow]{s['medium']} medium[/] · [cyan]{s['low']} low[/])"
        + (f"\n[dim]{len(errors)} vectors errored — result is incomplete[/]" if errors else ""),
        border_style=RISK_COLOR.get(report["risk"], "white").split()[-1],
        title="Risk"))

    if errors:
        console.print(f"[yellow]first error:[/] {errors[0]['error'][:200]}")

    if show_responses:
        for f in findings:
            console.print(Panel(f["response"][:1200] or "[dim](empty)[/]",
                                title=f"{f['vector']['id']} — {f['vector']['title']}",
                                border_style="red"))
