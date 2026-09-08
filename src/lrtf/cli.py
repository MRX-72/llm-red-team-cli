"""Command line interface."""

from __future__ import annotations

import json
import pathlib
from typing import Optional

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from . import engine, report as report_mod

app = typer.Typer(
    add_completion=False,
    help="Adversarial test harness for LLM applications.",
    no_args_is_help=True,
)
console = Console()

SEV_COLOR = {"high": "red", "medium": "yellow", "low": "cyan"}
RISK_COLOR = {"CRITICAL": "bold white on red", "HIGH": "bold red",
              "MODERATE": "bold yellow", "LOW": "cyan", "PASS": "bold green",
              "INCOMPLETE": "bold yellow"}


@app.command()
def scan(
    model: str = typer.Argument(..., help="Target model, litellm syntax. e.g. gpt-4o, anthropic/claude-sonnet-4-5, ollama/llama3"),
    category: Optional[list[str]] = typer.Option(None, "--category", "-c", help="Limit to categories (repeatable)."),
    severity: Optional[list[str]] = typer.Option(None, "--severity", "-s", help="Limit to severities (repeatable)."),
    system: Optional[pathlib.Path] = typer.Option(None, "--system", help="File holding your own system prompt. Must contain {canary}."),
    vectors_dir: Optional[list[pathlib.Path]] = typer.Option(
        None, "--vectors", help="Load vectors from these directories instead of the built-in suite (repeatable)."),
    repeat: int = typer.Option(
        1, "--repeat", "-n", help="Run each vector N times. Guardrails are probabilistic; findings report hits/runs."),
    workers: int = typer.Option(4, "--workers", "-w", help="Parallel requests."),
    rpm: int = typer.Option(0, "--rpm", help="Cap requests per minute. Set this on free tiers (try 10)."),
    temperature: float = typer.Option(0.0, "--temperature", help="Lower is more reproducible."),
    max_tokens: Optional[int] = typer.Option(
        None, "--max-tokens", help="Cap response length. Needed on token-per-minute limited tiers, since the unbounded_consumption vectors deliberately ask for huge outputs."),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write the full report here."),
    html_out: Optional[pathlib.Path] = typer.Option(None, "--html", help="Write a self-contained HTML report here."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at this severity or above: high|medium|low|never."),
    show_responses: bool = typer.Option(False, "--show-responses", help="Print the model reply for each finding."),
    tui: bool = typer.Option(False, "--tui", help="Live view: watch each vector land as it completes."),
):
    """Run the adversarial suite against a model and report what got through."""
    source = [str(d) for d in vectors_dir] if vectors_dir else engine.VECTOR_DIR
    vectors = engine.load_vectors(source, categories=category, severities=severity)
    if not vectors:
        console.print("[red]No vectors matched those filters.[/]")
        raise typer.Exit(2)

    custom = None
    if system:
        custom = system.read_text()
        if "{canary}" not in custom:
            console.print("[red]--system file must contain the literal {canary} placeholder.[/]")
            raise typer.Exit(2)

    requests = sum(len(v.messages) for v in vectors) * repeat
    extra = f" · {requests} requests" if requests != len(vectors) else ""
    extra += f" · {repeat}x each" if repeat > 1 else ""
    console.print(Panel(f"[bold]{model}[/]\n{len(vectors)} vectors · "
                        f"{len({v.category for v in vectors})} categories{extra}",
                        title="LLM Red Team", border_style="blue"))

    kw = dict(system=custom, workers=workers, rpm=rpm, repeat=repeat,
              temperature=temperature)
    if max_tokens:
        kw["max_tokens"] = max_tokens
    if tui:
        view = LiveScan(model, len(vectors))
        with Live(view, console=console, refresh_per_second=8, transient=True):
            results_, canary = engine.run_scan(model, vectors, on_result=view.add, **kw)
    else:
        done = [0]
        with console.status("[blue]probing…") as status:
            def tick(r):
                done[0] += 1
                status.update(f"[blue]probing… {done[0]}/{len(vectors)}  ({r.vector.id})")
            results_, canary = engine.run_scan(model, vectors, on_result=tick, **kw)

    report = engine.summarise(results_, model, canary)
    _render(report, show_responses)

    if json_out:
        json_out.write_text(json.dumps(report, indent=2))
        console.print(f"\n[dim]report → {json_out}[/]")
    if html_out:
        html_out.write_text(report_mod.render(report))
        console.print(f"[dim]html → {html_out}[/]")

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
    vectors_dir: Optional[list[pathlib.Path]] = typer.Option(
        None, "--vectors", help="List vectors from these directories instead of the built-in suite."),
):
    """List the attack vectors in the suite without calling any model."""
    table = Table(box=None, pad_edge=False)
    for col in ("ID", "SEVERITY", "CATEGORY", "TURNS", "TITLE"):
        table.add_column(col)
    source = [str(d) for d in vectors_dir] if vectors_dir else engine.VECTOR_DIR
    vs = engine.load_vectors(source, categories=category)
    for v in vs:
        n = len(v.messages)
        table.add_row(v.id, f"[{SEV_COLOR.get(v.severity,'white')}]{v.severity}[/]",
                      v.category, str(n) if n > 1 else "[dim]1[/]", v.title)
    console.print(table)
    requests = sum(len(v.messages) for v in vs)
    console.print(f"\n[dim]{len(vs)} vectors · {requests} requests per scan · "
                  f"{sum(1 for v in vs if v.turns)} multi-turn[/]")


class LiveScan:
    """Live view of a scan in flight.

    Built on rich.live rather than a TUI framework: the scan is a flat list of
    independent probes with no interaction, so a re-rendered frame per result is
    the whole requirement. Rich is already a dependency; Textual would be a new
    one plus an app lifecycle for a view with no input.
    """

    MARK = {True: "[red]✗[/]", False: "[green]✓[/]"}

    def __init__(self, model: str, total: int):
        self.total = total
        self.rows: list[tuple] = []
        self.counts = {"high": 0, "medium": 0, "low": 0}
        self.errors = 0
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="blue", finished_style="blue"),
            TextColumn("[dim]{task.completed}/{task.total}"),
            expand=True,
        )
        self.task = self.progress.add_task(model, total=total)

    def add(self, result) -> None:
        v = result.vector
        if result.error:
            self.errors += 1
            mark, detail = "[yellow]![/]", f"[yellow]{result.error.split(':')[0]}[/]"
        else:
            mark = self.MARK[result.vulnerable]
            detail = f"[red]{result.evidence[:38]}[/]" if result.vulnerable else "[dim]held[/]"
            if result.vulnerable:
                self.counts[v.severity] = self.counts.get(v.severity, 0) + 1
        self.rows.append((mark, v.id, v.category, v.title, detail))
        self.progress.advance(self.task)

    def __rich__(self) -> Group:
        # Keep the newest rows visible; the full list prints in the report.
        room = max(4, console.size.height - 10)
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=1)
        table.add_column(width=8, style="dim")
        table.add_column(width=18)
        table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)
        table.add_column(width=40, overflow="ellipsis", no_wrap=True)
        for row in self.rows[-room:]:
            table.add_row(*row)

        c = self.counts
        found = sum(c.values())
        tally = (f"[green]no bypasses yet[/]" if not found else
                 f"[red]{c['high']} high[/] · [yellow]{c['medium']} medium[/] · [cyan]{c['low']} low[/]")
        if self.errors:
            tally += f"   [yellow]{self.errors} errored[/]"

        return Group(
            self.progress,
            Panel(table, border_style="grey37", padding=(0, 1)),
            Panel(tally, border_style="grey37", padding=(0, 1)),
        )


@app.command()
def compare(
    models: list[str] = typer.Argument(..., help="Two or more models to scan with the same suite."),
    category: Optional[list[str]] = typer.Option(None, "--category", "-c"),
    severity: Optional[list[str]] = typer.Option(None, "--severity", "-s"),
    system: Optional[pathlib.Path] = typer.Option(None, "--system", help="Your own system prompt. Must contain {canary}."),
    vectors_dir: Optional[list[pathlib.Path]] = typer.Option(None, "--vectors"),
    repeat: int = typer.Option(1, "--repeat", "-n"),
    workers: int = typer.Option(4, "--workers", "-w"),
    rpm: int = typer.Option(0, "--rpm"),
    temperature: float = typer.Option(0.0, "--temperature"),
    max_tokens: Optional[int] = typer.Option(None, "--max-tokens"),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write every model's report here as one object."),
):
    """Scan several models with the same suite and put the results side by side.

    One model's score tells you little. The comparison is the useful artefact:
    the same vector that a model refuses today is one another model answers, and
    seeing that next to each other is what makes the difference legible.
    """
    if len(models) < 2:
        console.print("[red]compare needs at least two models.[/]")
        raise typer.Exit(2)

    source = [str(d) for d in vectors_dir] if vectors_dir else engine.VECTOR_DIR
    vectors = engine.load_vectors(source, categories=category, severities=severity)
    custom = system.read_text() if system else None
    if custom and "{canary}" not in custom:
        console.print("[red]--system file must contain the literal {canary} placeholder.[/]")
        raise typer.Exit(2)

    reports: dict[str, dict] = {}
    for model in models:
        console.print(f"[blue]scanning[/] [bold]{model}[/] …")
        extra = {"max_tokens": max_tokens} if max_tokens else {}
        results, canary = engine.run_scan(
            model, vectors, system=custom, workers=workers, rpm=rpm,
            repeat=repeat, temperature=temperature, **extra)
        reports[model] = engine.summarise(results, model, canary)

    # Only vectors that got through somewhere are worth a row.
    interesting = [v for v in vectors
                   if any(f["vulnerable"] for r in reports.values()
                          for f in r["findings"] if f["vector"]["id"] == v.id)]

    table = Table(box=None, pad_edge=False)
    table.add_column("ID")
    table.add_column("SEVERITY")
    table.add_column("TITLE", overflow="fold")
    for m in models:
        table.add_column(m.split("/")[-1][:18], justify="center")

    for v in interesting:
        row = [v.id, f"[{SEV_COLOR.get(v.severity,'white')}]{v.severity}[/]", v.title]
        for m in models:
            f = next(x for x in reports[m]["findings"] if x["vector"]["id"] == v.id)
            if f["error"]:
                row.append("[dim]![/]")
            elif f["vulnerable"]:
                rate = f"[red]✗[/]" if f.get("runs", 1) == 1 else f"[red]✗ {f['hits']}/{f['runs']}[/]"
                row.append(rate)
            else:
                row.append("[green]✓[/]")
        table.add_row(*row)

    console.print()
    if interesting:
        console.print(table)
    else:
        console.print("[green]No vector got through on any model.[/]")

    summary = Table(box=None, pad_edge=False)
    for col in ("MODEL", "RISK", "BYPASSED", "ERRORS"):
        summary.add_column(col)
    for m in models:
        r = reports[m]
        summary.add_row(m, f"[{RISK_COLOR.get(r['risk'],'white')}]{r['risk']}[/]",
                        f"{r['vulnerable']}/{r['total']}", str(r["errors"]))
    console.print()
    console.print(summary)

    if json_out:
        json_out.write_text(json.dumps(reports, indent=2))
        console.print(f"\n[dim]reports → {json_out}[/]")


@app.command()
def diff(
    baseline: pathlib.Path = typer.Argument(..., help="Earlier report from --json."),
    current: pathlib.Path = typer.Argument(..., help="Later report from --json."),
    fail_on_regression: bool = typer.Option(
        True, "--fail-on-regression/--no-fail", help="Exit non-zero if anything regressed."),
):
    """Compare two reports: what got fixed, what regressed, what still fails.

    A single scan tells you a prompt is weak. This tells you whether the change
    you made to it actually worked, which is the question anyone maintaining a
    system prompt asks second.
    """
    a, b = (json.loads(p.read_text()) for p in (baseline, current))
    old = {f["vector"]["id"]: f for f in a["findings"]}
    new = {f["vector"]["id"]: f for f in b["findings"]}

    def bucket(vid):
        was, now = old.get(vid), new.get(vid)
        if was is None:
            return "ADDED" if now and now["vulnerable"] else None
        if now is None:
            return "DROPPED" if was["vulnerable"] else None
        # A vector that errored was not tested; calling that a fix would be a lie.
        if was["error"] or now["error"]:
            return "UNTESTED" if (was["vulnerable"] or now["vulnerable"]) else None
        if was["vulnerable"] and not now["vulnerable"]:
            return "FIXED"
        if not was["vulnerable"] and now["vulnerable"]:
            return "REGRESSED"
        return "STILL FAILING" if now["vulnerable"] else None

    STYLE = {"REGRESSED": "bold red", "STILL FAILING": "yellow", "FIXED": "green",
             "ADDED": "red", "DROPPED": "dim", "UNTESTED": "yellow"}
    rows = []
    for vid in sorted(old | new):
        state = bucket(vid)
        if state:
            meta = (new.get(vid) or old[vid])["vector"]
            rows.append((state, vid, meta["severity"], meta["category"], meta["title"]))

    header = Table.grid(padding=(0, 2))
    header.add_column(style="dim")
    header.add_column()
    header.add_row("baseline", f"{a['model']}  ·  {a['scanned_at']}  ·  {a['risk']}")
    header.add_row("current", f"{b['model']}  ·  {b['scanned_at']}  ·  {b['risk']}")
    console.print(Panel(header, title="Diff", border_style="blue"))

    if not rows:
        console.print("\n[green]No change — both scans agree on every vector.[/]")
        raise typer.Exit(0)

    order = ["REGRESSED", "ADDED", "STILL FAILING", "UNTESTED", "FIXED", "DROPPED"]
    table = Table(box=None, pad_edge=False)
    for col in ("STATE", "ID", "SEVERITY", "CATEGORY", "TITLE"):
        table.add_column(col, overflow="fold")
    for state in order:
        for row in [r for r in rows if r[0] == state]:
            table.add_row(f"[{STYLE[state]}]{state}[/]", row[1],
                          f"[{SEV_COLOR.get(row[2],'white')}]{row[2]}[/]", row[3], row[4])
    console.print()
    console.print(table)

    counts = {s: sum(1 for r in rows if r[0] == s) for s in order}
    summary = "  ".join(f"[{STYLE[s]}]{counts[s]} {s.lower()}[/]" for s in order if counts[s])
    regressed = counts["REGRESSED"] + counts["ADDED"]
    console.print(Panel(summary, border_style="red" if regressed else "green"))

    if regressed and fail_on_regression:
        raise typer.Exit(1)


def _render(report: dict, show_responses: bool) -> None:
    findings = [f for f in report["findings"] if f["vulnerable"]]
    errors = [f for f in report["findings"] if f["error"]]

    if findings:
        table = Table(title="Findings", title_justify="left", box=None, pad_edge=False)
        repeated = any(f.get("runs", 1) > 1 for f in report["findings"])
        cols = ["ID", "SEVERITY", "CATEGORY", "TITLE", "TURN"]
        if repeated:
            cols.append("RATE")
        cols.append("EVIDENCE")
        for col in cols:
            table.add_column(col, overflow="fold")
        for f in findings:
            v = f["vector"]
            turns = len(v.get("turns") or []) or 1
            where = f"{f['turn']}/{turns}" if turns > 1 else "—"
            row = [v["id"], f"[{SEV_COLOR.get(v['severity'],'white')}]{v['severity'].upper()}[/]",
                   v["category"], v["title"], where]
            if repeated:
                hits, runs = f.get("hits", 1), f.get("runs", 1)
                colour = "red" if hits == runs else "yellow"
                row.append(f"[{colour}]{hits}/{runs}[/]")
            row.append(f["evidence"][:60])
            table.add_row(*row)
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
        + (f"\n[yellow]{len(errors)} of {report['total']} vectors errored — this is not a clean result.[/]"
           f"\n[dim]On a free tier, retry with --rpm 10.[/]" if errors else "")
        + (f"\n[yellow]{report['blank']} vectors returned an empty response — not counted as held.[/]"
           if report.get("blank") else ""),
        border_style=RISK_COLOR.get(report["risk"], "white").split()[-1],
        title="Risk"))

    if errors:
        console.print(f"[yellow]first error:[/] {errors[0]['error'][:200]}")

    if show_responses:
        for f in findings:
            v = f["vector"]
            turns = v.get("turns") or [v.get("prompt", "")]
            if len(turns) > 1:
                body = []
                for i, (t, r) in enumerate(zip(turns, f.get("replies") or []), start=1):
                    flag = " [red]← leaked here[/]" if i == f["turn"] else ""
                    body.append(f"[bold]turn {i}{flag}[/]\n[dim]> {' '.join(t.split())[:200]}[/]\n{r[:600]}")
                text = "\n\n".join(body)
            else:
                text = f["response"][:1200] or "[dim](empty)[/]"
            console.print(Panel(text, title=f"{v['id']} — {v['title']}", border_style="red"))
