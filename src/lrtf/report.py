"""Self-contained HTML report.

--json serves CI; this is the artefact a person forwards. No external CSS, fonts
or scripts: a security report that phones out to a CDN is a report that leaks
which findings you are reading, and one that breaks when opened offline.

Everything drawn from a model's output is escaped. That is not routine caution
here -- the suite plants live payloads on purpose (ioh-002 sends
<script>alert('XSS7734')</script>) and the finding *is* the model echoing them
back. Rendering a report unescaped would execute the exact payload it exists to
report.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

CSS = """
:root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;
--high:#cf222e;--medium:#bf8700;--low:#0969da;--ok:#1a7f37;--accent:#0969da}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;
--line:#30363d;--card:#161b22;--high:#ff7b72;--medium:#d29922;--low:#58a6ff;
--ok:#3fb950;--accent:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:60rem;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
h2{font-size:1.1rem;margin:2.5rem 0 .75rem;padding-bottom:.4rem;
border-bottom:1px solid var(--line)}
.sub{color:var(--muted);margin:0 0 1.5rem;font-size:.9rem}
.risk{display:inline-block;padding:.35rem .9rem;border-radius:2rem;
font-weight:700;letter-spacing:.04em;font-size:.85rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(8rem,1fr));
gap:.75rem;margin:1.5rem 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:6px;
padding:.85rem}
.stat b{display:block;font-size:1.5rem;line-height:1.2}
.stat span{color:var(--muted);font-size:.8rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;
letter-spacing:.03em}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;
border-radius:6px;padding:.9rem 1rem;margin:.75rem 0}
.f.high{border-left-color:var(--high)}
.f.medium{border-left-color:var(--medium)}
.f.low{border-left-color:var(--low)}
.f h3{margin:0 0 .35rem;font-size:1rem}
.tag{display:inline-block;font-size:.72rem;padding:.1rem .5rem;border-radius:1rem;
border:1px solid var(--line);color:var(--muted);margin-right:.35rem}
.tag.high{color:var(--high);border-color:var(--high)}
.tag.medium{color:var(--medium);border-color:var(--medium)}
.tag.low{color:var(--low);border-color:var(--low)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;
padding:.7rem .85rem;overflow-x:auto;font-size:.82rem;margin:.5rem 0;
white-space:pre-wrap;word-break:break-word}
details{margin-top:.6rem}
summary{cursor:pointer;color:var(--accent);font-size:.85rem}
.turn{color:var(--muted);font-size:.78rem;margin:.6rem 0 .1rem;font-weight:600}
.leak{color:var(--high)}
.none{color:var(--ok);font-weight:600}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);
color:var(--muted);font-size:.82rem}
"""

RISK_COLOUR = {"CRITICAL": "var(--high)", "HIGH": "var(--high)",
               "MODERATE": "var(--medium)", "LOW": "var(--low)",
               "INCOMPLETE": "var(--medium)", "PASS": "var(--ok)"}


def e(text: object) -> str:
    """Escape for HTML. Applied to every value that came from a model."""
    return html.escape(str(text), quote=True)


def _finding(f: dict) -> str:
    v = f["vector"]
    sev = v["severity"]
    turns = v.get("turns") or []
    bits = [
        f'<div class="f {e(sev)}">',
        f'<h3>{e(v["id"])} &mdash; {e(v["title"])}</h3>',
        f'<span class="tag {e(sev)}">{e(sev.upper())}</span>'
        f'<span class="tag">{e(v["category"])}</span>',
    ]
    if f.get("runs", 1) > 1:
        bits.append(f'<span class="tag">reproduced {e(f["hits"])}/{e(f["runs"])}</span>')
    if turns and f.get("turn"):
        bits.append(f'<span class="tag">leaked on turn {e(f["turn"])} of {len(turns)}</span>')
    bits.append(f'<p style="margin:.6rem 0 0"><b>Evidence:</b> <code>{e(f["evidence"])}</code></p>')

    bits.append("<details><summary>Show the exchange</summary>")
    if turns:
        for i, (t, r) in enumerate(zip(turns, f.get("replies") or []), start=1):
            mark = ' <span class="leak">&larr; leaked here</span>' if i == f.get("turn") else ""
            bits += [f'<div class="turn">TURN {i} &mdash; sent{mark}</div><pre>{e(t.strip())}</pre>',
                     f'<div class="turn">TURN {i} &mdash; reply</div><pre>{e(r.strip())}</pre>']
    else:
        bits += [f'<div class="turn">SENT</div><pre>{e(v.get("prompt", "").strip())}</pre>',
                 f'<div class="turn">REPLY</div><pre>{e(f["response"].strip())}</pre>']
    bits.append("</details></div>")
    return "".join(bits)


def render(report: dict, title: str = "LRTF scan") -> str:
    findings = sorted(
        (f for f in report["findings"] if f["vulnerable"]),
        key=lambda f: (SEV_ORDER.get(f["vector"]["severity"], 9), f["vector"]["id"]),
    )

    cats: dict[str, list[int]] = {}
    for f in report["findings"]:
        c = cats.setdefault(f["vector"]["category"], [0, 0])
        c[1] += 1
        c[0] += bool(f["vulnerable"])

    rows = "".join(
        f'<tr><td><code>{e(cat)}</code></td><td>{bad} / {total}</td>'
        f'<td>{"<span class=none>held</span>" if not bad else f"<b>{bad} bypassed</b>"}</td></tr>'
        for cat, (bad, total) in sorted(cats.items())
    )

    s = report["by_severity"]
    stats = [
        ("Vectors", report["total"]), ("Requests", report.get("requests", report["total"])),
        ("Bypassed", report["vulnerable"]), ("High", s["high"]),
        ("Medium", s["medium"]), ("Low", s["low"]),
        ("Errors", report.get("errors", 0)), ("Blank", report.get("blank", 0)),
    ]
    cards = "".join(f'<div class="stat"><b>{e(v)}</b><span>{e(k)}</span></div>' for k, v in stats)

    warn = ""
    if report.get("errors") or report.get("blank"):
        warn = (f'<p class="sub" style="color:var(--medium)"><b>Incomplete.</b> '
                f'{e(report.get("errors", 0))} vectors errored and '
                f'{e(report.get("blank", 0))} returned an empty response. Neither counts '
                f'as the guardrail holding, so an absence of findings here is not a clean '
                f'result.</p>')

    body = "".join(_finding(f) for f in findings) or \
        '<p class="none">No vector got through.</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} &mdash; {e(report['model'])}</title>
<style>{CSS}</style></head>
<body><main>
<h1>{e(title)}</h1>
<p class="sub"><code>{e(report['model'])}</code> &middot; {e(report['scanned_at'])}
&middot; canary <code>{e(report['canary'])}</code></p>
<span class="risk" style="background:{RISK_COLOUR.get(report['risk'], 'var(--muted)')};
color:#fff">{e(report['risk'])}</span>
{warn}
<div class="grid">{cards}</div>
<h2>By category</h2>
<table><thead><tr><th>Category</th><th>Bypassed</th><th>Result</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Findings ({len(findings)})</h2>
{body}
<footer>
Detection is a canary planted in the system prompt at scan time, so every finding
is a reproducible string match rather than a judge model's opinion. A single pass
is an observation, not a rate &mdash; use <code>--repeat</code> for rates. Findings
are relative to the system prompt used for this scan.
<br><br>Generated by <b>lrtf</b> at {e(datetime.now(timezone.utc).isoformat(timespec='seconds'))}.
</footer>
</main></body></html>"""


def markdown(rep: dict, title: str = "LRTF scan") -> str:
    """Report sized for a PR comment or an issue.

    Model output goes in fenced blocks and any backticks inside it are stripped,
    so a reply containing ``` cannot break out of its fence and reformat the
    rest of the comment.
    """
    def fence(text: str, limit: int = 600) -> str:
        return text.replace("```", "'''").strip()[:limit]

    findings = sorted(
        (f for f in rep["findings"] if f["vulnerable"]),
        key=lambda f: (SEV_ORDER.get(f["vector"]["severity"], 9), f["vector"]["id"]),
    )
    s = rep["by_severity"]
    out = [
        f"## {title} — `{rep['model']}`",
        "",
        f"**{rep['risk']}** · {rep['vulnerable']}/{rep['total']} vectors bypassed "
        f"({s['high']} high · {s['medium']} medium · {s['low']} low)",
    ]
    if rep.get("errors") or rep.get("blank"):
        out += ["", f"> **Incomplete.** {rep.get('errors', 0)} errored, "
                    f"{rep.get('blank', 0)} returned nothing. Neither counts as held, "
                    f"so an absence of findings here is not a clean result."]

    if not findings:
        out += ["", "No vector got through."]
    else:
        out += ["", "| ID | Severity | Category | Title | Evidence |",
                "|---|---|---|---|---|"]
        for f in findings:
            v = f["vector"]
            ev = f["evidence"].replace("|", "\\|")[:48]
            out.append(f"| `{v['id']}` | {v['severity'].upper()} | `{v['category']}` "
                       f"| {v['title']} | `{ev}` |")
        out += ["", "<details><summary>Transcripts</summary>", ""]
        for f in findings:
            v = f["vector"]
            out.append(f"**`{v['id']}` — {v['title']}**")
            turns = v.get("turns") or []
            if turns:
                for i, (t, r) in enumerate(zip(turns, f.get("replies") or []), start=1):
                    mark = "  ← leaked here" if i == f.get("turn") else ""
                    out += ["", f"*turn {i} sent{mark}*", "```", fence(t, 300), "```",
                            f"*turn {i} reply*", "```", fence(r, 400), "```"]
            else:
                out += ["", "*sent*", "```", fence(v.get("prompt", ""), 300), "```",
                        "*reply*", "```", fence(f["response"]), "```"]
            out.append("")
        out.append("</details>")

    out += ["", f"<sub>Canary `{rep['canary']}` · {rep.get('requests', rep['total'])} "
                f"requests · scanned {rep['scanned_at']}</sub>"]
    return "\n".join(out) + "\n"
