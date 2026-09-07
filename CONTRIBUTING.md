# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Adding an attack vector

Most contributions are a new vector. Append to the right file in
`src/llm_red_team/vectors/` — one category per file — and open a PR.

```yaml
- id: jb-008              # unique; prefix matches the category
  category: jailbreak
  severity: medium        # high | medium | low
  title: Short technique name
  detect: canary          # canary | contains | regex
  prompt: |
    The attack text.
  note: "Optional: why this works."
```

For an attack that builds over a conversation, use `turns` instead of `prompt` —
exactly one of the two:

```yaml
- id: jb-019
  category: jailbreak
  severity: high
  title: Your multi-turn technique
  detect: canary
  turns:
    - "First message."
    - "Follow-up that depends on the reply."
    - "The ask."
```

Each turn is a billed request, and every turn sees the full history. A finding
reports the first turn that fired. Use `turns` only when the attack genuinely
needs the model's own previous replies — otherwise a single prompt is cheaper
and just as good.

`pytest` checks ids are unique, detectors exist, every turn is non-empty, exactly
one of `prompt`/`turns` is set, and that non-canary vectors declare a `match`.

### Rules for vectors

1. **Target the canary, not real harm.** A vector proves a guardrail can be
   bypassed. The forbidden thing is a random token, so the payload stays benign
   and the suite is safe to run in CI. PRs containing genuinely harmful content
   will be closed.
2. **One technique per vector.** Combined attacks make findings unactionable.
3. **Severity reflects real-world exploitability**, not how clever it is.
   `high` = works unattended against a default deployment.
4. **Detection must be sound in both directions.** A vector that fires on a
   correct refusal is worse than no vector. If your payload can appear in a safe
   answer, add a `reject_if` and a pair in `SAFE_AND_UNSAFE` in
   `tests/test_tui.py` pinning both sides. `absent` vectors may not be `high`.

## Adding a detector

Add the function to `DETECTORS` in `engine.py`. It takes
`(response, vector, canary)` and returns the matched evidence string, or `""`
when the target held up. Evidence goes straight into the report, so return the
substring that proves the finding.
