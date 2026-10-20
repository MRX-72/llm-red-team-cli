# Changelog

## 0.7.0

### Added

- **330 vectors.** Every category expanded to 30, plus 30 published techniques
  that carry a `source` field citing the paper, advisory or CVE.
- **`--escalate N`.** Retries vectors that held through a ladder of buffs
  (base64, rot13, leet, prefix, manyshot, tags) and stops at the first level
  that leaks. Findings name the level and buff that got through.
- **`--buff`.** Applies one transformation to the whole suite.
- **Image and audio vectors.** `media: image | audio` renders the final turn
  into a PNG or a WAV behind a benign caption.
- **The canary detector sees through encodings.** A leak written in base64,
  hex, binary, ROT13, Morse, reversed, spelled out, in leetspeak or lookalike
  letters, or as the hex body alone, now counts. Evidence says how it came out.
- **`lrtf lint`** checks every vector against a corpus of correct refusals, and
  **`lrtf verify`** re-scores stored reports offline against the current
  detectors.
- **Custom detectors** from `lrtf_detectors.py`, without forking the repo.
- **`--baseline`**, `--dry-run`, `--html`, `--markdown`, shell completion, and
  twelve flags for selection, execution and provider routing.
- **Adaptive pacing.** `--rpm` backs off on rate limits and recovers, and gives
  up on a spent quota instead of sleeping for hours.
- `lrtf --version`, and `lrtf_version` in every report.
- `diff` shows when a still-failing vector changed escalation level.

### Fixed

- Native tool calls were invisible to the detectors.
- Curly quotes made correct refusals score as misinformation findings.
- The `tags` buff silently dropped 33 vectors' payloads.
- The throttle held its lock while sleeping.
- `verify` only re-read the last turn of a multi-turn vector, and left the old
  risk verdict in place after `--write`.
- `--escalate` retried vectors that never got an answer, and an escalated
  finding's hits/runs counted the levels that held.
- A bad report path, a bad `--vectors` directory or a missing `--system` file
  printed a traceback instead of an error.

### Changed

- Reports from 0.6 load unchanged. Fields added since (`escalation`,
  `esc_buff`, `esc_runs`, `lrtf_version`) default when absent.

## 0.6.0

- `compare`, `--repeat` and `--vectors`.
