"""Shared helpers.

`flat` exists because rich wraps to the terminal width, and the width differs
between a developer's terminal and CI. Asserting on a multi-word phrase that
happens to straddle a wrap point passes locally and fails on CI -- which is
exactly what happened to "not valid JSON", rendered as "is not\nvalid JSON" at
80 columns. Collapse the whitespace and the assertion stops depending on the
window it ran in.
"""

import re


def flat(output: str) -> str:
    return re.sub(r"\s+", " ", output)
