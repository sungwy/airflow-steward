# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Pure parser + composer for the status-rollup comment shape.

The on-disk spec lives at
[`tools/github/status-rollup.md`](../../../../github/status-rollup.md);
this module is the executable spec the CLI dispatches to. Keeping
the parser pure (no I/O, no `gh` shellouts) lets the tests exhaust
every edge case (legacy variants, missing rulers, embedded
backticks, trailing whitespace) without mocking subprocess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Slug-agnostic detector. A rollup marker is `<!-- <slug> status rollup
# v<N> … -->` for *any* adopter slug — `airflow-s`, `myorg/myrepo`, etc.
# Keying detection off the literal `airflow-s` meant any other adopter's
# marker went unrecognised, so `append` created a *second* rollup comment
# instead of folding into the existing one. This regex matches the shape,
# not the reference adopter's name, while still matching every legacy
# `airflow-s` marker.
_ROLLUP_MARKER_RE = re.compile(r"^<!--\s+\S.*?\bstatus rollup v\d+\b", re.IGNORECASE)

# Full first-line marker the tool writes when creating a new rollup with
# no explicit slug. Matches what every existing skill emits.
_DEFAULT_MARKER_LINE = (
    "<!-- airflow-s status rollup v1 — all bot-authored status updates fold into this single comment. -->"
)


def is_rollup_marker(text: str) -> bool:
    """True if ``text`` (a full comment body or just its first line)
    opens with a status-rollup marker, regardless of the adopter slug.

    Detection matches the marker *shape*, not any single adopter's slug,
    so a rollup written by a non-``airflow-s`` adopter (or hand-authored
    with the adopter's own slug) is still recognised — otherwise
    ``append`` creates a duplicate rollup comment.
    """
    first_line = text.split("\n", 1)[0]
    return bool(_ROLLUP_MARKER_RE.match(first_line))


def build_marker_line(slug: str) -> str:
    """Compose a rollup marker line for ``slug`` (e.g. an adopter's
    ``owner/repo``). Detection (:func:`is_rollup_marker`) is slug-
    agnostic, so any slug round-trips."""
    return f"<!-- {slug} status rollup v1 — all bot-authored status updates fold into this single comment. -->"

# Between consecutive `<details>` entries we always write exactly one
# blank line, a horizontal rule, and one blank line. Keeping this as
# a module constant guarantees `append` lays it down byte-identical
# every time so the regex round-trips.
_RULER_BETWEEN_ENTRIES = "\n\n---\n\n"

# Open and close tags for one rollup entry. The open tag is one line
# per the spec — split-tag variants get normalised on the next write.
_OPEN_TAG_RE = re.compile(r"^<details><summary>(.+?)</summary>$", re.MULTILINE)
_CLOSE_TAG = "</details>"


@dataclass(frozen=True)
class RollupEntry:
    """One parsed rollup entry."""

    date: str  # YYYY-MM-DD
    user: str  # @handle (with leading `@`)
    action: str  # human-friendly action label
    body: str  # the markdown between <summary>...</summary> and </details>


def parse_summary_line(summary: str) -> RollupEntry | None:
    """Parse the summary line's three middle-dot-separated fields.

    Returns ``None`` when the summary doesn't follow the
    `YYYY-MM-DD · @handle · <Action>` shape — the caller can keep
    the entry as raw text without failing the whole parse.
    """
    parts = [p.strip() for p in summary.split("·")]
    if len(parts) != 3:
        return None
    date, user, action = parts
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        return None
    if not user.startswith("@") or len(user) < 2:
        return None
    if not action:
        return None
    return RollupEntry(date=date, user=user, action=action, body="")


def iter_entries(rollup_body: str) -> list[RollupEntry]:
    """Walk a full rollup-comment body and return every entry it
    contains, ordered top-to-bottom.

    Robust to:

    - the marker line at the top of the comment,
    - rulers (`---`) between entries,
    - entries whose summary doesn't follow the canonical shape
      (those are returned with `date=user=action=""` and the
      surrounding context still in `body` for downstream
      preservation),
    - trailing whitespace and missing trailing newline.
    """
    text = rollup_body
    # Drop the marker line if present so the regex doesn't false-match
    # the marker's HTML-comment content. Slug-agnostic: any adopter's
    # marker, not just `airflow-s`.
    if is_rollup_marker(text):
        nl = text.find("\n")
        text = text[nl + 1 :] if nl != -1 else ""

    entries: list[RollupEntry] = []
    pos = 0
    for match in _OPEN_TAG_RE.finditer(text):
        summary = match.group(1)
        body_start = match.end()
        close_idx = text.find(f"\n{_CLOSE_TAG}", body_start)
        if close_idx == -1:
            # Tolerate a missing close tag at end-of-body.
            entry_body = text[body_start:].lstrip("\n").rstrip()
            next_pos = len(text)
        else:
            entry_body = text[body_start:close_idx].lstrip("\n").rstrip()
            next_pos = close_idx + len(f"\n{_CLOSE_TAG}")
        parsed = parse_summary_line(summary)
        if parsed is None:
            entries.append(RollupEntry(date="", user="", action="", body=entry_body))
        else:
            entries.append(
                RollupEntry(
                    date=parsed.date,
                    user=parsed.user,
                    action=parsed.action,
                    body=entry_body,
                )
            )
        pos = next_pos
    # `pos` is unused for the return but kept so future callers can
    # compute trailing content if they need to.
    _ = pos
    return entries


def build_entry(*, date: str, user: str, action: str, body: str) -> str:
    """Compose one rollup entry — the `<details>...</details>` block
    a single sync pass appends to the rollup.

    The result has no trailing newline; the caller decides whether
    to glue a ruler before it. The body's leading + trailing
    whitespace is stripped to keep the rendered shape consistent.
    """
    if not user.startswith("@"):
        user = f"@{user}"
    body_stripped = body.strip()
    summary = f"{date} · {user} · {action}"
    return f"<details><summary>{summary}</summary>\n\n{body_stripped}\n\n{_CLOSE_TAG}"


def build_new_rollup_body(entry: str, marker_line: str | None = None) -> str:
    """Compose a brand-new rollup comment body wrapping the first
    entry. Use when no rollup comment exists yet on the tracker.

    ``marker_line`` lets an adopter write a marker carrying its own slug
    (see :func:`build_marker_line`); when omitted the canonical
    ``airflow-s`` default is used for backward compatibility.
    """
    return f"{marker_line or _DEFAULT_MARKER_LINE}\n{entry}"


def rebuild_with_appended_entry(existing_body: str, new_entry: str) -> str:
    """Append ``new_entry`` to an existing rollup body, separated by
    the canonical ruler block. Strips any trailing whitespace from
    ``existing_body`` so the ruler lands in the right place.
    """
    return f"{existing_body.rstrip()}{_RULER_BETWEEN_ENTRIES}{new_entry}"
