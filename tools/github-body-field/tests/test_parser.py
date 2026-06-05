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
from __future__ import annotations

import pytest

from github_body_field.parser import (
    FieldNotFoundError,
    extract_field,
    list_fields,
    replace_field,
)

CANONICAL_BODY = (
    "<!-- a preamble comment from the issue template -->\n"
    "\n"
    "### CVE tool link\n"
    "\n"
    "https://cveprocess.apache.org/cve5/CVE-2026-12345\n"
    "\n"
    "### Reporter credited as\n"
    "\n"
    "anonymous\n"
    "\n"
    "### Short public summary for publish\n"
    "\n"
    "Upgrade to apache-airflow 3.3.0 or later.\n"
    "\n"
    "### Affected versions\n"
    "\n"
    "`>= 3.0.0, < 3.3.0`\n"
)


# ---------------------------------------------------------------------------
# list_fields
# ---------------------------------------------------------------------------


def test_list_fields_returns_headings_in_order():
    assert list_fields(CANONICAL_BODY) == [
        "CVE tool link",
        "Reporter credited as",
        "Short public summary for publish",
        "Affected versions",
    ]


def test_list_fields_empty_body():
    assert list_fields("") == []


def test_list_fields_no_headings():
    assert list_fields("just some prose, no headings.\n") == []


def test_list_fields_ignores_headings_in_code_fences():
    body = "### Real field\n\n```bash\n### not a heading\necho hi\n```\n\n### Another real\n\nvalue\n"
    assert list_fields(body) == ["Real field", "Another real"]


def test_list_fields_ignores_headings_in_tilde_fences():
    body = "### Real field\n\n~~~\n### still inside a fence\n~~~\n\n### Next real\n\nvalue\n"
    assert list_fields(body) == ["Real field", "Next real"]


def test_list_fields_does_not_match_h2_or_h4():
    body = "## Not a field (h2)\n\n### A real field\n\nvalue\n\n#### Subsection (h4)\n\nmore content\n"
    assert list_fields(body) == ["A real field"]


def test_list_fields_trims_trailing_whitespace_in_heading_name():
    body = "### Field with trailing space   \n\nvalue\n"
    assert list_fields(body) == ["Field with trailing space"]


def test_list_fields_reports_duplicates_as_separate_entries():
    body = "### Same\n\nvalue 1\n\n### Same\n\nvalue 2\n"
    assert list_fields(body) == ["Same", "Same"]


# ---------------------------------------------------------------------------
# extract_field
# ---------------------------------------------------------------------------


def test_extract_field_middle_section():
    assert extract_field(CANONICAL_BODY, "Reporter credited as") == "anonymous\n"


def test_extract_field_first_section():
    assert (
        extract_field(CANONICAL_BODY, "CVE tool link")
        == "https://cveprocess.apache.org/cve5/CVE-2026-12345\n"
    )


def test_extract_field_last_section():
    assert extract_field(CANONICAL_BODY, "Affected versions") == "`>= 3.0.0, < 3.3.0`\n"


def test_extract_field_multiline_value():
    body = "### Notes\n\nline 1\nline 2\n\nline 4 (internal blank preserved)\n\n### Next\n\nx\n"
    assert extract_field(body, "Notes") == ("line 1\nline 2\n\nline 4 (internal blank preserved)\n")


def test_extract_field_value_with_inline_code_fence_containing_hash():
    body = (
        "### Repro\n"
        "\n"
        "```python\n"
        "### this looks like a heading but is inside a fence\n"
        "print(1)\n"
        "```\n"
        "\n"
        "### Next\n"
        "\n"
        "x\n"
    )
    assert extract_field(body, "Repro") == (
        "```python\n### this looks like a heading but is inside a fence\nprint(1)\n```\n"
    )


def test_extract_field_missing_raises():
    with pytest.raises(FieldNotFoundError, match="not found"):
        extract_field(CANONICAL_BODY, "Nonexistent")


def test_extract_field_duplicate_raises():
    body = "### Same\n\nv1\n\n### Same\n\nv2\n"
    with pytest.raises(FieldNotFoundError, match="appears 2 times"):
        extract_field(body, "Same")


# ---------------------------------------------------------------------------
# replace_field
# ---------------------------------------------------------------------------


def test_replace_field_keeps_other_sections_byte_exact():
    new = replace_field(CANONICAL_BODY, "Reporter credited as", "Jane Doe (@jdoe)\n")
    # The unchanged sections should round-trip identically.
    assert "### CVE tool link\n\nhttps://cveprocess.apache.org/cve5/CVE-2026-12345\n\n" in new
    assert "### Short public summary for publish\n\nUpgrade to apache-airflow 3.3.0 or later.\n\n" in new
    assert "### Affected versions\n\n`>= 3.0.0, < 3.3.0`\n" in new
    # The targeted section now carries the new value.
    assert "### Reporter credited as\n\nJane Doe (@jdoe)\n\n" in new
    # And the old value is gone.
    assert "anonymous" not in new


def test_replace_field_with_value_missing_trailing_newline():
    """A value passed without a trailing \\n should still produce a
    well-formed section (no glued-on next heading)."""
    new = replace_field(CANONICAL_BODY, "Reporter credited as", "Jane")
    assert "### Reporter credited as\n\nJane\n\n### Short public summary" in new


def test_replace_field_preserves_spacer_blank_line():
    new = replace_field(CANONICAL_BODY, "Reporter credited as", "x")
    # The blank line between "x" and the next heading must survive.
    assert "### Reporter credited as\n\nx\n\n### Short public summary" in new


def test_replace_field_idempotent_when_value_unchanged():
    same = extract_field(CANONICAL_BODY, "Reporter credited as")
    new = replace_field(CANONICAL_BODY, "Reporter credited as", same)
    assert new == CANONICAL_BODY


def test_replace_field_last_section_does_not_pad_with_extra_blank():
    new = replace_field(CANONICAL_BODY, "Affected versions", "`< 3.3.0`")
    # Last section: original body ended exactly one newline after the
    # value, so the replacement should too — no extra blank.
    assert new.endswith("### Affected versions\n\n`< 3.3.0`\n")


def test_replace_field_preserves_preamble_byte_exact():
    new = replace_field(CANONICAL_BODY, "CVE tool link", "https://example.test/x")
    assert new.startswith("<!-- a preamble comment from the issue template -->\n\n")


def test_replace_field_does_not_treat_fenced_heading_as_section_break():
    """A `### Foo` line inside a fenced code block must not fool the
    parser into ending the current section. We verify by replacing a
    *different* section and showing the fenced block in section A
    survives byte-exact."""
    body = "### A\n\n```\n### Bogus heading inside fence\necho hi\n```\n\n### B\n\nv\n"
    new = replace_field(body, "B", "new_v\n")
    assert "```\n### Bogus heading inside fence\necho hi\n```" in new
    assert new.startswith("### A\n\n```\n### Bogus heading inside fence\necho hi\n```\n\n")
    assert new.endswith("### B\n\nnew_v\n")


def test_replace_field_value_can_contain_inline_code_with_pound_signs():
    new = replace_field(CANONICAL_BODY, "Affected versions", "Comment: see `### Field` in the docs.\n")
    assert "### Affected versions\n\nComment: see `### Field` in the docs.\n" in new


def test_replace_field_missing_raises_without_mutating():
    body = CANONICAL_BODY
    with pytest.raises(FieldNotFoundError):
        replace_field(body, "Nope", "x")


def test_replace_field_duplicate_raises_without_mutating():
    body = "### Same\n\nv1\n\n### Same\n\nv2\n"
    with pytest.raises(FieldNotFoundError, match="appears 2 times"):
        replace_field(body, "Same", "new")


def test_replace_field_value_with_multiple_trailing_blanks_normalised():
    """A caller passing a value padded with extra trailing blanks
    should not stack blank lines on top of the section spacer."""
    new = replace_field(CANONICAL_BODY, "Reporter credited as", "jane\n\n\n\n")
    # Exactly one spacer blank between the new value and the next heading.
    assert "### Reporter credited as\n\njane\n\n### Short public summary" in new


def test_replace_field_empty_value():
    new = replace_field(CANONICAL_BODY, "Reporter credited as", "")
    # Empty value still produces a well-formed section: the heading, a
    # single newline (to terminate the heading line), and the spacer.
    assert "### Reporter credited as\n\n### Short public summary" in new


def test_replace_field_field_with_no_spacer_before_next_heading():
    """Some legacy bodies pack headings without a blank-line spacer
    between sections. Replacement should still not break the next
    heading."""
    body = "### A\nv1\n### B\nv2\n"
    new = replace_field(body, "A", "new1\n")
    # No spacer originally → don't invent one.
    assert new == "### A\nnew1\n### B\nv2\n"


# ---------------------------------------------------------------------------
# trailer preservation on the last field (the clobbering fix)
# ---------------------------------------------------------------------------

# Mirrors a real tracker body: the last form field (`CVE tool link`) is
# followed by a `<details>` "Recommended fix" disclosure and an
# HTML-comment-delimited generate-cve-json record. Both are trailers that
# belong to the issue, not to the last field.
BODY_WITH_TRAILER = (
    "### Severity\n"
    "\n"
    "HIGH\n"
    "\n"
    "### CVE tool link\n"
    "\n"
    "_No response_\n"
    "\n"
    "<details><summary>Recommended fix (per the source markdown)</summary>\n"
    "\n"
    "Stop accepting bananas.\n"
    "\n"
    "</details>\n"
    "\n"
    "<!-- generate-cve-json: cve=CVE-2026-90001 version=v1 -->\n"
    "```json\n"
    '{"cveId": "CVE-2026-90001"}\n'
    "```\n"
    "<!-- generate-cve-json:end cve=CVE-2026-90001 version=v1 -->\n"
)


def test_extract_last_field_ignores_trailer():
    # The value is just `_No response_`, not the trailing details/JSON.
    assert extract_field(BODY_WITH_TRAILER, "CVE tool link") == "_No response_\n"


def test_replace_last_field_preserves_details_trailer():
    new = replace_field(
        BODY_WITH_TRAILER, "CVE tool link", "https://cveprocess.apache.org/cve5/CVE-2026-90001"
    )
    # The value was rewritten…
    assert "### CVE tool link\n\nhttps://cveprocess.apache.org/cve5/CVE-2026-90001\n\n" in new
    assert "_No response_" not in new
    # …and BOTH trailers survived byte-exact.
    assert "<details><summary>Recommended fix (per the source markdown)</summary>" in new
    assert "Stop accepting bananas." in new
    assert "<!-- generate-cve-json: cve=CVE-2026-90001 version=v1 -->" in new
    assert '{"cveId": "CVE-2026-90001"}' in new
    assert new.endswith("<!-- generate-cve-json:end cve=CVE-2026-90001 version=v1 -->\n")
    # Earlier section untouched.
    assert "### Severity\n\nHIGH\n\n" in new


def test_replace_last_field_value_then_trailer_spacing_is_single_blank():
    new = replace_field(BODY_WITH_TRAILER, "CVE tool link", "X")
    # Exactly one blank line between the new value and the trailer.
    assert "### CVE tool link\n\nX\n\n<details>" in new


def test_replace_last_field_empty_value_keeps_trailer():
    new = replace_field(BODY_WITH_TRAILER, "CVE tool link", "")
    # Empty value collapses to a single spacer, trailer preserved.
    assert "### CVE tool link\n\n<details><summary>Recommended fix" in new
    assert "<!-- generate-cve-json: cve=CVE-2026-90001 version=v1 -->" in new


def test_trailer_inside_code_fence_is_not_treated_as_trailer():
    # A `<details>` that lives *inside* the last field's fenced code
    # block is genuine field content, not a trailer — it must be
    # replaced along with the rest of the value.
    body = (
        "### Notes\n"
        "\n"
        "real value\n"
        "\n"
        "```html\n"
        "<details>not a trailer — inside a fence</details>\n"
        "```\n"
    )
    new = replace_field(body, "Notes", "new value\n")
    assert new == "### Notes\n\nnew value\n"
    assert "not a trailer" not in new


def test_list_fields_unaffected_by_trailer():
    # Trailers are not headings, so field discovery is unchanged.
    assert list_fields(BODY_WITH_TRAILER) == ["Severity", "CVE tool link"]


def test_replace_non_last_field_with_trailer_present_is_byte_exact_elsewhere():
    # Replacing a non-last field must leave the last field + its
    # trailers completely untouched.
    new = replace_field(BODY_WITH_TRAILER, "Severity", "LOW\n")
    assert "### Severity\n\nLOW\n\n" in new
    assert "### CVE tool link\n\n_No response_\n\n<details>" in new
    assert new.endswith("<!-- generate-cve-json:end cve=CVE-2026-90001 version=v1 -->\n")
