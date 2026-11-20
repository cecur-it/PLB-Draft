"""Edge-sanitisation parity (CONTRACT §3) and payload guards.

Traces: PROMPT §2.3, CONTRACT §3 (control-char strip, 8000-char cap, secret redaction), §15 (no payload bodies).
"""

from __future__ import annotations

import pytest
import sanitize as sz


def test_control_characters_are_stripped_but_tab_and_newline_survive():
    assert sz.clean("a\x00b\x07c\x1bd\x7fe\tf\ng\r") == "abcde\tf\ng"


def test_truncation_is_utf8_safe_and_marked():
    out = sz.clean("é" * 10, limit=5)
    assert out == "éé" + sz.TRUNCATED
    assert sz.clean("x" * 8000) == "x" * 8000
    assert sz.clean("x" * 8001) == "x" * 8000 + sz.TRUNCATED


def test_cap_follows_cs3_message_max_chars(monkeypatch):
    monkeypatch.setenv("CS3_MESSAGE_MAX_CHARS", "10")
    assert sz.clean("y" * 11) == "y" * 10 + sz.TRUNCATED
    monkeypatch.setenv("CS3_MESSAGE_MAX_CHARS", "nonsense")
    assert sz.max_chars() == 8000


@pytest.mark.parametrize(("raw", "expected"), [
    ("Authorization: Bearer abc.DEF-123_x==", "Authorization: [REDACTED] [REDACTED]"),
    ("bearer eyJhbGciOi.payload.sig", "bearer [REDACTED]"),
    ("password=hunter2&user=bob", "password=[REDACTED]&user=bob"),
    ('{"api_key": "sk-123", "ok": 1}', '{"api_key": "[REDACTED]", "ok": 1}'),
    ("API-KEY: abcdef", "API-KEY: [REDACTED]"),
    ("secret='s3cr3t' token:t0k3n", "secret='[REDACTED]' token:[REDACTED]"),
    ("nothing sensitive here", "nothing sensitive here"),
])
def test_secret_redaction(raw, expected):
    assert sz.redact(raw) == expected


def test_sanitize_text_cleans_then_redacts():
    assert sz.sanitize_text("pass\x00word=hunter2") == "password=[REDACTED]"


def test_fenced_code_is_elided_including_unterminated_blocks():
    assert sz.elide_code("a\n```py\nprint(1)\n```\nb") == "a\n[code block omitted: 18 chars]\nb"
    assert sz.elide_code("a\n~~~\nraw").startswith("a\n[code block omitted:")
    assert sz.elide_code("no fences") == "no fences"


def test_payload_keys_are_dropped_at_any_depth():
    doc = {"a": 1, "poc_script_code": "X", "n": [{"poc_script_code": "Y", "k": 2}], "d": {"poc_script_code": "Z"}}
    assert sz.drop_keys(doc) == {"a": 1, "n": [{"k": 2}], "d": {}}


def test_tool_arguments_keep_context_but_not_code_bodies():
    args = {"command": "id", "code": "import os", "nested": [{"payload": 12345, "x": 1}]}
    assert sz.omit_tool_args(args) == {"command": "id", "code": "[omitted:9 chars]",
                                       "nested": [{"payload": "[omitted:5 chars]", "x": 1}]}


def test_sanitize_value_walks_keys_and_values():
    assert sz.sanitize_value({"token=abc": ["password=x", 3]}) == {"token=[REDACTED]": ["password=[REDACTED]", 3]}
