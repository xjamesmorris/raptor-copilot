"""diagrams.md goes through the atomic-write substrate.

A crash mid-write used to leave a half-written diagrams.md in place
(the file is re-rendered and consumed by other tools). Pin the
substrate adoption so the plain write_text doesn't re-grow.
"""

import json
from unittest import mock

from ..renderer import render_and_write


def test_render_and_write_uses_atomic_substrate(tmp_path):
    (tmp_path / "hypotheses.json").write_text(
        json.dumps({"hypotheses": [{"id": "H1", "status": "exploring"}]}),
        encoding="utf-8",
    )
    with mock.patch(
        "packages.diagram.renderer.write_text_atomically",
    ) as atomic:
        out = render_and_write(tmp_path, target="t")
    atomic.assert_called_once()
    args, kwargs = atomic.call_args
    assert args[0] == tmp_path / "diagrams.md"
    assert "Security Diagrams" in args[1]
    assert out == tmp_path / "diagrams.md"


def test_render_and_write_still_produces_file(tmp_path):
    out = render_and_write(tmp_path, target="t")
    assert out.is_file()
    assert "Security Diagrams" in out.read_text(encoding="utf-8")
