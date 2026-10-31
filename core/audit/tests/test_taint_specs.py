"""Tests for core.audit.taint_specs."""

from __future__ import annotations

from pathlib import Path

from core.audit.taint_specs import (
    check_config_dependent,
    check_stored_taint,
)


class TestStoredTaint:
    def test_detects_unescaped_db_read_render(self):
        gaps = [
            {
                "name": "save_bio",
                "file": "profile.py",
                "source": "def save_bio(bio): db.execute('UPDATE users SET bio = %s', (bio,))",
            },
            {
                "name": "show_profile",
                "file": "views.py",
                "source": "def show_profile(uid): row = db.get(uid); return render(row['bio'])",
            },
        ]
        findings = check_stored_taint(gaps)
        assert len(findings) == 1
        assert findings[0].check == "stored_taint"
        assert findings[0].cwe == "CWE-79"

    def test_no_finding_when_sanitized(self):
        gaps = [
            {
                "name": "save",
                "file": "a.py",
                "source": "db.execute('INSERT INTO t VALUES (%s)', (x,))",
            },
            {
                "name": "show",
                "file": "b.py",
                "source": "row = db.get(id); return render(escape(row['data']))",
            },
        ]
        assert check_stored_taint(gaps) == []

    def test_no_finding_without_render(self):
        gaps = [
            {
                "name": "write",
                "file": "a.py",
                "source": "db.execute('INSERT INTO t VALUES (%s)', (x,))",
            },
            {
                "name": "read",
                "file": "b.py",
                "source": "row = db.get(id); return row['count']",
            },
        ]
        assert check_stored_taint(gaps) == []

    def test_no_finding_without_writers(self):
        gaps = [
            {
                "name": "read",
                "file": "a.py",
                "source": "row = db.get(id); return render(row['bio'])",
            },
        ]
        assert check_stored_taint(gaps) == []


class TestConfigDependent:
    def test_detects_config_in_security_decision(self):
        gaps = [
            {
                "name": "check_auth",
                "file": "auth.py",
                "source": (
                    "debug = os.environ.get('DEBUG')\n"
                    "if debug: skip_auth = True"
                ),
            },
        ]
        findings = check_config_dependent(gaps)
        assert len(findings) == 1
        assert findings[0].check == "config_dependent"

    def test_no_finding_for_non_security_config(self):
        gaps = [
            {
                "name": "get_color",
                "file": "ui.py",
                "source": "color = os.environ.get('THEME_COLOR', 'blue')",
            },
        ]
        assert check_config_dependent(gaps) == []


class TestStoredTaintFromDisk:
    """check_stored_taint reads source from disk when gaps lack source."""

    def test_hydrates_from_target_path(self, tmp_path: Path):
        writer = tmp_path / "profile.py"
        writer.write_text(
            "def save_bio(bio):\n"
            "    db.execute('UPDATE users SET bio = %s', (bio,))\n"
        )
        reader = tmp_path / "views.py"
        reader.write_text(
            "def show_profile(uid):\n"
            "    row = db.get(uid)\n"
            "    return render(row['bio'])\n"
        )
        gaps = [
            {"name": "save_bio", "file": "profile.py", "line_start": 1, "line_end": 2},
            {"name": "show_profile", "file": "views.py", "line_start": 1, "line_end": 3},
        ]
        findings = check_stored_taint(gaps, target_path=tmp_path)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-79"

    def test_skips_when_no_target_path(self):
        gaps = [
            {"name": "save_bio", "file": "profile.py", "line_start": 1, "line_end": 2},
            {"name": "show_profile", "file": "views.py", "line_start": 1, "line_end": 3},
        ]
        assert check_stored_taint(gaps) == []

    def test_skips_missing_file(self, tmp_path: Path):
        gaps = [
            {"name": "save_bio", "file": "nonexistent.py", "line_start": 1, "line_end": 2},
        ]
        assert check_stored_taint(gaps, target_path=tmp_path) == []

    def test_skips_when_line_end_is_none(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("db.execute('INSERT INTO t VALUES (%s)', (x,))\n")
        gaps = [
            {"name": "w", "file": "a.py", "line_start": 1, "line_end": None},
        ]
        assert check_stored_taint(gaps, target_path=tmp_path) == []

    def test_skips_path_traversal(self, tmp_path: Path):
        secret = tmp_path / "outside" / "secret.py"
        secret.parent.mkdir()
        secret.write_text("db.execute('INSERT INTO t VALUES (%s)', (x,))\n")
        target = tmp_path / "project"
        target.mkdir()
        gaps = [
            {"name": "w", "file": "../outside/secret.py", "line_start": 1, "line_end": 1},
        ]
        assert check_stored_taint(gaps, target_path=target) == []


class TestConfigDependentFromDisk:
    """check_config_dependent reads source from disk when gaps lack source."""

    def test_hydrates_from_target_path(self, tmp_path: Path):
        src = tmp_path / "auth.py"
        src.write_text(
            "def check_auth():\n"
            "    debug = os.environ.get('DEBUG')\n"
            "    if debug: skip_auth = True\n"
        )
        gaps = [
            {"name": "check_auth", "file": "auth.py", "line_start": 1, "line_end": 3},
        ]
        findings = check_config_dependent(gaps, target_path=tmp_path)
        assert len(findings) == 1
        assert findings[0].check == "config_dependent"

    def test_skips_when_no_target_path(self):
        gaps = [
            {"name": "check_auth", "file": "auth.py", "line_start": 1, "line_end": 3},
        ]
        assert check_config_dependent(gaps) == []

    def test_skips_when_line_end_is_none(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("debug = os.environ.get('DEBUG')\nif debug: skip_auth = True\n")
        gaps = [
            {"name": "f", "file": "a.py", "line_start": 1, "line_end": None},
        ]
        assert check_config_dependent(gaps, target_path=tmp_path) == []
