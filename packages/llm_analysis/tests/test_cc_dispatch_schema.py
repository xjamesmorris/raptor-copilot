"""CC dispatch transport contract tests.

Covers two invoke_cc_simple properties:

* the ``--json-schema`` payload handed to the CC transport is real
  JSON Schema — the task layer produces descriptive dicts
  ({"field": "type — description"}) that a JSON-Schema validator
  treats as annotation-only, so they must be normalised exactly like
  the native provider lanes normalise them before use;
* per-invocation debug artifacts never clobber each other under
  parallel dispatch — each failure gets a unique file and each failed
  result's ``cc_debug_file`` points at its own dump.
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis import cc_dispatch  # noqa: E402


@pytest.fixture(autouse=True)
def _transport_enabled(monkeypatch):
    monkeypatch.delenv("RAPTOR_CC_TRANSPORT_DISABLED", raising=False)


class _ConfigRecorder:
    """Wraps CCDispatchConfig, recording every constructed config."""

    def __init__(self):
        self.configs: list = []
        self._real = cc_dispatch.CCDispatchConfig

    def __call__(self, *args, **kwargs):
        config = self._real(*args, **kwargs)
        self.configs.append(config)
        return config


class TestSchemaNormalisedForCCTransport:
    def _invoke(self, monkeypatch, schema):
        recorder = _ConfigRecorder()
        monkeypatch.setattr(cc_dispatch, "CCDispatchConfig", recorder)

        # Abort the invocation right after config construction — the
        # sandbox-launch failure path returns a graceful error result,
        # so the test never spawns anything.
        def _raise(config):
            raise FileNotFoundError("stop after config capture")

        monkeypatch.setattr(cc_dispatch, "system_prompt_file_for", _raise)
        result = cc_dispatch.invoke_cc_simple(
            "prompt", schema, "/tmp/repo", "claude", "/tmp/out",
        )
        assert "error" in result.result  # graceful abort, as arranged
        assert len(recorder.configs) == 1
        return recorder.configs[0].json_schema

    def test_descriptive_schema_converted_to_json_schema(self, monkeypatch):
        descriptive = {
            "reasoning": "string",
            "path_conditions": "list of strings or null - branch conditions",
            "is_exploitable": "bool",
        }
        sent = self._invoke(monkeypatch, descriptive)
        # Real JSON Schema shape: properties with typed entries, not
        # bare descriptive strings the CLI validator would ignore.
        assert sent["type"] == "object"
        assert "properties" in sent
        props = sent["properties"]
        assert props["reasoning"]["type"] == "string"
        assert props["is_exploitable"]["type"] == "boolean"
        # Nullable "or null" descriptive fields become union types.
        assert "null" in props["path_conditions"]["type"]
        # No raw descriptive string survives as a property value.
        assert all(isinstance(v, dict) for v in props.values())

    def test_keyword_named_punctuated_fields_stay_descriptive(
        self, monkeypatch,
    ):
        descriptive = {
            "items": "list. selected values",
            "description": "string. explanation",
            "type": "bool. verdict",
            "title": "string. display title",
        }
        sent = self._invoke(monkeypatch, descriptive)
        assert sent["type"] == "object"
        assert sent["properties"]["items"]["type"] == "array"
        assert sent["properties"]["description"]["type"] == "string"
        assert sent["properties"]["type"]["type"] == "boolean"
        assert sent["properties"]["title"]["type"] == "string"
        assert sent["required"] == list(descriptive)

    def test_property_schema_gains_root_object_type(self, monkeypatch):
        proper = {
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
        }
        sent = self._invoke(monkeypatch, proper)
        assert sent == {**proper, "type": "object"}
        assert "type" not in proper

    def test_nested_property_schema_gains_object_type(self, monkeypatch):
        proper = {
            "type": "array",
            "items": {
                "properties": {"verdict": {"type": "string"}},
                "additionalProperties": False,
            },
        }
        sent = self._invoke(monkeypatch, proper)
        assert sent["type"] == "array"
        assert sent["items"]["type"] == "object"
        assert "type" not in proper["items"]

    @pytest.mark.parametrize("proper", [
        {"$ref": "#/$defs/result", "$defs": {"result": {"type": "object"}}},
        {"allOf": [{"type": "object"}]},
        {"anyOf": [{"type": "object"}]},
        {"oneOf": [{"type": "object"}]},
        {"enum": ["safe", "unsafe"]},
        True,
        False,
    ])
    def test_advanced_json_schema_roots_pass_through(
        self, monkeypatch, proper,
    ):
        sent = self._invoke(monkeypatch, proper)
        assert sent == proper

    def test_explicit_non_object_root_type_is_preserved(self, monkeypatch):
        explicit = {
            "type": "array",
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
        }
        sent = self._invoke(monkeypatch, explicit)
        assert sent == explicit

    def test_none_schema_stays_freeform(self, monkeypatch):
        assert self._invoke(monkeypatch, None) is None

    def test_analysis_schema_normalises(self, monkeypatch):
        # The real task-layer schema (descriptive strings) must come
        # out as a closed, typed JSON Schema.
        from packages.llm_analysis.prompts import build_analysis_schema
        sent = self._invoke(monkeypatch, build_analysis_schema())
        assert sent["type"] == "object"
        assert "properties" in sent
        assert all(isinstance(v, dict) for v in sent["properties"].values())


class TestDebugFilesUniquePerInvocation:
    def _invoke_failing(self, monkeypatch, out_dir):
        @contextlib.contextmanager
        def _no_prompt_file(config):
            yield None

        monkeypatch.setattr(cc_dispatch, "system_prompt_file_for",
                            _no_prompt_file)
        monkeypatch.setattr(cc_dispatch, "build_cc_command",
                            lambda config, system_prompt_file=None: ["true"])

        import core.llm.cc_proxy_hosts as proxy_hosts
        monkeypatch.setattr(proxy_hosts, "proxy_hosts_for_cc_dispatch",
                            lambda claude_bin: [])
        monkeypatch.setattr(proxy_hosts, "readable_paths_for_cc_dispatch",
                            lambda claude_bin: [])

        import core.sandbox as sandbox
        monkeypatch.setattr(
            sandbox, "run_untrusted_networked",
            lambda *a, **kw: SimpleNamespace(
                returncode=1, stdout="child stdout", stderr="child stderr",
            ),
        )
        return cc_dispatch.invoke_cc_simple(
            "prompt", None, "/tmp/repo", "claude", str(out_dir),
        )

    def test_two_failures_write_distinct_debug_files(self, monkeypatch, tmp_path):
        r1 = self._invoke_failing(monkeypatch, tmp_path)
        r2 = self._invoke_failing(monkeypatch, tmp_path)
        f1 = r1.result.get("cc_debug_file")
        f2 = r2.result.get("cc_debug_file")
        assert f1 and f2
        # Each failure keeps its own artifact — a constant name meant
        # parallel failures truncate-wrote the same file and operators
        # debugging finding A read finding B's output.
        assert f1 != f2
        assert (tmp_path / f1).is_file()
        assert (tmp_path / f2).is_file()


class TestEnvelopeAccountingMetadata:
    def _invoke_success(self, monkeypatch, tmp_path, *, schema):
        @contextlib.contextmanager
        def _no_prompt_file(config):
            yield None

        monkeypatch.setattr(
            cc_dispatch, "system_prompt_file_for", _no_prompt_file,
        )
        monkeypatch.setattr(
            cc_dispatch, "build_cc_command",
            lambda config, system_prompt_file=None: ["true"],
        )

        import core.llm.cc_proxy_hosts as proxy_hosts
        monkeypatch.setattr(
            proxy_hosts, "proxy_hosts_for_cc_dispatch",
            lambda claude_bin: [],
        )
        monkeypatch.setattr(
            proxy_hosts, "readable_paths_for_cc_dispatch",
            lambda claude_bin: [],
        )

        payload = (
            {
                "type": "result",
                "structured_output": {"verdict": "ok"},
                "total_cost_usd": 0.25,
                "modelUsage": {"claude-test": {}},
            }
            if schema
            else {
                "type": "result",
                "result": "analysis",
                "total_cost_usd": 0.25,
                "modelUsage": {"claude-test": {}},
            }
        )
        import core.sandbox as sandbox
        monkeypatch.setattr(
            sandbox,
            "run_untrusted_networked",
            lambda *a, **kw: SimpleNamespace(
                returncode=0,
                stdout=json.dumps(payload),
                stderr="",
            ),
        )
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        return cc_dispatch.invoke_cc_simple(
            "prompt",
            schema,
            str(tmp_path),
            "claude",
            str(out_dir),
        ), out_dir

    def test_structured_metadata_is_not_validated_as_model_output(
        self, monkeypatch, tmp_path,
    ):
        from core.llm.accounting import CostBasis, RouteIdentity

        schema = {
            "type": "object",
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
            "additionalProperties": False,
        }
        result, out_dir = self._invoke_success(
            monkeypatch, tmp_path, schema=schema,
        )

        assert result.result["verdict"] == "ok"
        assert "cost_reported" not in result.result
        assert not (out_dir / "debug").exists()
        assert result.cost_observation is not None
        assert result.cost_observation.basis is CostBasis.CLI_REPORTED
        assert result.cost_observation.estimated_usd == pytest.approx(0.25)
        assert result.cost_observation.route == RouteIdentity(
            "claudecode", "claude-test",
        )
        assert result.accounting_complete is True

    def test_freeform_metadata_is_removed_from_task_payload(
        self, monkeypatch, tmp_path,
    ):
        from core.llm.accounting import CostBasis

        result, _out_dir = self._invoke_success(
            monkeypatch, tmp_path, schema=None,
        )

        assert result.result == {"content": "analysis"}
        assert result.cost_observation is not None
        assert result.cost_observation.basis is CostBasis.CLI_REPORTED
