"""JSON Schema root preservation versus RAPTOR descriptive shorthand."""

from __future__ import annotations

import copy
import json

import pytest

from core.llm.providers import _normalize_schema
from core.llm.response_validation import (
    unknown_response_fields,
    validate_structured_response,
)
from core.llm.schema_normalization import is_raptor_descriptive_schema


@pytest.mark.parametrize("schema", [
    {
        "$ref": "#/$defs/answer",
        "$defs": {
            "answer": {
                "type": "object",
                "properties": {"answer": {"type": "integer"}},
            },
        },
    },
    {"allOf": [{"type": "object"}, {"required": ["answer"]}]},
    {"anyOf": [{"type": "string"}, {"type": "integer"}]},
    {"oneOf": [{"const": "yes"}, {"const": "no"}]},
    {"enum": ["safe", "unsafe"]},
    {"description": "annotation-only schema"},
    {},
    True,
    False,
])
def test_valid_json_schema_roots_are_byte_semantically_preserved(schema):
    before = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)

    normalized = _normalize_schema(schema)

    assert json.dumps(
        normalized,
        separators=(",", ":"),
        ensure_ascii=False,
    ) == before


def test_valid_json_schema_is_deep_copied_without_caller_mutation():
    schema = {
        "allOf": [{
            "type": "object",
            "properties": {"answer": {"type": "integer"}},
        }],
    }
    original = copy.deepcopy(schema)

    normalized = _normalize_schema(schema)
    normalized["allOf"][0]["properties"]["answer"]["minimum"] = 1

    assert schema == original


def test_property_object_root_gains_type_without_mutating_caller():
    schema = {
        "title": "result",
        "properties": {"answer": {"type": "integer"}},
        "required": ["answer"],
        "additionalProperties": False,
    }
    original = copy.deepcopy(schema)

    normalized = _normalize_schema(schema)

    assert normalized == {**schema, "type": "object"}
    assert schema == original


def test_nested_property_object_nodes_gain_type():
    schema = {
        "properties": {
            "metadata": {
                "properties": {"source": {"type": "string"}},
                "required": ["source"],
            },
        },
        "additionalProperties": {
            "properties": {"tag": {"type": "string"}},
        },
    }

    normalized = _normalize_schema(schema)

    assert normalized["type"] == "object"
    assert normalized["properties"]["metadata"]["type"] == "object"
    assert normalized["additionalProperties"]["type"] == "object"
    assert "type" not in schema
    assert "type" not in schema["properties"]["metadata"]


def test_explicit_non_object_root_is_preserved_but_nested_item_is_normalized():
    schema = {
        "type": "array",
        "items": {
            "properties": {"answer": {"type": "integer"}},
            "required": ["answer"],
        },
    }

    normalized = _normalize_schema(schema)

    assert normalized["type"] == "array"
    assert normalized["items"]["type"] == "object"
    assert "type" not in schema["items"]


def test_advanced_root_and_descendants_remain_semantically_unchanged():
    schema = {
        "allOf": [{
            "properties": {"answer": {"type": "integer"}},
            "required": ["answer"],
        }],
    }
    assert _normalize_schema(schema) == schema


def test_descriptive_schema_only_is_converted_and_deep_copied():
    schema = {
        "reasoning": "string - concise rationale",
        "verdict": {
            "type": "string",
            "enum": ["safe", "unsafe"],
        },
    }
    original = copy.deepcopy(schema)

    normalized = _normalize_schema(schema)

    assert normalized == {
        "type": "object",
        "properties": {
            "reasoning": {
                "type": "string",
                "description": "concise rationale",
            },
            "verdict": {
                "type": "string",
                "enum": ["safe", "unsafe"],
            },
        },
        "required": ["reasoning", "verdict"],
    }
    normalized["properties"]["verdict"]["enum"].append("unknown")
    assert schema == original


def test_unknown_annotation_shape_is_preserved_not_guessed_descriptive():
    schema = {"x-private-annotation": "opaque"}
    assert _normalize_schema(schema) == schema


def test_keyword_named_fields_with_punctuation_are_shorthand():
    schema = {
        "items": "list. selected values",
        "description": "string. explanation",
        "type": "bool. verdict",
        "title": "string. display title",
    }
    original = copy.deepcopy(schema)

    normalized = _normalize_schema(schema)

    assert normalized["type"] == "object"
    assert normalized["properties"]["items"]["type"] == "array"
    assert normalized["properties"]["description"]["type"] == "string"
    assert normalized["properties"]["type"]["type"] == "boolean"
    assert normalized["properties"]["title"]["type"] == "string"
    assert normalized["required"] == list(schema)
    assert schema == original
    assert unknown_response_fields(
        {"items": [], "description": "x", "type": True, "title": "t",
         "extra": 1},
        schema,
    ) == ["extra"]

    validated = validate_structured_response({"items": []}, schema)
    assert set(validated.incomplete) == {"description", "type", "title"}


@pytest.mark.parametrize(("field", "descriptor", "expected_type"), [
    ("items", "list. selected values", "array"),
    ("description", "string. explanation", "string"),
    ("type", "bool. verdict", "boolean"),
    ("title", "string. display title", "string"),
])
def test_single_keyword_named_field_is_valid_shorthand(
    field, descriptor, expected_type,
):
    normalized = _normalize_schema({field: descriptor})
    assert normalized["properties"][field]["type"] == expected_type
    assert normalized["required"] == [field]


def test_punctuated_boolean_descriptor_gets_real_type_validation():
    schema = {"type": "bool. verdict"}
    validated = validate_structured_response(
        {"type": {"not": "a boolean"}},
        schema,
    )
    assert validated.data["type"] is None
    assert validated.incomplete == ["type"]


@pytest.mark.parametrize("schema", [
    {
        "type": "object",
        "title": "Widget",
        "description": "string payload returned by the API",
        "properties": {"value": {"type": "string"}},
    },
    {
        "items": {"type": "string"},
        "description": "string elements are allowed",
    },
    {"title": "Widget", "description": "A string payload"},
    {"$ref": "string"},
    {"type": "string", "description": "string output"},
])
def test_full_json_schema_keyword_shapes_are_not_misclassified(schema):
    before = copy.deepcopy(schema)
    assert is_raptor_descriptive_schema(schema) is False
    assert _normalize_schema(schema) == before
    assert schema == before


@pytest.mark.parametrize("schema", [
    {"$ref": "#/$defs/result"},
    {"allOf": [{"type": "object"}]},
    {"anyOf": [{"type": "object"}]},
    {"oneOf": [{"type": "object"}]},
    {"enum": [{"answer": 1}, {"answer": 2}]},
    True,
])
def test_non_field_json_schema_roots_preserve_provider_result(schema):
    raw = {"answer": 1, "extra": "provider-validated"}
    validated = validate_structured_response(raw, schema)
    assert validated.data == raw
    assert validated.quality == 1.0


def test_false_boolean_schema_never_claims_a_valid_result():
    validated = validate_structured_response({"answer": 1}, False)
    assert validated.data == {}
    assert validated.quality == 0.0
    assert validated.incomplete == ["$schema:false"]
