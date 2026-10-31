"""RAPTOR descriptive-schema detection and JSON Schema preservation."""

from __future__ import annotations

import copy
import re
from typing import Any

JSONSchema = dict[str, Any] | bool

JSON_SCHEMA_ROOT_KEYWORDS = frozenset({
    "$comment", "$defs", "$id", "$ref", "$schema", "$vocabulary",
    "additionalItems", "additionalProperties", "allOf", "anyOf",
    "const", "contains", "contentEncoding", "contentMediaType",
    "default", "definitions", "dependencies", "dependentRequired",
    "dependentSchemas", "deprecated", "description", "else", "enum",
    "examples", "exclusiveMaximum", "exclusiveMinimum", "format", "if",
    "items", "maxContains", "maximum", "maxItems", "maxLength",
    "maxProperties", "minContains", "minimum", "minItems", "minLength",
    "minProperties", "multipleOf", "not", "oneOf", "pattern",
    "patternProperties", "prefixItems", "properties", "propertyNames",
    "readOnly", "required", "then", "title", "type", "unevaluatedItems",
    "unevaluatedProperties", "uniqueItems", "writeOnly",
})
_JSON_SCHEMA_PROPERTY_KEYWORDS = frozenset({
    "$ref", "additionalProperties", "allOf", "anyOf", "const",
    "default", "description", "enum", "examples", "format", "items",
    "maximum", "maxItems", "maxLength", "minimum", "minItems",
    "minLength", "oneOf", "pattern", "properties", "required", "title",
    "type",
})
_JSON_PRIMITIVE_TYPES = frozenset({
    "array", "boolean", "integer", "null", "number", "object", "string",
})
_DESCRIPTOR_TYPE_RE = re.compile(
    r"^\s*(array|bool(?:ean)?|dict|float|int(?:eger)?|list|null|"
    r"number|object|str(?:ing)?)(?=$|[\s.,;:()\[\]{}<>/\\|_+=\-—])",
    re.IGNORECASE,
)
_UNAMBIGUOUS_STRING_ROOTS = frozenset({
    "$dynamicRef", "$id", "$recursiveRef", "$ref", "$schema",
})
_DICT_OR_BOOL_ROOTS = frozenset({
    "additionalProperties", "contains", "else", "if", "items", "not",
    "propertyNames", "then", "unevaluatedItems", "unevaluatedProperties",
})
_DICT_ROOTS = frozenset({
    "$defs", "definitions", "dependentSchemas", "patternProperties",
    "properties",
})
_ADVANCED_PASS_THROUGH_ROOTS = frozenset({
    "$dynamicRef", "$recursiveRef", "$ref", "allOf", "anyOf",
    "const", "else", "enum", "if", "not", "oneOf", "then",
})
_SUBSCHEMA_MAP_KEYS = (
    "$defs",
    "definitions",
    "dependentSchemas",
    "patternProperties",
    "properties",
)
_SUBSCHEMA_VALUE_KEYS = (
    "additionalProperties",
    "contains",
    "items",
    "propertyNames",
    "unevaluatedItems",
    "unevaluatedProperties",
)


def descriptor_type_token(value: str) -> str | None:
    match = _DESCRIPTOR_TYPE_RE.match(value)
    if match is None:
        return None
    token = match.group(1).lower()
    return {
        "bool": "boolean",
        "dict": "object",
        "float": "number",
        "int": "integer",
        "list": "array",
        "str": "string",
    }.get(token, token)


def _is_field_descriptor(value: object) -> bool:
    if isinstance(value, str):
        return descriptor_type_token(value) is not None
    if isinstance(value, dict):
        return bool(_JSON_SCHEMA_PROPERTY_KEYWORDS.intersection(value))
    return False


def _keyword_value_is_structural_signal(key: str, value: object) -> bool:
    """True when a keyword/value pair unambiguously spells JSON Schema."""
    if key == "type":
        if isinstance(value, str):
            return value in _JSON_PRIMITIVE_TYPES
        if isinstance(value, list):
            return bool(value) and all(
                item in _JSON_PRIMITIVE_TYPES for item in value
            )
        return False
    if key in _UNAMBIGUOUS_STRING_ROOTS:
        return isinstance(value, str)
    if key in _DICT_ROOTS:
        return isinstance(value, dict)
    if key in _DICT_OR_BOOL_ROOTS:
        return isinstance(value, (dict, bool, list))
    # Lists/numbers/booleans are not field-description shapes, so schemas
    # carrying those values already fail the all-descriptors gate below.
    return False


def is_raptor_descriptive_schema(schema: object) -> bool:
    """Whether *schema* is RAPTOR's field-description shorthand.

    Field names are deliberately ignored for the primary decision: RAPTOR
    findings may legitimately be named ``type``, ``items``, ``title`` or
    ``description``. Values must all look like field descriptors. When every
    field name also happens to be a JSON Schema keyword, only an
    unambiguous keyword/value shape (for example ``type: object`` or
    ``items: {...}``) wins the full-JSON interpretation.
    """
    if not isinstance(schema, dict) or not schema:
        return False
    if not all(_is_field_descriptor(value) for value in schema.values()):
        return False
    if any(key not in JSON_SCHEMA_ROOT_KEYWORDS for key in schema):
        return True
    return not any(
        _keyword_value_is_structural_signal(key, value)
        for key, value in schema.items()
    )


def _add_missing_object_types(schema: JSONSchema) -> JSONSchema:
    """Add object type only to ordinary property-based schema nodes.

    Advanced roots are pass-through contracts: do not rewrite them or their
    descendants. Ordinary object/property nodes are copied before this helper
    runs, so adding ``type`` never mutates caller-owned data.
    """
    if isinstance(schema, bool):
        return schema
    if _ADVANCED_PASS_THROUGH_ROOTS.intersection(schema):
        return schema
    if (
        "properties" not in schema
        and ("$defs" in schema or "definitions" in schema)
    ):
        return schema
    if isinstance(schema.get("properties"), dict) and "type" not in schema:
        schema["type"] = "object"

    for key in _SUBSCHEMA_MAP_KEYS:
        values = schema.get(key)
        if not isinstance(values, dict):
            continue
        for name, subschema in list(values.items()):
            if isinstance(subschema, (dict, bool)):
                values[name] = _add_missing_object_types(subschema)

    for key in _SUBSCHEMA_VALUE_KEYS:
        subschema = schema.get(key)
        if isinstance(subschema, (dict, bool)):
            schema[key] = _add_missing_object_types(subschema)

    prefix_items = schema.get("prefixItems")
    if isinstance(prefix_items, list):
        schema["prefixItems"] = [
            (
                _add_missing_object_types(subschema)
                if isinstance(subschema, (dict, bool))
                else subschema
            )
            for subschema in prefix_items
        ]
    return schema


def normalize_schema(schema: JSONSchema) -> JSONSchema:
    """Convert shorthand, add property-object types, preserve advanced roots."""
    if isinstance(schema, bool):
        return schema
    if not is_raptor_descriptive_schema(schema):
        return _add_missing_object_types(copy.deepcopy(schema))

    properties: dict[str, Any] = {}
    for field_name, field_desc in schema.items():
        if isinstance(field_desc, dict):
            properties[field_name] = copy.deepcopy(field_desc)
            continue

        field_desc_str = str(field_desc)
        parts = field_desc_str.split()
        field_type = descriptor_type_token(field_desc_str) or "string"
        desc_lower = field_desc_str.lower()
        if " or null" in desc_lower:
            prop: dict[str, Any] = {"type": [field_type, "null"]}
        elif desc_lower.startswith("null or "):
            actual = (
                descriptor_type_token(parts[2])
                if len(parts) > 2
                else "string"
            ) or "string"
            prop = {"type": [actual, "null"]}
        else:
            prop = {"type": field_type}

        if field_type == "array":
            prop["items"] = {"type": "string"}
        if " - " in field_desc_str:
            prop["description"] = field_desc_str.split(
                " - ", 1,
            )[1].strip()
        elif "(" in field_desc_str:
            prop["description"] = field_desc_str[
                field_desc_str.find("("):
            ].strip()
        properties[field_name] = prop

    required = []
    for field_name, field_desc in schema.items():
        if isinstance(field_desc, dict):
            required.append(field_name)
            continue
        desc_lower = str(field_desc).lower()
        if "optional" not in desc_lower and "or null" not in desc_lower:
            required.append(field_name)
    return _add_missing_object_types({
        "type": "object",
        "properties": properties,
        "required": required,
    })


__all__ = [
    "JSONSchema",
    "JSON_SCHEMA_ROOT_KEYWORDS",
    "descriptor_type_token",
    "is_raptor_descriptive_schema",
    "normalize_schema",
]
