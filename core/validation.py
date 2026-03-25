"""Lightweight resource validation helpers."""

from __future__ import annotations

from typing import Any


def validate_resource(resource: dict[str, Any], required_fields: list[str] | None = None) -> tuple[bool, list[str]]:
    """
    Validate a resource with minimal checks.

    Checks:
    - resource has non-empty id
    - resource has non-empty type
    - all required fields are present and non-empty

    Returns:
        (is_valid, errors)
    """
    errors: list[str] = []

    resource_id = resource.get("id")
    if resource_id is None or str(resource_id).strip() == "":
        errors.append("Missing required field: id")

    resource_type = resource.get("type")
    if resource_type is None or str(resource_type).strip() == "":
        errors.append("Missing required field: type")

    for field in required_fields or []:
        value = resource.get(field)
        if value is None:
            errors.append(f"Missing required field: {field}")
            continue

        if isinstance(value, str) and value.strip() == "":
            errors.append(f"Required field is empty: {field}")

    return (len(errors) == 0, errors)
