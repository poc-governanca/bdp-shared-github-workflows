#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator


ALLOWED_BUILD_PROFILES = {
    "dotnet",
    "java",
    "node",
    "python",
    "none",
}

LANGUAGE_BUILD_PROFILES = {
    "dotnet": {"dotnet"},
    "java": {"java"},
    "node": {"node"},
    "javascript": {"node"},
    "typescript": {"node"},
    "python": {"python"},
    "go": {"none"},
}


class ComponentValidationError(Exception):
    """Raised when component configuration is invalid."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate repository components manifest."
    )

    parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--schema",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path("."),
    )

    return parser.parse_args()


def load_yaml(
    path: Path,
) -> dict[str, Any]:
    if not path.exists():
        raise ComponentValidationError(
            f"Manifest does not exist: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            document = yaml.safe_load(file)
    except yaml.YAMLError as error:
        raise ComponentValidationError(
            f"Invalid YAML in {path}: {error}"
        ) from error

    if not isinstance(document, dict):
        raise ComponentValidationError(
            "Components manifest must contain a YAML object."
        )

    return document


def load_json(
    path: Path,
) -> dict[str, Any]:
    if not path.exists():
        raise ComponentValidationError(
            f"Schema does not exist: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            document = json.load(file)
    except json.JSONDecodeError as error:
        raise ComponentValidationError(
            f"Invalid JSON Schema: {error}"
        ) from error

    if not isinstance(document, dict):
        raise ComponentValidationError(
            "JSON Schema must contain an object."
        )

    return document


def validate_schema(
    document: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    validator = Draft202012Validator(
        schema
    )

    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: list(
            error.absolute_path
        ),
    )

    if not errors:
        return

    messages: list[str] = []

    for error in errors:
        location = ".".join(
            str(item)
            for item in error.absolute_path
        ) or "<root>"

        messages.append(
            f"{location}: {error.message}"
        )

    raise ComponentValidationError(
        "Schema validation failed:\n- "
        + "\n- ".join(messages)
    )


def normalize_relative_path(
    value: str,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise ComponentValidationError(
            f"{field_name} must be a string."
        )

    normalized = (
        value.strip()
        .replace("\\", "/")
    )

    while normalized.startswith("./"):
        normalized = normalized[2:]

    if not normalized:
        raise ComponentValidationError(
            f"{field_name} cannot be empty."
        )

    if normalized == ".":
        return "."

    path = PurePosixPath(
        normalized
    )

    if path.is_absolute():
        raise ComponentValidationError(
            f"{field_name} cannot be absolute: {value}"
        )

    if ".." in path.parts:
        raise ComponentValidationError(
            f"{field_name} cannot contain '..': {value}"
        )

    return str(path)


def validate_relative_path(
    value: str,
    field_name: str,
) -> None:
    normalize_relative_path(
        value,
        field_name,
    )


def normalize_glob(
    value: str,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise ComponentValidationError(
            f"{field_name} must be a string."
        )

    normalized = (
        value.strip()
        .replace("\\", "/")
    )

    while normalized.startswith("./"):
        normalized = normalized[2:]

    if not normalized:
        raise ComponentValidationError(
            f"{field_name} cannot be empty."
        )

    if normalized.startswith("/"):
        raise ComponentValidationError(
            f"{field_name} cannot start with '/': {value}"
        )

    if ".." in PurePosixPath(
        normalized
    ).parts:
        raise ComponentValidationError(
            f"{field_name} cannot contain '..': {value}"
        )

    return normalized


def validate_glob(
    value: str,
    field_name: str,
) -> None:
    normalize_glob(
        value,
        field_name,
    )


def validate_build(
    name: str,
    component: dict[str, Any],
) -> None:
    language = component["language"]
    build = component["build"]

    enabled = build["enabled"]
    profile = build["profile"]

    if profile not in ALLOWED_BUILD_PROFILES:
        raise ComponentValidationError(
            f"{name}: unsupported build profile '{profile}'."
        )

    if enabled and profile == "none":
        raise ComponentValidationError(
            f"{name}: build is enabled but profile is 'none'."
        )

    if not enabled and profile != "none":
        raise ComponentValidationError(
            f"{name}: build is disabled but profile "
            f"is '{profile}'. Expected 'none'."
        )

    if not enabled:
        return

    allowed_profiles = (
        LANGUAGE_BUILD_PROFILES.get(
            language
        )
    )

    if not allowed_profiles:
        raise ComponentValidationError(
            f"{name}: no build policy exists "
            f"for language '{language}'."
        )

    if profile not in allowed_profiles:
        expected = ", ".join(
            sorted(allowed_profiles)
        )

        raise ComponentValidationError(
            f"{name}: language '{language}' "
            f"is incompatible with build profile "
            f"'{profile}'. Expected one of: {expected}."
        )


def validate_container(
    name: str,
    component: dict[str, Any],
    repository_root: Path,
) -> None:
    container = component["container"]

    if not container["enabled"]:
        return

    for field in (
        "image_name",
        "dockerfile",
        "build_context",
    ):
        value = container.get(field)

        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise ComponentValidationError(
                f"{name}: container.{field} is required "
                "when container is enabled."
            )

    dockerfile = normalize_relative_path(
        container["dockerfile"],
        f"{name}.container.dockerfile",
    )

    build_context = normalize_relative_path(
        container["build_context"],
        f"{name}.container.build_context",
    )

    if not (
        repository_root
        / dockerfile
    ).is_file():
        raise ComponentValidationError(
            f"{name}: Dockerfile does not exist: "
            f"{dockerfile}"
        )

    if not (
        repository_root
        / build_context
    ).is_dir():
        raise ComponentValidationError(
            f"{name}: build_context must be an "
            f"existing directory: {build_context}"
        )


def validate_component_infrastructure(
    name: str,
    component: dict[str, Any],
    repository_root: Path,
) -> None:
    infrastructure = component[
        "infrastructure"
    ]

    if not infrastructure["enabled"]:
        return

    paths = infrastructure.get(
        "paths",
        [],
    )

    scan_path = infrastructure.get(
        "scan_path"
    )

    if not paths:
        raise ComponentValidationError(
            f"{name}: component infrastructure "
            "is enabled but has no paths."
        )

    if (
        not isinstance(scan_path, str)
        or not scan_path.strip()
    ):
        raise ComponentValidationError(
            f"{name}: component infrastructure "
            "is enabled but scan_path is missing."
        )

    infrastructure_patterns: set[str] = set()

    for index, pattern in enumerate(paths):
        normalized = normalize_glob(
            pattern,
            (
                f"{name}.infrastructure."
                f"paths[{index}]"
            ),
        )

        if normalized in infrastructure_patterns:
            raise ComponentValidationError(
                f"{name}: duplicate infrastructure "
                f"path pattern '{normalized}'."
            )

        infrastructure_patterns.add(
            normalized
        )

    normalized_scan_path = (
        normalize_relative_path(
            scan_path,
            (
                f"{name}.infrastructure."
                "scan_path"
            ),
        )
    )

    if not (
        repository_root
        / normalized_scan_path
    ).is_dir():
        raise ComponentValidationError(
            f"{name}: infrastructure scan_path "
            "must be an existing directory: "
            f"{scan_path}"
        )

    application_patterns = {
        normalize_glob(
            pattern,
            f"{name}.paths",
        )
        for pattern
        in component["paths"]
    }

    duplicated_patterns = (
        application_patterns
        & infrastructure_patterns
    )

    if duplicated_patterns:
        duplicated = ", ".join(
            sorted(
                duplicated_patterns
            )
        )

        raise ComponentValidationError(
            f"{name}: the same path pattern cannot "
            "be used for application code and "
            f"component infrastructure: {duplicated}."
        )


def validate_components(
    document: dict[str, Any],
    repository_root: Path,
) -> None:
    components = document[
        "components"
    ]

    image_names: dict[
        str,
        str,
    ] = {}

    for name, component in components.items():
        component_path = (
            normalize_relative_path(
                component["path"],
                f"{name}.path",
            )
        )

        if not (
            repository_root
            / component_path
        ).is_dir():
            raise ComponentValidationError(
                f"{name}: component path "
                "must be an existing directory: "
                f"{component_path}"
            )

        application_patterns: set[str] = set()

        for index, pattern in enumerate(
            component["paths"]
        ):
            normalized = normalize_glob(
                pattern,
                f"{name}.paths[{index}]",
            )

            if normalized in application_patterns:
                raise ComponentValidationError(
                    f"{name}: duplicate application "
                    f"path pattern '{normalized}'."
                )

            application_patterns.add(
                normalized
            )

        validate_build(
            name,
            component,
        )

        validate_container(
            name,
            component,
            repository_root,
        )

        validate_component_infrastructure(
            name,
            component,
            repository_root,
        )

        container = component[
            "container"
        ]

        if container["enabled"]:
            image_name = (
                container["image_name"]
                .strip()
            )

            existing = image_names.get(
                image_name
            )

            if existing:
                raise ComponentValidationError(
                    f"Duplicate container image_name "
                    f"'{image_name}' used by "
                    f"'{existing}' and '{name}'."
                )

            image_names[
                image_name
            ] = name


def validate_shared_paths(
    document: dict[str, Any],
) -> None:
    component_names = set(
        document["components"].keys()
    )

    shared_paths = document.get(
        "shared_paths",
        {},
    )

    if not isinstance(
        shared_paths,
        dict,
    ):
        raise ComponentValidationError(
            "shared_paths must be an object."
        )

    for group_name, group in (
        shared_paths.items()
    ):
        patterns: set[str] = set()

        for index, pattern in enumerate(
            group["paths"]
        ):
            normalized = normalize_glob(
                pattern,
                (
                    f"shared_paths.{group_name}."
                    f"paths[{index}]"
                ),
            )

            if normalized in patterns:
                raise ComponentValidationError(
                    f"shared_paths.{group_name}: "
                    f"duplicate path pattern '{normalized}'."
                )

            patterns.add(
                normalized
            )

        for component_name in group[
            "affects"
        ]:
            if component_name not in component_names:
                raise ComponentValidationError(
                    f"shared_paths.{group_name} "
                    f"references unknown component "
                    f"'{component_name}'."
                )


def validate_global_paths(
    document: dict[str, Any],
) -> None:
    global_paths = document.get(
        "global_paths",
        [],
    )

    if not isinstance(global_paths, list):
        raise ComponentValidationError(
            "global_paths must be an array."
        )

    patterns: set[str] = set()

    for index, pattern in enumerate(
        global_paths
    ):
        normalized = normalize_glob(
            pattern,
            f"global_paths[{index}]",
        )

        if normalized in patterns:
            raise ComponentValidationError(
                "Duplicate global path "
                f"pattern '{normalized}'."
            )

        patterns.add(
            normalized
        )


def validate_repository_controls(
    document: dict[str, Any],
    repository_root: Path,
) -> None:
    controls = document.get(
        "repository_controls",
        {},
    )

    github_actions = controls.get(
        "github_actions"
    )

    if (
        github_actions
        and github_actions["enabled"]
    ):
        paths = github_actions.get(
            "paths",
            [],
        )

        if not paths:
            raise ComponentValidationError(
                "repository_controls.github_actions "
                "is enabled but has no paths."
            )

        patterns: set[str] = set()

        for index, pattern in enumerate(
            paths
        ):
            normalized = normalize_glob(
                pattern,
                (
                    "repository_controls."
                    "github_actions."
                    f"paths[{index}]"
                ),
            )

            if normalized in patterns:
                raise ComponentValidationError(
                    "repository_controls."
                    "github_actions contains "
                    "duplicate path pattern "
                    f"'{normalized}'."
                )

            patterns.add(
                normalized
            )

    infrastructure = controls.get(
        "infrastructure"
    )

    if (
        not infrastructure
        or not infrastructure["enabled"]
    ):
        return

    paths = infrastructure.get(
        "paths",
        [],
    )

    scan_path = infrastructure.get(
        "scan_path"
    )

    if not paths:
        raise ComponentValidationError(
            "Infrastructure control is enabled "
            "but has no paths."
        )

    if (
        not isinstance(scan_path, str)
        or not scan_path.strip()
    ):
        raise ComponentValidationError(
            "Infrastructure control is enabled "
            "but scan_path is missing."
        )

    patterns: set[str] = set()

    for index, pattern in enumerate(
        paths
    ):
        normalized = normalize_glob(
            pattern,
            (
                "repository_controls."
                "infrastructure."
                f"paths[{index}]"
            ),
        )

        if normalized in patterns:
            raise ComponentValidationError(
                "repository_controls."
                "infrastructure contains "
                "duplicate path pattern "
                f"'{normalized}'."
            )

        patterns.add(
            normalized
        )

    normalized_scan_path = (
        normalize_relative_path(
            scan_path,
            (
                "repository_controls."
                "infrastructure.scan_path"
            ),
        )
    )

    if not (
        repository_root
        / normalized_scan_path
    ).is_dir():
        raise ComponentValidationError(
            "Infrastructure scan_path must "
            "be an existing directory: "
            f"{scan_path}"
        )


def validate_policy(
    document: dict[str, Any],
    repository_root: Path,
) -> None:
    validate_components(
        document,
        repository_root,
    )

    validate_shared_paths(
        document
    )

    validate_global_paths(
        document
    )

    validate_repository_controls(
        document,
        repository_root,
    )


def print_summary(
    document: dict[str, Any],
) -> None:
    components = document[
        "components"
    ]

    print(
        "Repository components validation: PASS"
    )

    print(
        f"Components: {len(components)}"
    )

    for name, component in components.items():
        print(
            f"- {name}: "
            f"type={component['type']} "
            f"path={component['path']} "
            f"language={component['language']} "
            f"tier={component['tier']} "
            f"profile={component['build']['profile']} "
            f"container="
            f"{component['container']['enabled']} "
            f"infrastructure="
            f"{component['infrastructure']['enabled']}"
        )


def main() -> int:
    arguments = parse_arguments()

    try:
        repository_root = (
            arguments
            .repository_root
            .resolve()
        )

        if not repository_root.is_dir():
            raise ComponentValidationError(
                "repository-root must be "
                "an existing directory: "
                f"{repository_root}"
            )

        document = load_yaml(
            arguments.manifest
        )

        schema = load_json(
            arguments.schema
        )

        validate_schema(
            document,
            schema,
        )

        validate_policy(
            document,
            repository_root,
        )

        print_summary(
            document
        )

        return 0

    except ComponentValidationError as error:
        print(
            "::error::Repository components "
            "validation failed."
        )

        print(
            f"::error::{error}"
        )

        return 1


if __name__ == "__main__":
    sys.exit(
        main()
    )