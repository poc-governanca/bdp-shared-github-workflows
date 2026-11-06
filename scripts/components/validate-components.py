#!/usr/bin/env python3

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
    "terraform",
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

FORBIDDEN_PATH_PARTS = {
    "..",
}


class ComponentValidationError(Exception):
    """Raised when repository component configuration is invalid."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate repository components manifest."
    )

    parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="Path to .github/components.yml",
    )

    parser.add_argument(
        "--schema",
        required=True,
        type=Path,
        help="Path to components.schema.json",
    )

    parser.add_argument(
        "--repository-root",
        required=False,
        type=Path,
        default=Path("."),
        help="Repository root directory.",
    )

    return parser.parse_args()


# ============================================================
# File loading
# ============================================================

def load_yaml(path: Path) -> dict[str, Any]:
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


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ComponentValidationError(
            f"Schema does not exist: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except json.JSONDecodeError as error:
        raise ComponentValidationError(
            f"Invalid JSON Schema: {error}"
        ) from error


# ============================================================
# JSON Schema
# ============================================================

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

    messages = []

    for error in errors:

        location = ".".join(
            str(item)
            for item
            in error.absolute_path
        )

        if not location:
            location = "<root>"

        messages.append(
            f"{location}: {error.message}"
        )

    raise ComponentValidationError(
        "Schema validation failed:\n- "
        + "\n- ".join(messages)
    )


# ============================================================
# Path validation
# ============================================================

def validate_relative_path(
    value: str,
    field_name: str,
) -> None:

    value = value.strip()

    if not value:
        raise ComponentValidationError(
            f"{field_name} cannot be empty."
        )

    normalized = value.replace(
        "\\",
        "/",
    )

    path = PurePosixPath(
        normalized
    )

    if path.is_absolute():
        raise ComponentValidationError(
            f"{field_name} cannot be absolute: {value}"
        )

    if any(
        part in FORBIDDEN_PATH_PARTS
        for part in path.parts
    ):
        raise ComponentValidationError(
            f"{field_name} cannot contain '..': {value}"
        )


def validate_glob(
    value: str,
    field_name: str,
) -> None:

    validate_relative_path(
        value,
        field_name,
    )

    if value.startswith("/"):
        raise ComponentValidationError(
            f"{field_name} cannot start with '/': {value}"
        )


# ============================================================
# Build Policy
# ============================================================

def validate_build(
    name: str,
    component: dict[str, Any],
) -> None:

    language = component[
        "language"
    ]

    build = component[
        "build"
    ]

    enabled = build[
        "enabled"
    ]

    profile = build[
        "profile"
    ]

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

    if enabled:

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
            raise ComponentValidationError(
                f"{name}: language '{language}' "
                f"is incompatible with build profile "
                f"'{profile}'. "
                f"Expected one of: "
                f"{', '.join(sorted(allowed_profiles))}."
            )


# ============================================================
# Container Policy
# ============================================================

def validate_container(
    name: str,
    component: dict[str, Any],
    repository_root: Path,
) -> None:

    container = component[
        "container"
    ]

    enabled = container[
        "enabled"
    ]

    if not enabled:
        return

    required = (
        "image_name",
        "dockerfile",
        "build_context",
    )

    for field in required:

        value = container.get(
            field
        )

        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise ComponentValidationError(
                f"{name}: container.{field} "
                "is required when container is enabled."
            )

    dockerfile = container[
        "dockerfile"
    ]

    build_context = container[
        "build_context"
    ]

    validate_relative_path(
        dockerfile,
        f"{name}.container.dockerfile",
    )

    validate_relative_path(
        build_context,
        f"{name}.container.build_context",
    )

    dockerfile_path = (
        repository_root
        / dockerfile
    )

    if not dockerfile_path.is_file():
        raise ComponentValidationError(
            f"{name}: Dockerfile does not exist: "
            f"{dockerfile}"
        )

    build_context_path = (
        repository_root
        / build_context
    )

    if not build_context_path.is_dir():
        raise ComponentValidationError(
            f"{name}: build_context does not exist: "
            f"{build_context}"
        )


# ============================================================
# Components
# ============================================================

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

    for name, component in (
        components.items()
    ):

        component_path = (
            component["path"]
        )

        validate_relative_path(
            component_path,
            f"{name}.path",
        )

        component_directory = (
            repository_root
            / component_path
        )

        if not component_directory.exists():
            raise ComponentValidationError(
                f"{name}: component path does not exist: "
                f"{component_path}"
            )

        paths = component[
            "paths"
        ]

        for index, pattern in enumerate(
            paths
        ):

            validate_glob(
                pattern,
                f"{name}.paths[{index}]",
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

        container = component[
            "container"
        ]

        if container["enabled"]:

            image_name = (
                container[
                    "image_name"
                ]
            )

            existing = (
                image_names.get(
                    image_name
                )
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


# ============================================================
# Shared Paths
# ============================================================

def validate_shared_paths(
    document: dict[str, Any],
) -> None:

    components = set(
        document[
            "components"
        ].keys()
    )

    shared_paths = document.get(
        "shared_paths",
        {},
    )

    for group_name, group in (
        shared_paths.items()
    ):

        for index, pattern in enumerate(
            group["paths"]
        ):

            validate_glob(
                pattern,
                (
                    f"shared_paths."
                    f"{group_name}."
                    f"paths[{index}]"
                ),
            )

        for component_name in (
            group["affects"]
        ):

            if (
                component_name
                not in components
            ):
                raise ComponentValidationError(
                    f"shared_paths.{group_name} "
                    f"references unknown component "
                    f"'{component_name}'."
                )


# ============================================================
# Global Paths
# ============================================================

def validate_global_paths(
    document: dict[str, Any],
) -> None:

    global_paths = document.get(
        "global_paths",
        [],
    )

    if not isinstance(
        global_paths,
        list,
    ):
        raise ComponentValidationError(
            "global_paths must be an array."
        )

    for index, pattern in enumerate(
        global_paths
    ):

        validate_glob(
            pattern,
            f"global_paths[{index}]",
        )


# ============================================================
# Repository Controls
# ============================================================

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

    if github_actions:

        if github_actions["enabled"]:

            paths = github_actions.get(
                "paths",
                [],
            )

            if not paths:
                raise ComponentValidationError(
                    "repository_controls.github_actions "
                    "is enabled but has no paths."
                )

            for index, pattern in enumerate(
                paths
            ):

                validate_glob(
                    pattern,
                    (
                        "repository_controls."
                        "github_actions."
                        f"paths[{index}]"
                    ),
                )

    infrastructure = controls.get(
        "infrastructure"
    )

    if infrastructure:

        enabled = infrastructure[
            "enabled"
        ]

        if enabled:

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
                not isinstance(
                    scan_path,
                    str,
                )
                or not scan_path.strip()
            ):
                raise ComponentValidationError(
                    "Infrastructure control is enabled "
                    "but scan_path is missing."
                )

            validate_relative_path(
                scan_path,
                (
                    "repository_controls."
                    "infrastructure.scan_path"
                ),
            )

            scan_directory = (
                repository_root
                / scan_path
            )

            if not scan_directory.exists():
                raise ComponentValidationError(
                    "Infrastructure scan_path "
                    f"does not exist: {scan_path}"
                )

            for index, pattern in enumerate(
                paths
            ):

                validate_glob(
                    pattern,
                    (
                        "repository_controls."
                        "infrastructure."
                        f"paths[{index}]"
                    ),
                )


# ============================================================
# Main Policy Validation
# ============================================================

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


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    arguments = parse_arguments()

    try:

        repository_root = (
            arguments.repository_root.resolve()
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

        components = document[
            "components"
        ]

        print(
            "Repository components validation: PASS"
        )

        print(
            f"Components: {len(components)}"
        )

        for name, component in (
            components.items()
        ):

            print(
                f"- {name}: "
                f"language={component['language']} "
                f"tier={component['tier']} "
                f"profile={component['build']['profile']} "
                f"container="
                f"{component['container']['enabled']}"
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