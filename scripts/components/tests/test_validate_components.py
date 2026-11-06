from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest


# ============================================================
# Module loading
# ============================================================

COMPONENTS_DIRECTORY = Path(__file__).parents[1]

SCRIPT_PATH = (
    COMPONENTS_DIRECTORY
    / "validate-components.py"
)

SCHEMA_PATH = (
    COMPONENTS_DIRECTORY
    / "schemas"
    / "components.schema.json"
)

SPEC = importlib.util.spec_from_file_location(
    "validate_components",
    SCRIPT_PATH,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError(
        f"Unable to load validator module: {SCRIPT_PATH}"
    )

MODULE = importlib.util.module_from_spec(
    SPEC
)

SPEC.loader.exec_module(
    MODULE
)


# ============================================================
# Manifest factories
# ============================================================

def valid_monorepo_manifest() -> dict[str, Any]:
    return {
        "version": 1,
        "global_paths": [
            "Directory.Build.props",
            "Directory.Packages.props",
            "global.json",
        ],
        "components": {
            "backend": {
                "type": "application",
                "path": "backend",
                "language": "dotnet",
                "tier": 1,
                "paths": [
                    "backend/**",
                    "libs/backend-common/**",
                ],
                "build": {
                    "enabled": True,
                    "profile": "dotnet",
                },
                "container": {
                    "enabled": True,
                    "image_name": "fastqa-api",
                    "dockerfile": "backend/Dockerfile",
                    "build_context": "backend",
                },
            },
            "frontend": {
                "type": "application",
                "path": "frontend",
                "language": "typescript",
                "tier": 2,
                "paths": [
                    "frontend/**",
                    "libs/frontend-common/**",
                ],
                "build": {
                    "enabled": True,
                    "profile": "node",
                },
                "container": {
                    "enabled": True,
                    "image_name": "fastqa-web",
                    "dockerfile": "frontend/Dockerfile",
                    "build_context": "frontend",
                },
            },
        },
        "shared_paths": {
            "common": {
                "paths": [
                    "libs/common/**",
                ],
                "affects": [
                    "backend",
                    "frontend",
                ],
            },
        },
        "repository_controls": {
            "github_actions": {
                "enabled": True,
                "paths": [
                    ".github/workflows/**",
                ],
            },
            "infrastructure": {
                "enabled": True,
                "paths": [
                    "infra/**",
                ],
                "scan_path": "infra",
            },
        },
    }


def valid_multirepo_manifest() -> dict[str, Any]:
    return {
        "version": 1,
        "global_paths": [
            "Directory.Build.props",
            "Directory.Packages.props",
            "global.json",
        ],
        "components": {
            "backend": {
                "type": "application",
                "path": ".",
                "language": "dotnet",
                "tier": 1,
                "paths": [
                    "**",
                ],
                "build": {
                    "enabled": True,
                    "profile": "dotnet",
                },
                "container": {
                    "enabled": True,
                    "image_name": "fastqa-api",
                    "dockerfile": "Dockerfile",
                    "build_context": ".",
                },
            },
        },
        "shared_paths": {},
        "repository_controls": {
            "github_actions": {
                "enabled": True,
                "paths": [
                    ".github/workflows/**",
                ],
            },
            "infrastructure": {
                "enabled": False,
            },
        },
    }


def valid_non_container_component() -> dict[str, Any]:
    return {
        "version": 1,
        "components": {
            "shared-library": {
                "type": "library",
                "path": "shared-library",
                "language": "dotnet",
                "tier": 3,
                "paths": [
                    "shared-library/**",
                ],
                "build": {
                    "enabled": True,
                    "profile": "dotnet",
                },
                "container": {
                    "enabled": False,
                },
            },
        },
        "shared_paths": {},
        "repository_controls": {
            "github_actions": {
                "enabled": False,
            },
            "infrastructure": {
                "enabled": False,
            },
        },
    }


def valid_python_worker_manifest() -> dict[str, Any]:
    return {
        "version": 1,
        "components": {
            "notification-worker": {
                "type": "worker",
                "path": "worker",
                "language": "python",
                "tier": 2,
                "paths": [
                    "worker/**",
                ],
                "build": {
                    "enabled": True,
                    "profile": "python",
                },
                "container": {
                    "enabled": True,
                    "image_name": "notification-worker",
                    "dockerfile": "worker/Dockerfile",
                    "build_context": "worker",
                },
            },
        },
        "shared_paths": {},
        "repository_controls": {
            "github_actions": {
                "enabled": False,
            },
            "infrastructure": {
                "enabled": False,
            },
        },
    }


# ============================================================
# Repository fixture creation
# ============================================================

def create_monorepo_structure(
    repository_root: Path,
) -> None:
    directories = [
        "backend",
        "frontend",
        "worker",
        "shared-library",
        "libs/common",
        "libs/backend-common",
        "libs/frontend-common",
        "infra",
        ".github/workflows",
    ]

    for directory in directories:
        (
            repository_root
            / directory
        ).mkdir(
            parents=True,
            exist_ok=True,
        )

    files = {
        "backend/Dockerfile": (
            "FROM scratch\n"
        ),
        "frontend/Dockerfile": (
            "FROM scratch\n"
        ),
        "worker/Dockerfile": (
            "FROM scratch\n"
        ),
        "Dockerfile": (
            "FROM scratch\n"
        ),
        "Directory.Build.props": (
            "<Project />\n"
        ),
        "Directory.Packages.props": (
            "<Project />\n"
        ),
        "global.json": (
            '{"sdk": {"version": "10.0.100"}}\n'
        ),
        "infra/main.tf": (
            'terraform {}\n'
        ),
    }

    for relative_path, content in files.items():
        file_path = (
            repository_root
            / relative_path
        )

        file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_path.write_text(
            content,
            encoding="utf-8",
        )


@pytest.fixture
def repository_root(
    tmp_path: Path,
) -> Path:
    create_monorepo_structure(
        tmp_path
    )

    return tmp_path


@pytest.fixture
def schema() -> dict[str, Any]:
    with SCHEMA_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


# ============================================================
# Complete validation helper
# ============================================================

def validate_complete_manifest(
    manifest: dict[str, Any],
    schema: dict[str, Any],
    repository_root: Path,
) -> None:
    MODULE.validate_schema(
        manifest,
        schema,
    )

    MODULE.validate_policy(
        manifest,
        repository_root,
    )


# ============================================================
# Valid manifest scenarios
# ============================================================

def test_valid_monorepo_manifest_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


def test_valid_multirepo_manifest_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


def test_valid_component_without_container_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_non_container_component()
    )

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


def test_valid_python_worker_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_python_worker_manifest()
    )

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


def test_empty_global_paths_are_valid(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["global_paths"] = []

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


def test_missing_optional_global_paths_are_valid(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest.pop(
        "global_paths"
    )

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


def test_empty_shared_paths_are_valid(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["shared_paths"] = {}

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )


# ============================================================
# Manifest loading
# ============================================================

def test_load_yaml_reads_valid_manifest(
    tmp_path: Path,
) -> None:
    manifest_path = (
        tmp_path
        / "components.yml"
    )

    manifest_path.write_text(
        """
version: 1

components:
  application:
    type: application
    path: "."
    language: dotnet
    tier: 2

    paths:
      - "**"

    build:
      enabled: true
      profile: dotnet

    container:
      enabled: false
""".strip(),
        encoding="utf-8",
    )

    document = MODULE.load_yaml(
        manifest_path
    )

    assert document["version"] == 1
    assert "application" in document[
        "components"
    ]


def test_load_yaml_fails_when_manifest_is_missing(
    tmp_path: Path,
) -> None:
    missing_path = (
        tmp_path
        / "missing.yml"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Manifest does not exist",
    ):
        MODULE.load_yaml(
            missing_path
        )


def test_load_yaml_fails_for_invalid_yaml(
    tmp_path: Path,
) -> None:
    manifest_path = (
        tmp_path
        / "invalid.yml"
    )

    manifest_path.write_text(
        """
version: 1
components:
  backend:
    invalid: [
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Invalid YAML",
    ):
        MODULE.load_yaml(
            manifest_path
        )


def test_load_yaml_fails_when_root_is_not_object(
    tmp_path: Path,
) -> None:
    manifest_path = (
        tmp_path
        / "invalid-root.yml"
    )

    manifest_path.write_text(
        """
- backend
- frontend
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match=(
            "must contain a YAML object"
        ),
    ):
        MODULE.load_yaml(
            manifest_path
        )


def test_load_json_reads_schema() -> None:
    document = MODULE.load_json(
        SCHEMA_PATH
    )

    assert document[
        "$schema"
    ] == (
        "https://json-schema.org/"
        "draft/2020-12/schema"
    )


def test_load_json_fails_for_missing_file(
    tmp_path: Path,
) -> None:
    missing_schema = (
        tmp_path
        / "missing-schema.json"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema does not exist",
    ):
        MODULE.load_json(
            missing_schema
        )


def test_load_json_fails_for_invalid_json(
    tmp_path: Path,
) -> None:
    schema_path = (
        tmp_path
        / "invalid.json"
    )

    schema_path.write_text(
        "{ invalid-json }",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Invalid JSON Schema",
    ):
        MODULE.load_json(
            schema_path
        )


# ============================================================
# Schema validation
# ============================================================

def test_schema_fails_for_invalid_version(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["version"] = 2

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


@pytest.mark.parametrize(
    "tier",
    [
        0,
        4,
        99,
        "1",
    ],
)
def test_schema_fails_for_invalid_tier(
    tier: Any,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["tier"] = tier

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_for_unknown_language(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["language"] = "ruby"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_for_unknown_build_profile(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["build"]["profile"] = (
        "custom-command"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_when_component_has_no_paths(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["paths"] = []

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_when_components_are_empty(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"] = {}

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_for_invalid_component_name(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    component = manifest[
        "components"
    ].pop(
        "backend"
    )

    manifest["components"][
        "Backend API"
    ] = component

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_for_container_enabled_without_image(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["container"].pop(
        "image_name"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_for_container_enabled_without_dockerfile(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["container"].pop(
        "dockerfile"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_for_container_enabled_without_context(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["container"].pop(
        "build_context"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_when_disabled_container_has_image_fields(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    container = manifest[
        "components"
    ]["backend"]["container"]

    container["enabled"] = False

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_when_build_enabled_with_none_profile(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["build"] = {
        "enabled": True,
        "profile": "none",
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_schema_fails_when_build_disabled_with_active_profile(
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["build"] = {
        "enabled": False,
        "profile": "dotnet",
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


# ============================================================
# Path validation
# ============================================================

@pytest.mark.parametrize(
    "path",
    [
        "backend",
        "backend/src",
        ".",
        "backend/**",
        "backend/**/*.cs",
        "libs/common/**",
    ],
)
def test_valid_relative_paths_pass(
    path: str,
) -> None:
    MODULE.validate_relative_path(
        path,
        "test.path",
    )


@pytest.mark.parametrize(
    "path",
    [
        "",
        " ",
        "/backend",
        "../backend",
        "backend/../frontend",
        "../../shared",
    ],
)
def test_invalid_relative_paths_fail(
    path: str,
) -> None:
    with pytest.raises(
        MODULE.ComponentValidationError
    ):
        MODULE.validate_relative_path(
            path,
            "test.path",
        )


@pytest.mark.parametrize(
    "pattern",
    [
        "backend/**",
        "backend/**/*.cs",
        "libs/common/**",
        "**",
        ".github/workflows/**",
    ],
)
def test_controlled_globs_pass(
    pattern: str,
) -> None:
    MODULE.validate_glob(
        pattern,
        "test.pattern",
    )


@pytest.mark.parametrize(
    "pattern",
    [
        "/backend/**",
        "../backend/**",
        "backend/../../frontend/**",
    ],
)
def test_dangerous_globs_fail(
    pattern: str,
) -> None:
    with pytest.raises(
        MODULE.ComponentValidationError
    ):
        MODULE.validate_glob(
            pattern,
            "test.pattern",
        )


# ============================================================
# Build policy
# ============================================================

@pytest.mark.parametrize(
    (
        "language",
        "profile",
    ),
    [
        (
            "dotnet",
            "dotnet",
        ),
        (
            "java",
            "java",
        ),
        (
            "node",
            "node",
        ),
        (
            "javascript",
            "node",
        ),
        (
            "typescript",
            "node",
        ),
        (
            "python",
            "python",
        ),
    ],
)
def test_compatible_language_and_profile_pass(
    language: str,
    profile: str,
) -> None:
    component = {
        "language": language,
        "build": {
            "enabled": True,
            "profile": profile,
        },
    }

    MODULE.validate_build(
        "application",
        component,
    )


@pytest.mark.parametrize(
    (
        "language",
        "profile",
    ),
    [
        (
            "dotnet",
            "node",
        ),
        (
            "typescript",
            "dotnet",
        ),
        (
            "python",
            "java",
        ),
        (
            "java",
            "python",
        ),
    ],
)
def test_incompatible_language_and_profile_fail(
    language: str,
    profile: str,
) -> None:
    component = {
        "language": language,
        "build": {
            "enabled": True,
            "profile": profile,
        },
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="incompatible",
    ):
        MODULE.validate_build(
            "application",
            component,
        )


def test_enabled_build_with_none_profile_fails_policy() -> None:
    component = {
        "language": "dotnet",
        "build": {
            "enabled": True,
            "profile": "none",
        },
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="enabled but profile is 'none'",
    ):
        MODULE.validate_build(
            "application",
            component,
        )


def test_disabled_build_with_active_profile_fails_policy() -> None:
    component = {
        "language": "dotnet",
        "build": {
            "enabled": False,
            "profile": "dotnet",
        },
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="build is disabled",
    ):
        MODULE.validate_build(
            "application",
            component,
        )


def test_disabled_build_with_none_profile_passes() -> None:
    component = {
        "language": "go",
        "build": {
            "enabled": False,
            "profile": "none",
        },
    }

    MODULE.validate_build(
        "application",
        component,
    )


def test_go_build_enabled_fails_until_profile_exists() -> None:
    component = {
        "language": "go",
        "build": {
            "enabled": True,
            "profile": "none",
        },
    }

    with pytest.raises(
        MODULE.ComponentValidationError
    ):
        MODULE.validate_build(
            "go-service",
            component,
        )


# ============================================================
# Component physical structure
# ============================================================

def test_component_path_must_exist(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["path"] = "missing-backend"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="component path does not exist",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_dockerfile_must_exist(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["container"][
        "dockerfile"
    ] = "backend/Missing.Dockerfile"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Dockerfile does not exist",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_build_context_must_exist(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["container"][
        "build_context"
    ] = "missing-context"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="build_context does not exist",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_duplicate_image_name_fails(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["components"][
        "frontend"
    ]["container"][
        "image_name"
    ] = "fastqa-api"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Duplicate container image_name",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_disabled_container_does_not_require_files(
    repository_root: Path,
) -> None:
    manifest = (
        valid_non_container_component()
    )

    MODULE.validate_components(
        manifest,
        repository_root,
    )


def test_container_enabled_requires_complete_configuration(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["components"][
        "backend"
    ]["container"].pop(
        "image_name"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="container.image_name is required",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


# ============================================================
# Shared paths
# ============================================================

def test_valid_shared_paths_pass() -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    MODULE.validate_shared_paths(
        manifest
    )


def test_shared_path_unknown_component_fails() -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest[
        "shared_paths"
    ]["common"]["affects"].append(
        "unknown-component"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="references unknown component",
    ):
        MODULE.validate_shared_paths(
            manifest
        )


def test_shared_path_parent_traversal_fails() -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest[
        "shared_paths"
    ]["common"]["paths"] = [
        "../common/**"
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="cannot contain '..'",
    ):
        MODULE.validate_shared_paths(
            manifest
        )


# ============================================================
# Global paths
# ============================================================

def test_valid_global_paths_pass() -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    MODULE.validate_global_paths(
        manifest
    )


def test_global_paths_must_be_array() -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["global_paths"] = (
        "global.json"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="global_paths must be an array",
    ):
        MODULE.validate_global_paths(
            manifest
        )


def test_global_path_parent_traversal_fails() -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest["global_paths"] = [
        "../global.json"
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="cannot contain '..'",
    ):
        MODULE.validate_global_paths(
            manifest
        )


# ============================================================
# Repository controls
# ============================================================

def test_valid_repository_controls_pass(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    MODULE.validate_repository_controls(
        manifest,
        repository_root,
    )


def test_github_actions_enabled_requires_paths(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest[
        "repository_controls"
    ]["github_actions"]["paths"] = []

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="enabled but has no paths",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )


def test_infrastructure_enabled_requires_paths(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest[
        "repository_controls"
    ]["infrastructure"]["paths"] = []

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="enabled but has no paths",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )


def test_infrastructure_enabled_requires_scan_path(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest[
        "repository_controls"
    ]["infrastructure"].pop(
        "scan_path"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="scan_path is missing",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )


def test_infrastructure_scan_path_must_exist(
    repository_root: Path,
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    manifest[
        "repository_controls"
    ]["infrastructure"][
        "scan_path"
    ] = "missing-infra"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="scan_path does not exist",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )


def test_disabled_infrastructure_is_valid(
    repository_root: Path,
) -> None:
    manifest = (
        valid_multirepo_manifest()
    )

    MODULE.validate_repository_controls(
        manifest,
        repository_root,
    )


# ============================================================
# Immutability and test isolation
# ============================================================

def test_factory_returns_independent_manifests() -> None:
    first = (
        valid_monorepo_manifest()
    )

    second = (
        valid_monorepo_manifest()
    )

    first["components"][
        "backend"
    ]["tier"] = 3

    assert second["components"][
        "backend"
    ]["tier"] == 1


def test_validation_does_not_modify_manifest(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = (
        valid_monorepo_manifest()
    )

    original = copy.deepcopy(
        manifest
    )

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )

    assert manifest == original