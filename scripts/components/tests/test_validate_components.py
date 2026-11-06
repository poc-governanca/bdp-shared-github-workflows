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
                "infrastructure": {
                    "enabled": True,
                    "paths": [
                        "backend/infra/**",
                    ],
                    "scan_path": "backend/infra",
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
                "infrastructure": {
                    "enabled": False,
                },
            },
            "worker": {
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
                    "enabled": False,
                },
                "infrastructure": {
                    "enabled": False,
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
                    "worker",
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
                    "infra/shared/**",
                ],
                "scan_path": "infra/shared",
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
                "infrastructure": {
                    "enabled": False,
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


def valid_library_manifest() -> dict[str, Any]:
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
                "infrastructure": {
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


# ============================================================
# Repository fixture
# ============================================================

def create_repository_structure(
    repository_root: Path,
) -> None:
    directories = [
        "backend",
        "backend/infra",
        "frontend",
        "worker",
        "shared-library",
        "libs/common",
        "libs/backend-common",
        "libs/frontend-common",
        "infra/shared",
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
        "backend/Dockerfile": "FROM scratch\n",
        "backend/infra/main.tf": "terraform {}\n",
        "frontend/Dockerfile": "FROM scratch\n",
        "worker/Dockerfile": "FROM scratch\n",
        "Dockerfile": "FROM scratch\n",
        "Directory.Build.props": "<Project />\n",
        "Directory.Packages.props": "<Project />\n",
        "global.json": (
            '{"sdk": {"version": "10.0.100"}}\n'
        ),
        "infra/shared/main.tf": "terraform {}\n",
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
    create_repository_structure(
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
# Valid manifests
# ============================================================

def test_valid_monorepo_manifest_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    validate_complete_manifest(
        valid_monorepo_manifest(),
        schema,
        repository_root,
    )


def test_valid_multirepo_manifest_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    validate_complete_manifest(
        valid_multirepo_manifest(),
        schema,
        repository_root,
    )


def test_valid_library_without_container_passes(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    validate_complete_manifest(
        valid_library_manifest(),
        schema,
        repository_root,
    )


def test_validation_does_not_modify_manifest(
    repository_root: Path,
    schema: dict[str, Any],
) -> None:
    manifest = valid_monorepo_manifest()
    original = copy.deepcopy(manifest)

    validate_complete_manifest(
        manifest,
        schema,
        repository_root,
    )

    assert manifest == original


# ============================================================
# File loading
# ============================================================

def test_load_yaml_reads_manifest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "components.yml"

    path.write_text(
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
    infrastructure:
      enabled: false
""".strip(),
        encoding="utf-8",
    )

    document = MODULE.load_yaml(path)

    assert document["version"] == 1
    assert "application" in document["components"]


def test_load_yaml_missing_file_fails(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Manifest does not exist",
    ):
        MODULE.load_yaml(
            tmp_path / "missing.yml"
        )


def test_load_yaml_invalid_yaml_fails(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid.yml"

    path.write_text(
        "version: [",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Invalid YAML",
    ):
        MODULE.load_yaml(path)


def test_load_json_reads_schema() -> None:
    document = MODULE.load_json(
        SCHEMA_PATH
    )

    assert document["$schema"].endswith(
        "draft/2020-12/schema"
    )


# ============================================================
# Schema validation
# ============================================================

@pytest.mark.parametrize(
    "tier",
    [
        0,
        4,
        99,
        "1",
    ],
)
def test_invalid_tier_fails_schema(
    tier: Any,
    schema: dict[str, Any],
) -> None:
    manifest = valid_multirepo_manifest()

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


def test_unknown_language_fails_schema(
    schema: dict[str, Any],
) -> None:
    manifest = valid_multirepo_manifest()

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


def test_terraform_build_profile_is_rejected(
    schema: dict[str, Any],
) -> None:
    manifest = valid_multirepo_manifest()

    manifest["components"][
        "backend"
    ]["build"]["profile"] = "terraform"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_component_requires_infrastructure_block(
    schema: dict[str, Any],
) -> None:
    manifest = valid_multirepo_manifest()

    manifest["components"][
        "backend"
    ].pop("infrastructure")

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_enabled_container_requires_image_name(
    schema: dict[str, Any],
) -> None:
    manifest = valid_multirepo_manifest()

    manifest["components"][
        "backend"
    ]["container"].pop("image_name")

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_disabled_container_cannot_have_image_fields(
    schema: dict[str, Any],
) -> None:
    manifest = valid_multirepo_manifest()

    manifest["components"][
        "backend"
    ]["container"]["enabled"] = False

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_enabled_infrastructure_requires_scan_path(
    schema: dict[str, Any],
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"].pop("scan_path")

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Schema validation failed",
    ):
        MODULE.validate_schema(
            manifest,
            schema,
        )


def test_disabled_infrastructure_cannot_have_paths(
    schema: dict[str, Any],
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "frontend"
    ]["infrastructure"] = {
        "enabled": False,
        "paths": [
            "frontend/infra/**",
        ],
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
# Path handling
# ============================================================

@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("backend", "backend"),
        ("./backend", "backend"),
        ("backend\\src", "backend/src"),
        (".", "."),
    ],
)
def test_relative_path_normalization(
    value: str,
    expected: str,
) -> None:
    assert (
        MODULE.normalize_relative_path(
            value,
            "test.path",
        )
        == expected
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "/backend",
        "../backend",
        "backend/../../frontend",
    ],
)
def test_invalid_relative_path_fails(
    value: str,
) -> None:
    with pytest.raises(
        MODULE.ComponentValidationError
    ):
        MODULE.normalize_relative_path(
            value,
            "test.path",
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("backend/**", "backend/**"),
        ("./backend/**/*.cs", "backend/**/*.cs"),
        (
            "backend\\infra\\**",
            "backend/infra/**",
        ),
        ("**", "**"),
    ],
)
def test_glob_normalization(
    value: str,
    expected: str,
) -> None:
    assert (
        MODULE.normalize_glob(
            value,
            "test.glob",
        )
        == expected
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/backend/**",
        "../backend/**",
        "backend/../../frontend/**",
    ],
)
def test_invalid_glob_fails(
    value: str,
) -> None:
    with pytest.raises(
        MODULE.ComponentValidationError
    ):
        MODULE.normalize_glob(
            value,
            "test.glob",
        )


# ============================================================
# Build policy
# ============================================================

@pytest.mark.parametrize(
    ("language", "profile"),
    [
        ("dotnet", "dotnet"),
        ("java", "java"),
        ("node", "node"),
        ("javascript", "node"),
        ("typescript", "node"),
        ("python", "python"),
    ],
)
def test_compatible_build_profiles_pass(
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
        "component",
        component,
    )


@pytest.mark.parametrize(
    ("language", "profile"),
    [
        ("dotnet", "node"),
        ("typescript", "dotnet"),
        ("python", "java"),
        ("java", "python"),
    ],
)
def test_incompatible_build_profiles_fail(
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
            "component",
            component,
        )


def test_disabled_build_requires_none_profile() -> None:
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
            "component",
            component,
        )


def test_disabled_go_component_with_none_profile_passes() -> None:
    component = {
        "language": "go",
        "build": {
            "enabled": False,
            "profile": "none",
        },
    }

    MODULE.validate_build(
        "go-service",
        component,
    )


# ============================================================
# Physical component validation
# ============================================================

def test_component_path_must_be_directory(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    invalid_path = (
        repository_root
        / "component-file"
    )

    invalid_path.write_text(
        "not a directory",
        encoding="utf-8",
    )

    manifest["components"][
        "backend"
    ]["path"] = "component-file"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="must be an existing directory",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_dockerfile_must_exist(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

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


def test_build_context_must_be_directory(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    context_file = (
        repository_root
        / "backend"
        / "context.txt"
    )

    context_file.write_text(
        "not a directory",
        encoding="utf-8",
    )

    manifest["components"][
        "backend"
    ]["container"][
        "build_context"
    ] = "backend/context.txt"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="must be an existing directory",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_duplicate_image_name_fails(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

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


def test_duplicate_application_pattern_fails(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["paths"] = [
        "backend/**",
        "./backend/**",
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="duplicate application path pattern",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


# ============================================================
# Component infrastructure validation
# ============================================================

def test_component_infrastructure_enabled_passes(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    MODULE.validate_components(
        manifest,
        repository_root,
    )


def test_component_infrastructure_disabled_passes(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": False,
    }

    MODULE.validate_components(
        manifest,
        repository_root,
    )


def test_component_infrastructure_requires_paths(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [],
        "scan_path": "backend/infra",
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="has no paths",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_component_infrastructure_requires_scan_path(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [
            "backend/infra/**",
        ],
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="scan_path is missing",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_component_scan_path_must_exist(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [
            "backend/missing-infra/**",
        ],
        "scan_path": "backend/missing-infra",
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="must be an existing directory",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_component_scan_path_must_be_directory(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    file_path = (
        repository_root
        / "backend"
        / "infra.tf"
    )

    file_path.write_text(
        "terraform {}\n",
        encoding="utf-8",
    )

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [
            "backend/infra.tf",
        ],
        "scan_path": "backend/infra.tf",
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="must be an existing directory",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_identical_application_and_iac_pattern_fails(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["paths"] = [
        "backend/**",
    ]

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [
            "backend/**",
        ],
        "scan_path": "backend/infra",
    }

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="same path pattern cannot be used",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


def test_broad_application_and_specific_iac_pattern_passes(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["paths"] = [
        "backend/**",
    ]

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [
            "backend/infra/**",
        ],
        "scan_path": "backend/infra",
    }

    MODULE.validate_components(
        manifest,
        repository_root,
    )


def test_duplicate_iac_pattern_fails(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"][
        "paths"
    ] = [
        "backend/infra/**",
        "./backend/infra/**",
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="duplicate infrastructure path pattern",
    ):
        MODULE.validate_components(
            manifest,
            repository_root,
        )


# ============================================================
# Shared and global paths
# ============================================================

def test_shared_path_unknown_component_fails() -> None:
    manifest = valid_monorepo_manifest()

    manifest["shared_paths"][
        "common"
    ]["affects"].append(
        "unknown"
    )

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="references unknown component",
    ):
        MODULE.validate_shared_paths(
            manifest
        )


def test_duplicate_shared_pattern_fails() -> None:
    manifest = valid_monorepo_manifest()

    manifest["shared_paths"][
        "common"
    ]["paths"] = [
        "libs/common/**",
        "./libs/common/**",
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="duplicate path pattern",
    ):
        MODULE.validate_shared_paths(
            manifest
        )


def test_duplicate_global_pattern_fails() -> None:
    manifest = valid_monorepo_manifest()

    manifest["global_paths"] = [
        "global.json",
        "./global.json",
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="Duplicate global path pattern",
    ):
        MODULE.validate_global_paths(
            manifest
        )


# ============================================================
# Repository controls
# ============================================================

def test_repository_infrastructure_passes(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    MODULE.validate_repository_controls(
        manifest,
        repository_root,
    )


def test_repository_scan_path_must_exist(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["repository_controls"][
        "infrastructure"
    ]["scan_path"] = "infra/missing"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="must be an existing directory",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )


def test_repository_scan_path_must_be_directory(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    file_path = (
        repository_root
        / "infra"
        / "single.tf"
    )

    file_path.write_text(
        "terraform {}\n",
        encoding="utf-8",
    )

    manifest["repository_controls"][
        "infrastructure"
    ]["scan_path"] = "infra/single.tf"

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="must be an existing directory",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )


def test_duplicate_repository_control_path_fails(
    repository_root: Path,
) -> None:
    manifest = valid_monorepo_manifest()

    manifest["repository_controls"][
        "github_actions"
    ]["paths"] = [
        ".github/workflows/**",
        "./.github/workflows/**",
    ]

    with pytest.raises(
        MODULE.ComponentValidationError,
        match="duplicate path pattern",
    ):
        MODULE.validate_repository_controls(
            manifest,
            repository_root,
        )