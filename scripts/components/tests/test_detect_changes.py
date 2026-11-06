from __future__ import annotations

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
    / "detect-changes.py"
)

SPEC = importlib.util.spec_from_file_location(
    "detect_changes",
    SCRIPT_PATH,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError(
        f"Unable to load module: {SCRIPT_PATH}"
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

def monorepo_manifest() -> dict[str, Any]:
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

            "backend-shared": {
                "paths": [
                    "libs/backend-shared/**",
                ],

                "affects": [
                    "backend",
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


def multirepo_manifest() -> dict[str, Any]:
    return {
        "version": 1,

        "global_paths": [],

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
                "enabled": False,
            },

            "infrastructure": {
                "enabled": False,
            },
        },
    }


def multirepo_with_iac_manifest() -> dict[str, Any]:
    manifest = multirepo_manifest()

    manifest["components"][
        "backend"
    ]["infrastructure"] = {
        "enabled": True,
        "paths": [
            "infra/**",
        ],
        "scan_path": "infra",
    }

    return manifest


# ============================================================
# Repository path normalization
# ============================================================

@pytest.mark.parametrize(
    ("input_path", "expected"),
    [
        (
            "backend/file.cs",
            "backend/file.cs",
        ),
        (
            "./backend/file.cs",
            "backend/file.cs",
        ),
        (
            "backend\\src\\file.cs",
            "backend/src/file.cs",
        ),
        (
            ".github/workflows/ci.yml",
            ".github/workflows/ci.yml",
        ),
    ],
)
def test_repository_path_normalization(
    input_path: str,
    expected: str,
) -> None:
    assert (
        MODULE.normalize_repository_path(
            input_path
        )
        == expected
    )


@pytest.mark.parametrize(
    "input_path",
    [
        "",
        " ",
        "/etc/passwd",
        "../backend/file.cs",
        "backend/../../frontend/file.ts",
    ],
)
def test_invalid_repository_path_fails(
    input_path: str,
) -> None:
    with pytest.raises(
        MODULE.ChangeDetectionError
    ):
        MODULE.normalize_repository_path(
            input_path
        )


# ============================================================
# Pattern normalization
# ============================================================

@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (
            "backend/**",
            "backend/**",
        ),
        (
            "./backend/**",
            "backend/**",
        ),
        (
            "backend\\infra\\**",
            "backend/infra/**",
        ),
        (
            "**",
            "**",
        ),
    ],
)
def test_pattern_normalization(
    pattern: str,
    expected: str,
) -> None:
    assert (
        MODULE.normalize_pattern(
            pattern
        )
        == expected
    )


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        " ",
        "/backend/**",
        "../backend/**",
        "backend/../../frontend/**",
    ],
)
def test_invalid_pattern_fails(
    pattern: str,
) -> None:
    with pytest.raises(
        MODULE.ChangeDetectionError
    ):
        MODULE.normalize_pattern(
            pattern
        )


# ============================================================
# Glob matching
# ============================================================

@pytest.mark.parametrize(
    ("changed_file", "pattern"),
    [
        (
            "backend/file.cs",
            "backend/**",
        ),
        (
            "backend/src/file.cs",
            "backend/**",
        ),
        (
            "backend/src/file.cs",
            "backend/**/*.cs",
        ),
        (
            "backend/infra/main.tf",
            "backend/infra/**",
        ),
        (
            "libs/common/auth.ts",
            "libs/common/**",
        ),
        (
            ".github/workflows/security.yml",
            ".github/workflows/**",
        ),
        (
            "README.md",
            "**",
        ),
    ],
)
def test_path_matches_pattern(
    changed_file: str,
    pattern: str,
) -> None:
    assert MODULE.path_matches_pattern(
        changed_file,
        pattern,
    )


@pytest.mark.parametrize(
    ("changed_file", "pattern"),
    [
        (
            "frontend/file.ts",
            "backend/**",
        ),
        (
            "backend/file.cs",
            "frontend/**",
        ),
        (
            "README.md",
            "backend/**",
        ),
        (
            "backend/file.cs",
            "backend/infra/**",
        ),
    ],
)
def test_path_does_not_match_pattern(
    changed_file: str,
    pattern: str,
) -> None:
    assert not MODULE.path_matches_pattern(
        changed_file,
        pattern,
    )


# ============================================================
# Application changes
# ============================================================

def test_backend_source_only_activates_application() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/CustomerService.cs",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
    ]

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "affected"
    ]

    assert backend[
        "application_changed"
    ]

    assert not backend[
        "infrastructure_changed"
    ]


def test_frontend_source_only_activates_frontend() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "frontend/src/app.ts",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "frontend",
    ]

    frontend = result[
        "component_details"
    ]["frontend"]

    assert frontend[
        "application_changed"
    ]

    assert not frontend[
        "infrastructure_changed"
    ]


def test_worker_source_only_activates_worker() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "worker/process.py",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "worker",
    ]

    worker = result[
        "component_details"
    ]["worker"]

    assert worker[
        "application_changed"
    ]

    assert not worker[
        "infrastructure_changed"
    ]


def test_backend_and_frontend_source_changes_activate_both() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/Application.cs",
            "frontend/src/main.ts",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
    ]

    assert result[
        "affected_component_count"
    ] == 2


# ============================================================
# Component infrastructure precedence
# ============================================================

def test_backend_iac_only_activates_infrastructure() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/infra/main.tf",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
    ]

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "affected"
    ]

    assert not backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]


def test_broad_application_path_does_not_absorb_iac() -> None:
    manifest = monorepo_manifest()

    assert (
        "backend/**"
        in manifest[
            "components"
        ]["backend"]["paths"]
    )

    result = MODULE.detect_changes(
        manifest,
        [
            "backend/infra/"
            "modules/network/main.tf",
        ],
    )

    backend = result[
        "component_details"
    ]["backend"]

    assert not backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]


def test_backend_code_and_iac_activate_both() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/CustomerService.cs",
            "backend/infra/main.tf",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
    ]

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]


def test_component_without_iac_treats_path_as_application() -> None:
    manifest = monorepo_manifest()

    manifest[
        "components"
    ]["frontend"]["paths"].append(
        "frontend/infra/**"
    )

    result = MODULE.detect_changes(
        manifest,
        [
            "frontend/infra/config.yml",
        ],
    )

    frontend = result[
        "component_details"
    ]["frontend"]

    assert frontend[
        "application_changed"
    ]

    assert not frontend[
        "infrastructure_changed"
    ]


# ============================================================
# Shared paths
# ============================================================

def test_common_shared_path_activates_declared_components() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "libs/common/auth.ts",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
        "worker",
    ]

    for component in (
        "backend",
        "frontend",
        "worker",
    ):
        details = result[
            "component_details"
        ][component]

        assert details[
            "application_changed"
        ]

        assert any(
            reason.startswith(
                "shared:common:"
            )
            for reason
            in details["reasons"]
        )


def test_backend_shared_path_only_activates_declared_components() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "libs/backend-shared/"
            "validation.cs",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "worker",
    ]

    assert not result[
        "component_details"
    ]["frontend"]["affected"]


def test_shared_path_does_not_activate_component_iac() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "libs/common/auth.ts",
        ],
    )

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "application_changed"
    ]

    assert not backend[
        "infrastructure_changed"
    ]


# ============================================================
# Global paths / full fan-out
# ============================================================

@pytest.mark.parametrize(
    "changed_file",
    [
        "Directory.Build.props",
        "Directory.Packages.props",
        "global.json",
    ],
)
def test_global_path_forces_full_fan_out(
    changed_file: str,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            changed_file,
        ],
    )

    assert result[
        "full_fan_out"
    ]

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
        "worker",
    ]

    assert result[
        "affected_component_count"
    ] == 3

    backend = result[
        "component_details"
    ]["backend"]

    frontend = result[
        "component_details"
    ]["frontend"]

    worker = result[
        "component_details"
    ]["worker"]

    assert backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]

    assert frontend[
        "application_changed"
    ]

    assert not frontend[
        "infrastructure_changed"
    ]

    assert worker[
        "application_changed"
    ]

    assert not worker[
        "infrastructure_changed"
    ]

    assert result[
        "repository_controls"
    ]["github_actions"]["affected"]

    assert result[
        "repository_controls"
    ]["infrastructure"]["affected"]


# ============================================================
# Manifest governance / full fan-out
# ============================================================

def test_components_manifest_change_forces_full_fan_out() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            ".github/components.yml",
        ],
    )

    assert result[
        "full_fan_out"
    ]

    assert (
        ".github/components.yml"
        in result[
            "full_fan_out_reasons"
        ]
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
        "worker",
    ]

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]

    frontend = result[
        "component_details"
    ]["frontend"]

    assert frontend[
        "application_changed"
    ]

    assert not frontend[
        "infrastructure_changed"
    ]

    assert result[
        "repository_controls"
    ]["github_actions"]["affected"]

    assert result[
        "repository_controls"
    ]["infrastructure"]["affected"]


def test_manifest_and_global_change_do_not_duplicate_matrix_entries() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            ".github/components.yml",
            "global.json",
            "backend/src/Program.cs",
        ],
    )

    matrix = result[
        "matrix"
    ]["include"]

    assert len(
        matrix
    ) == 3

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
        "worker",
    ]


# ============================================================
# Repository controls
# ============================================================

def test_repository_iac_change_does_not_activate_components() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "infra/shared/network.tf",
        ],
    )

    assert result[
        "affected_components"
    ] == []

    assert result[
        "affected_component_count"
    ] == 0

    assert result[
        "repository_controls"
    ]["infrastructure"]["affected"]

    assert not result[
        "repository_controls"
    ]["github_actions"]["affected"]

    assert (
        result[
            "repository_controls"
        ]["infrastructure"][
            "scan_path"
        ]
        == "infra/shared"
    )


def test_workflow_change_only_activates_actions_control() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            ".github/workflows/"
            "security.yml",
        ],
    )

    assert result[
        "affected_components"
    ] == []

    assert result[
        "repository_controls"
    ]["github_actions"]["affected"]

    assert not result[
        "repository_controls"
    ]["infrastructure"]["affected"]


def test_application_and_repository_iac_are_independent() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/Application.cs",
            "infra/shared/network.tf",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
    ]

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "application_changed"
    ]

    assert not backend[
        "infrastructure_changed"
    ]

    assert result[
        "repository_controls"
    ]["infrastructure"]["affected"]


def test_repository_iac_and_component_iac_are_independent() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/infra/main.tf",
            "infra/shared/network.tf",
        ],
    )

    backend = result[
        "component_details"
    ]["backend"]

    assert not backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]

    assert result[
        "repository_controls"
    ]["infrastructure"]["affected"]


# ============================================================
# Unmapped changes
# ============================================================

def test_unmapped_file_does_not_activate_component() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "docs/architecture.md",
        ],
    )

    assert result[
        "affected_components"
    ] == []

    assert result[
        "affected_component_count"
    ] == 0

    assert not result[
        "full_fan_out"
    ]

    assert not result[
        "repository_controls"
    ]["github_actions"]["affected"]

    assert not result[
        "repository_controls"
    ]["infrastructure"]["affected"]


def test_empty_change_set_is_valid() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [],
    )

    assert result[
        "affected_components"
    ] == []

    assert result[
        "affected_component_count"
    ] == 0

    assert not result[
        "full_fan_out"
    ]


# ============================================================
# Matrix metadata
# ============================================================

def test_backend_application_matrix_is_complete() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/Program.cs",
        ],
    )

    matrix = result[
        "matrix"
    ]["include"]

    assert len(
        matrix
    ) == 1

    backend = matrix[0]

    assert backend == {
        "name": "backend",
        "type": "application",
        "path": "backend",
        "language": "dotnet",
        "tier": 1,
        "application_changed": True,
        "build_enabled": True,
        "build_profile": "dotnet",
        "container_enabled": True,
        "infrastructure_enabled": True,
        "infrastructure_changed": False,
        "infrastructure_paths": [
            "backend/infra/**",
        ],
        "infrastructure_scan_path": (
            "backend/infra"
        ),
        "image_name": "fastqa-api",
        "dockerfile": "backend/Dockerfile",
        "build_context": "backend",
    }


def test_backend_iac_matrix_is_complete() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/infra/main.tf",
        ],
    )

    matrix = result[
        "matrix"
    ]["include"]

    assert len(
        matrix
    ) == 1

    backend = matrix[0]

    assert backend[
        "name"
    ] == "backend"

    assert not backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_enabled"
    ]

    assert backend[
        "infrastructure_changed"
    ]

    assert backend[
        "infrastructure_paths"
    ] == [
        "backend/infra/**",
    ]

    assert (
        backend[
            "infrastructure_scan_path"
        ]
        == "backend/infra"
    )


def test_frontend_matrix_has_disabled_iac() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "frontend/src/app.ts",
        ],
    )

    frontend = result[
        "matrix"
    ]["include"][0]

    assert frontend[
        "name"
    ] == "frontend"

    assert frontend[
        "application_changed"
    ]

    assert not frontend[
        "infrastructure_enabled"
    ]

    assert not frontend[
        "infrastructure_changed"
    ]

    assert frontend[
        "infrastructure_paths"
    ] == []

    assert (
        frontend[
            "infrastructure_scan_path"
        ]
        == ""
    )


def test_worker_matrix_has_empty_container_fields() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "worker/process.py",
        ],
    )

    worker = result[
        "matrix"
    ]["include"][0]

    assert not worker[
        "container_enabled"
    ]

    assert worker[
        "image_name"
    ] == ""

    assert worker[
        "dockerfile"
    ] == ""

    assert worker[
        "build_context"
    ] == ""


# ============================================================
# Multirepo
# ============================================================

@pytest.mark.parametrize(
    "changed_file",
    [
        "Program.cs",
        "src/Application.cs",
        "tests/ApplicationTests.cs",
        "README.md",
        ".github/workflows/ci.yml",
    ],
)
def test_multirepo_starstar_activates_application(
    changed_file: str,
) -> None:
    result = MODULE.detect_changes(
        multirepo_manifest(),
        [
            changed_file,
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
    ]

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "application_changed"
    ]

    assert not backend[
        "infrastructure_changed"
    ]


def test_multirepo_iac_precedence_works() -> None:
    result = MODULE.detect_changes(
        multirepo_with_iac_manifest(),
        [
            "infra/main.tf",
        ],
    )

    backend = result[
        "component_details"
    ]["backend"]

    assert not backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]


def test_multirepo_normal_source_still_activates_application() -> None:
    result = MODULE.detect_changes(
        multirepo_with_iac_manifest(),
        [
            "src/Application.cs",
        ],
    )

    backend = result[
        "component_details"
    ]["backend"]

    assert backend[
        "application_changed"
    ]

    assert not backend[
        "infrastructure_changed"
    ]


# ============================================================
# Changed-files loading
# ============================================================

def test_changed_files_are_normalized(
    tmp_path: Path,
) -> None:
    path = (
        tmp_path
        / "changed-files.txt"
    )

    path.write_text(
        "\n".join(
            [
                "./backend/src/Program.cs",
                "frontend\\src\\main.ts",
            ]
        ),
        encoding="utf-8",
    )

    result = MODULE.load_changed_files(
        path
    )

    assert result == [
        "backend/src/Program.cs",
        "frontend/src/main.ts",
    ]


def test_duplicate_changed_files_are_removed(
    tmp_path: Path,
) -> None:
    path = (
        tmp_path
        / "changed-files.txt"
    )

    path.write_text(
        "\n".join(
            [
                "backend/src/Program.cs",
                "./backend/src/Program.cs",
                "backend\\src\\Program.cs",
            ]
        ),
        encoding="utf-8",
    )

    result = MODULE.load_changed_files(
        path
    )

    assert result == [
        "backend/src/Program.cs",
    ]


def test_changed_file_parent_traversal_fails(
    tmp_path: Path,
) -> None:
    path = (
        tmp_path
        / "changed-files.txt"
    )

    path.write_text(
        "../outside.txt\n",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.ChangeDetectionError,
        match="Parent traversal",
    ):
        MODULE.load_changed_files(
            path
        )


def test_missing_changed_files_input_fails(
    tmp_path: Path,
) -> None:
    path = (
        tmp_path
        / "missing.txt"
    )

    with pytest.raises(
        MODULE.ChangeDetectionError,
        match=(
            "Changed-files input "
            "does not exist"
        ),
    ):
        MODULE.load_changed_files(
            path
        )


# ============================================================
# JSON evidence
# ============================================================

def test_detection_result_can_be_written_to_json(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/Program.cs",
        ],
    )

    path = (
        tmp_path
        / "affected-components.json"
    )

    MODULE.write_json_output(
        path,
        result,
    )

    loaded = json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )

    assert loaded[
        "schema_version"
    ] == 1

    assert loaded[
        "affected_components"
    ] == [
        "backend",
    ]


# ============================================================
# GitHub outputs
# ============================================================

def test_github_outputs_for_application_change(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/Program.cs",
        ],
    )

    path = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        path,
        result,
    )

    content = path.read_text(
        encoding="utf-8",
    )

    assert (
        'affected-components=["backend"]'
        in content
    )

    assert (
        "affected-components-count=1"
        in content
    )

    assert (
        "has-affected-components=true"
        in content
    )

    assert (
        "full-fan-out=false"
        in content
    )

    assert (
        "github-actions-affected=false"
        in content
    )

    assert (
        "infrastructure-affected=false"
        in content
    )


def test_github_outputs_for_repository_iac(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "infra/shared/main.tf",
        ],
    )

    path = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        path,
        result,
    )

    content = path.read_text(
        encoding="utf-8",
    )

    assert (
        "affected-components-count=0"
        in content
    )

    assert (
        "has-affected-components=false"
        in content
    )

    assert (
        "infrastructure-affected=true"
        in content
    )

    assert (
        "infrastructure-scan-path=infra/shared"
        in content
    )


def test_matrix_github_output_is_valid_json(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/infra/main.tf",
        ],
    )

    path = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        path,
        result,
    )

    content = path.read_text(
        encoding="utf-8",
    )

    matrix_line = next(
        line
        for line
        in content.splitlines()
        if line.startswith(
            "matrix="
        )
    )

    matrix = json.loads(
        matrix_line.split(
            "=",
            1,
        )[1]
    )

    assert len(
        matrix["include"]
    ) == 1

    backend = matrix[
        "include"
    ][0]

    assert backend[
        "name"
    ] == "backend"

    assert not backend[
        "application_changed"
    ]

    assert backend[
        "infrastructure_changed"
    ]


def test_empty_matrix_github_output(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "docs/architecture.md",
        ],
    )

    path = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        path,
        result,
    )

    content = path.read_text(
        encoding="utf-8",
    )

    assert (
        "affected-components-count=0"
        in content
    )

    assert (
        "has-affected-components=false"
        in content
    )

    assert (
        'matrix={"include":[]}'
        in content
    )


# ============================================================
# Deterministic output
# ============================================================

def test_component_matrix_is_sorted() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "worker/process.py",
            "backend/src/Program.cs",
            "frontend/src/main.ts",
        ],
    )

    names = [
        item["name"]
        for item
        in result[
            "matrix"
        ]["include"]
    ]

    assert names == [
        "backend",
        "frontend",
        "worker",
    ]


def test_reasons_do_not_duplicate() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/src/Program.cs",
            "backend/src/Program.cs",
        ],
    )

    reasons = result[
        "component_details"
    ]["backend"]["reasons"]

    assert reasons == [
        "application:"
        "backend/src/Program.cs"
    ]