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
                    "infra/**",
                ],

                "scan_path": "infra",
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
# Path normalization
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
            "backend\\file.cs",
            "backend/file.cs",
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
    "path",
    [
        "",
        " ",
        "/etc/passwd",
        "../backend/file.cs",
        "backend/../../frontend/file.ts",
    ],
)
def test_invalid_repository_path_fails(
    path: str,
) -> None:
    with pytest.raises(
        MODULE.ChangeDetectionError
    ):
        MODULE.normalize_repository_path(
            path
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
            "libs/common/auth.ts",
            "libs/common/**",
        ),
        (
            "anything/file.txt",
            "**",
        ),
        (
            ".github/workflows/security.yml",
            ".github/workflows/**",
        ),
    ],
)
def test_glob_matches(
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
    ],
)
def test_glob_does_not_match(
    changed_file: str,
    pattern: str,
) -> None:
    assert not MODULE.path_matches_pattern(
        changed_file,
        pattern,
    )


# ============================================================
# Direct component changes
# ============================================================

def test_backend_change_affects_only_backend() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/Controllers/"
            "CustomerController.cs"
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend"
    ]

    assert (
        result[
            "affected_component_count"
        ]
        == 1
    )

    assert not result[
        "full_fan_out"
    ]

    assert not result[
        "component_details"
    ]["frontend"]["affected"]

    assert not result[
        "component_details"
    ]["worker"]["affected"]


def test_frontend_change_affects_only_frontend() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "frontend/src/app/"
            "customer.component.ts"
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "frontend"
    ]


def test_worker_change_affects_only_worker() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "worker/processor.py"
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "worker"
    ]


# ============================================================
# Multiple independent changes
# ============================================================

def test_backend_and_frontend_changes_affect_both() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/Application.cs",
            "frontend/src/main.ts",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
    ]

    assert (
        result[
            "affected_component_count"
        ]
        == 2
    )


# ============================================================
# Shared paths
# ============================================================

def test_common_shared_path_affects_all_declared_components() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "libs/common/security/auth.ts"
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
        reasons = result[
            "component_details"
        ][component]["reasons"]

        assert any(
            reason.startswith(
                "shared:common:"
            )
            for reason in reasons
        )


def test_backend_shared_path_affects_only_declared_components() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "libs/backend-shared/"
            "validation.cs"
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


# ============================================================
# Global paths
# ============================================================

@pytest.mark.parametrize(
    "global_file",
    [
        "Directory.Build.props",
        "Directory.Packages.props",
        "global.json",
    ],
)
def test_global_path_forces_all_components(
    global_file: str,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            global_file,
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

    assert (
        result[
            "repository_controls"
        ]["github_actions"]["affected"]
    )

    assert (
        result[
            "repository_controls"
        ]["infrastructure"]["affected"]
    )


# ============================================================
# Manifest governance changes
# ============================================================

def test_components_manifest_change_forces_full_fan_out() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            ".github/components.yml"
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

    assert (
        result[
            "repository_controls"
        ]["github_actions"]["affected"]
    )

    assert (
        result[
            "repository_controls"
        ]["infrastructure"]["affected"]
    )

    assert (
        ".github/components.yml"
        in result[
            "full_fan_out_reasons"
        ]
    )


# ============================================================
# Repository controls
# ============================================================

def test_workflow_change_activates_only_github_actions_control() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            ".github/workflows/"
            "security.yml"
        ],
    )

    assert result[
        "affected_components"
    ] == []

    assert (
        result[
            "repository_controls"
        ]["github_actions"]["affected"]
    )

    assert not (
        result[
            "repository_controls"
        ]["infrastructure"]["affected"]
    )


def test_infrastructure_change_activates_only_infrastructure_control() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "infra/main.tf"
        ],
    )

    assert result[
        "affected_components"
    ] == []

    assert not (
        result[
            "repository_controls"
        ]["github_actions"]["affected"]
    )

    assert (
        result[
            "repository_controls"
        ]["infrastructure"]["affected"]
    )

    assert (
        result[
            "repository_controls"
        ]["infrastructure"]["scan_path"]
        == "infra"
    )


# ============================================================
# Unmapped files
# ============================================================

def test_unmapped_file_does_not_trigger_component() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "README.md"
        ],
    )

    assert result[
        "affected_components"
    ] == []

    assert (
        result[
            "affected_component_count"
        ]
        == 0
    )

    assert not result[
        "full_fan_out"
    ]


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
def test_multirepo_starstar_affects_application(
    changed_file: str,
) -> None:
    result = MODULE.detect_changes(
        multirepo_manifest(),
        [
            changed_file
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend"
    ]

    assert (
        result[
            "affected_component_count"
        ]
        == 1
    )


# ============================================================
# Matrix metadata
# ============================================================

def test_backend_matrix_contains_required_metadata() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/Program.cs"
        ],
    )

    matrix = result[
        "matrix"
    ]["include"]

    assert len(matrix) == 1

    backend = matrix[0]

    assert backend == {
        "name": "backend",
        "type": "application",
        "path": "backend",
        "language": "dotnet",
        "tier": 1,
        "build_enabled": True,
        "build_profile": "dotnet",
        "container_enabled": True,
        "image_name": "fastqa-api",
        "dockerfile": "backend/Dockerfile",
        "build_context": "backend",
    }


def test_non_container_matrix_uses_empty_container_fields() -> None:
    manifest = monorepo_manifest()

    manifest[
        "components"
    ]["worker"]["container"] = {
        "enabled": False
    }

    result = MODULE.detect_changes(
        manifest,
        [
            "worker/process.py"
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
# Empty change set
# ============================================================

def test_empty_change_set_is_valid() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [],
    )

    assert result[
        "affected_components"
    ] == []

    assert (
        result[
            "affected_component_count"
        ]
        == 0
    )

    assert not result[
        "full_fan_out"
    ]


# ============================================================
# Duplicate files
# ============================================================

def test_duplicate_changed_files_do_not_duplicate_components(
    tmp_path: Path,
) -> None:
    changed_file = (
        tmp_path
        / "changed-files.txt"
    )

    changed_file.write_text(
        "\n".join(
            [
                "backend/Program.cs",
                "backend/Program.cs",
                "./backend/Program.cs",
            ]
        ),
        encoding="utf-8",
    )

    loaded = MODULE.load_changed_files(
        changed_file
    )

    assert loaded == [
        "backend/Program.cs"
    ]


# ============================================================
# Changed-files input
# ============================================================

def test_changed_files_are_normalized(
    tmp_path: Path,
) -> None:
    changed_file = (
        tmp_path
        / "changed-files.txt"
    )

    changed_file.write_text(
        "\n".join(
            [
                "./backend/Program.cs",
                "frontend\\src\\main.ts",
            ]
        ),
        encoding="utf-8",
    )

    loaded = MODULE.load_changed_files(
        changed_file
    )

    assert loaded == [
        "backend/Program.cs",
        "frontend/src/main.ts",
    ]


def test_changed_files_parent_traversal_fails(
    tmp_path: Path,
) -> None:
    changed_file = (
        tmp_path
        / "changed-files.txt"
    )

    changed_file.write_text(
        "../outside.txt\n",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.ChangeDetectionError,
        match="Parent traversal",
    ):
        MODULE.load_changed_files(
            changed_file
        )


def test_missing_changed_files_input_fails(
    tmp_path: Path,
) -> None:
    missing = (
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
            missing
        )


# ============================================================
# GitHub outputs
# ============================================================

def test_github_outputs_are_generated(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/Program.cs",
            "infra/main.tf",
        ],
    )

    github_output = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        github_output,
        result,
    )

    content = github_output.read_text(
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
        "infrastructure-affected=true"
        in content
    )

    assert (
        "infrastructure-scan-path=infra"
        in content
    )


def test_matrix_output_is_valid_json(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/Program.cs"
        ],
    )

    github_output = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        github_output,
        result,
    )

    content = github_output.read_text(
        encoding="utf-8",
    )

    matrix_line = next(
        line
        for line in content.splitlines()
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

    assert (
        matrix[
            "include"
        ][0]["name"]
        == "backend"
    )


def test_empty_matrix_github_output(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "README.md"
        ],
    )

    github_output = (
        tmp_path
        / "github-output.txt"
    )

    MODULE.write_github_outputs(
        github_output,
        result,
    )

    content = github_output.read_text(
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
# JSON evidence
# ============================================================

def test_detection_result_can_be_written_as_json(
    tmp_path: Path,
) -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "backend/Program.cs"
        ],
    )

    output = (
        tmp_path
        / "affected-components.json"
    )

    MODULE.write_json_output(
        output,
        result,
    )

    loaded = json.loads(
        output.read_text(
            encoding="utf-8",
        )
    )

    assert loaded[
        "schema_version"
    ] == 1

    assert loaded[
        "affected_components"
    ] == [
        "backend"
    ]


# ============================================================
# Full fan-out reasons
# ============================================================

def test_multiple_global_changes_do_not_duplicate_components() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            "global.json",
            "Directory.Build.props",
        ],
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
        "worker",
    ]

    assert (
        len(
            result[
                "full_fan_out_reasons"
            ]
        )
        == 2
    )


def test_manifest_and_global_change_still_produce_single_matrix_entries() -> None:
    result = MODULE.detect_changes(
        monorepo_manifest(),
        [
            ".github/components.yml",
            "global.json",
            "backend/Program.cs",
        ],
    )

    matrix = result[
        "matrix"
    ]["include"]

    assert (
        len(matrix)
        == 3
    )

    assert result[
        "affected_components"
    ] == [
        "backend",
        "frontend",
        "worker",
    ]