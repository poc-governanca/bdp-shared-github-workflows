#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


COMPONENTS_MANIFEST = ".github/components.yml"


class ChangeDetectionError(Exception):
    """Raised when change detection cannot complete safely."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect affected repository components."
    )

    parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--changed-files",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--github-output",
        type=Path,
    )

    return parser.parse_args()


def load_yaml(
    path: Path,
) -> dict[str, Any]:
    if not path.exists():
        raise ChangeDetectionError(
            f"Components manifest does not exist: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            document = yaml.safe_load(file)

    except yaml.YAMLError as error:
        raise ChangeDetectionError(
            f"Invalid YAML in {path}: {error}"
        ) from error

    if not isinstance(document, dict):
        raise ChangeDetectionError(
            "Components manifest must contain a YAML object."
        )

    components = document.get(
        "components"
    )

    if (
        not isinstance(components, dict)
        or not components
    ):
        raise ChangeDetectionError(
            "Components manifest must define "
            "at least one component."
        )

    return document


def normalize_repository_path(
    value: str,
) -> str:
    if not isinstance(value, str):
        raise ChangeDetectionError(
            "Repository path must be a string."
        )

    normalized = (
        value.strip()
        .replace("\\", "/")
    )

    while normalized.startswith("./"):
        normalized = normalized[2:]

    if not normalized:
        raise ChangeDetectionError(
            "Repository path cannot be empty."
        )

    path = PurePosixPath(
        normalized
    )

    if path.is_absolute():
        raise ChangeDetectionError(
            f"Absolute paths are not permitted: {value}"
        )

    if ".." in path.parts:
        raise ChangeDetectionError(
            f"Parent traversal is not permitted: {value}"
        )

    result = str(path)

    if result in {
        "",
        ".",
    }:
        raise ChangeDetectionError(
            f"Invalid repository path: {value}"
        )

    return result


def normalize_pattern(
    value: str,
) -> str:
    if not isinstance(value, str):
        raise ChangeDetectionError(
            "Change-detection pattern must be a string."
        )

    normalized = (
        value.strip()
        .replace("\\", "/")
    )

    while normalized.startswith("./"):
        normalized = normalized[2:]

    if not normalized:
        raise ChangeDetectionError(
            "Change-detection pattern cannot be empty."
        )

    if normalized.startswith("/"):
        raise ChangeDetectionError(
            f"Absolute patterns are not permitted: {value}"
        )

    if ".." in PurePosixPath(
        normalized
    ).parts:
        raise ChangeDetectionError(
            f"Parent traversal is not permitted: {value}"
        )

    return normalized


def load_changed_files(
    path: Path,
) -> list[str]:
    if not path.exists():
        raise ChangeDetectionError(
            f"Changed-files input does not exist: {path}"
        )

    changed_files: list[str] = []

    for line_number, line in enumerate(
        path.read_text(
            encoding="utf-8",
        ).splitlines(),
        start=1,
    ):
        value = line.strip()

        if not value:
            continue

        try:
            normalized = (
                normalize_repository_path(
                    value
                )
            )

        except ChangeDetectionError as error:
            raise ChangeDetectionError(
                f"Invalid changed file at line "
                f"{line_number}: {error}"
            ) from error

        if normalized not in changed_files:
            changed_files.append(
                normalized
            )

    return changed_files


def path_matches_pattern(
    changed_file: str,
    pattern: str,
) -> bool:
    file_path = (
        normalize_repository_path(
            changed_file
        )
    )

    normalized_pattern = (
        normalize_pattern(
            pattern
        )
    )

    if normalized_pattern == "**":
        return True

    if file_path == normalized_pattern:
        return True

    if normalized_pattern.endswith("/**"):
        directory = (
            normalized_pattern[:-3]
            .rstrip("/")
        )

        if (
            file_path == directory
            or file_path.startswith(
                f"{directory}/"
            )
        ):
            return True

    return fnmatch.fnmatchcase(
        file_path,
        normalized_pattern,
    )


def matches_any_pattern(
    changed_file: str,
    patterns: list[str],
) -> bool:
    return any(
        path_matches_pattern(
            changed_file,
            pattern,
        )
        for pattern in patterns
    )


def create_component_matrix_entry(
    name: str,
    component: dict[str, Any],
    application_changed: bool,
    infrastructure_changed: bool,
) -> dict[str, Any]:
    build = component["build"]
    container = component["container"]
    infrastructure = component[
        "infrastructure"
    ]

    entry: dict[str, Any] = {
        "name": name,
        "type": component["type"],
        "path": component["path"],
        "language": component["language"],
        "tier": component["tier"],
        "application_changed": (
            application_changed
        ),
        "build_enabled": (
            build["enabled"]
        ),
        "build_profile": (
            build["profile"]
        ),
        "container_enabled": (
            container["enabled"]
        ),
        "infrastructure_enabled": (
            infrastructure["enabled"]
        ),
        "infrastructure_changed": (
            infrastructure_changed
        ),
        "infrastructure_paths": (
            infrastructure.get(
                "paths",
                [],
            )
            if infrastructure["enabled"]
            else []
        ),
        "infrastructure_scan_path": (
            infrastructure.get(
                "scan_path",
                "",
            )
        ),
    }

    if container["enabled"]:
        entry.update(
            {
                "image_name": (
                    container["image_name"]
                ),
                "dockerfile": (
                    container["dockerfile"]
                ),
                "build_context": (
                    container["build_context"]
                ),
            }
        )

    else:
        entry.update(
            {
                "image_name": "",
                "dockerfile": "",
                "build_context": "",
            }
        )

    return entry


def enabled_repository_controls(
    document: dict[str, Any],
) -> dict[str, bool]:
    controls = document.get(
        "repository_controls",
        {},
    )

    result = {
        "github_actions": False,
        "infrastructure": False,
    }

    for name in result:
        control = controls.get(
            name
        )

        if isinstance(
            control,
            dict,
        ):
            result[name] = bool(
                control.get(
                    "enabled",
                    False,
                )
            )

    return result


def repository_infrastructure_configuration(
    document: dict[str, Any],
) -> dict[str, Any]:
    control = (
        document
        .get(
            "repository_controls",
            {},
        )
        .get(
            "infrastructure",
            {},
        )
    )

    return {
        "enabled": bool(
            control.get(
                "enabled",
                False,
            )
        ),
        "scan_path": (
            control.get(
                "scan_path",
                "",
            )
        ),
    }


def detect_changes(
    document: dict[str, Any],
    changed_files: list[str],
) -> dict[str, Any]:
    components = document[
        "components"
    ]

    application_changes = {
        name: False
        for name in components
    }

    infrastructure_changes = {
        name: False
        for name in components
    }

    component_reasons: dict[
        str,
        list[str],
    ] = {
        name: []
        for name in components
    }

    repository_controls = {
        "github_actions": False,
        "infrastructure": False,
    }

    control_reasons: dict[
        str,
        list[str],
    ] = {
        "github_actions": [],
        "infrastructure": [],
    }

    full_fan_out = False

    full_fan_out_reasons: list[str] = []

    if not changed_files:
        return build_detection_result(
            document=document,
            changed_files=[],
            application_changes=application_changes,
            infrastructure_changes=infrastructure_changes,
            component_reasons=component_reasons,
            repository_controls=repository_controls,
            control_reasons=control_reasons,
            full_fan_out=False,
            full_fan_out_reasons=[],
        )

    if (
        COMPONENTS_MANIFEST
        in changed_files
    ):
        full_fan_out = True

        full_fan_out_reasons.append(
            COMPONENTS_MANIFEST
        )

    global_paths = document.get(
        "global_paths",
        [],
    )

    for changed_file in changed_files:
        if matches_any_pattern(
            changed_file,
            global_paths,
        ):
            full_fan_out = True

            full_fan_out_reasons.append(
                changed_file
            )

    if full_fan_out:
        for (
            name,
            component,
        ) in components.items():
            application_changes[
                name
            ] = True

            if component[
                "infrastructure"
            ]["enabled"]:
                infrastructure_changes[
                    name
                ] = True

            component_reasons[
                name
            ].append(
                "full-fan-out"
            )

        enabled_controls = (
            enabled_repository_controls(
                document
            )
        )

        for (
            name,
            enabled,
        ) in enabled_controls.items():
            if enabled:
                repository_controls[
                    name
                ] = True

                control_reasons[
                    name
                ].append(
                    "full-fan-out"
                )

        return build_detection_result(
            document=document,
            changed_files=changed_files,
            application_changes=application_changes,
            infrastructure_changes=infrastructure_changes,
            component_reasons=component_reasons,
            repository_controls=repository_controls,
            control_reasons=control_reasons,
            full_fan_out=True,
            full_fan_out_reasons=sorted(
                set(
                    full_fan_out_reasons
                )
            ),
        )

    #
    # Component-local changes.
    #
    # Component IaC takes precedence over broad application
    # patterns such as "backend/**".
    #
    for (
        name,
        component,
    ) in components.items():
        application_patterns = (
            component[
                "paths"
            ]
        )

        infrastructure = (
            component[
                "infrastructure"
            ]
        )

        infrastructure_patterns = (
            infrastructure.get(
                "paths",
                [],
            )
            if infrastructure[
                "enabled"
            ]
            else []
        )

        for changed_file in changed_files:
            infrastructure_match = (
                infrastructure[
                    "enabled"
                ]
                and matches_any_pattern(
                    changed_file,
                    infrastructure_patterns,
                )
            )

            if infrastructure_match:
                infrastructure_changes[
                    name
                ] = True

                component_reasons[
                    name
                ].append(
                    "infrastructure:"
                    f"{changed_file}"
                )

                continue

            if matches_any_pattern(
                changed_file,
                application_patterns,
            ):
                application_changes[
                    name
                ] = True

                component_reasons[
                    name
                ].append(
                    "application:"
                    f"{changed_file}"
                )

    #
    # Shared paths affect application execution only.
    #
    shared_paths = document.get(
        "shared_paths",
        {},
    )

    for (
        shared_name,
        configuration,
    ) in shared_paths.items():
        matching_files = [
            changed_file
            for changed_file
            in changed_files
            if matches_any_pattern(
                changed_file,
                configuration["paths"],
            )
        ]

        if not matching_files:
            continue

        for component_name in (
            configuration[
                "affects"
            ]
        ):
            application_changes[
                component_name
            ] = True

            for changed_file in (
                matching_files
            ):
                component_reasons[
                    component_name
                ].append(
                    f"shared:"
                    f"{shared_name}:"
                    f"{changed_file}"
                )

    #
    # Repository-level controls.
    #
    controls = document.get(
        "repository_controls",
        {},
    )

    for control_name in (
        "github_actions",
        "infrastructure",
    ):
        control = controls.get(
            control_name,
            {},
        )

        if not control.get(
            "enabled",
            False,
        ):
            continue

        patterns = control.get(
            "paths",
            [],
        )

        for changed_file in (
            changed_files
        ):
            if matches_any_pattern(
                changed_file,
                patterns,
            ):
                repository_controls[
                    control_name
                ] = True

                control_reasons[
                    control_name
                ].append(
                    changed_file
                )

    return build_detection_result(
        document=document,
        changed_files=changed_files,
        application_changes=application_changes,
        infrastructure_changes=infrastructure_changes,
        component_reasons=component_reasons,
        repository_controls=repository_controls,
        control_reasons=control_reasons,
        full_fan_out=False,
        full_fan_out_reasons=[],
    )


def build_detection_result(
    document: dict[str, Any],
    changed_files: list[str],
    application_changes: dict[str, bool],
    infrastructure_changes: dict[str, bool],
    component_reasons: dict[str, list[str]],
    repository_controls: dict[str, bool],
    control_reasons: dict[str, list[str]],
    full_fan_out: bool,
    full_fan_out_reasons: list[str],
) -> dict[str, Any]:
    components = document[
        "components"
    ]

    affected_components = {
        name
        for name in components
        if (
            application_changes[
                name
            ]
            or infrastructure_changes[
                name
            ]
        )
    }

    matrix = [
        create_component_matrix_entry(
            name=name,
            component=components[
                name
            ],
            application_changed=(
                application_changes[
                    name
                ]
            ),
            infrastructure_changed=(
                infrastructure_changes[
                    name
                ]
            ),
        )
        for name in sorted(
            affected_components
        )
    ]

    component_details = {
        name: {
            "affected": (
                name
                in affected_components
            ),
            "application_changed": (
                application_changes[
                    name
                ]
            ),
            "infrastructure_changed": (
                infrastructure_changes[
                    name
                ]
            ),
            "reasons": sorted(
                set(
                    component_reasons.get(
                        name,
                        [],
                    )
                )
            ),
        }
        for name in sorted(
            components
        )
    }

    repository_iac = (
        repository_infrastructure_configuration(
            document
        )
    )

    return {
        "schema_version": 1,
        "full_fan_out": (
            full_fan_out
        ),
        "full_fan_out_reasons": (
            full_fan_out_reasons
        ),
        "changed_files": (
            changed_files
        ),
        "affected_component_count": (
            len(
                matrix
            )
        ),
        "affected_components": sorted(
            affected_components
        ),
        "matrix": {
            "include": matrix,
        },
        "component_details": (
            component_details
        ),
        "repository_controls": {
            "github_actions": {
                "affected": (
                    repository_controls[
                        "github_actions"
                    ]
                ),
                "reasons": sorted(
                    set(
                        control_reasons[
                            "github_actions"
                        ]
                    )
                ),
            },
            "infrastructure": {
                "affected": (
                    repository_controls[
                        "infrastructure"
                    ]
                ),
                "enabled": (
                    repository_iac[
                        "enabled"
                    ]
                ),
                "scan_path": (
                    repository_iac[
                        "scan_path"
                    ]
                ),
                "reasons": sorted(
                    set(
                        control_reasons[
                            "infrastructure"
                        ]
                    )
                ),
            },
        },
    }


def write_json_output(
    path: Path,
    result: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            result,
            file,
            indent=2,
            ensure_ascii=False,
        )

        file.write(
            "\n"
        )


def compact_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        separators=(
            ",",
            ":",
        ),
        ensure_ascii=False,
    )


def write_github_outputs(
    path: Path,
    result: dict[str, Any],
) -> None:
    controls = result[
        "repository_controls"
    ]

    outputs = {
        "affected-components": compact_json(
            result[
                "affected_components"
            ]
        ),
        "affected-components-count": str(
            result[
                "affected_component_count"
            ]
        ),
        "matrix": compact_json(
            result[
                "matrix"
            ]
        ),
        "has-affected-components": (
            "true"
            if result[
                "affected_component_count"
            ] > 0
            else "false"
        ),
        "full-fan-out": (
            "true"
            if result[
                "full_fan_out"
            ]
            else "false"
        ),
        "github-actions-affected": (
            "true"
            if controls[
                "github_actions"
            ]["affected"]
            else "false"
        ),
        "infrastructure-affected": (
            "true"
            if controls[
                "infrastructure"
            ]["affected"]
            else "false"
        ),
        "infrastructure-scan-path": (
            controls[
                "infrastructure"
            ]["scan_path"]
        ),
    }

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "a",
        encoding="utf-8",
    ) as file:
        for (
            name,
            value,
        ) in outputs.items():
            file.write(
                f"{name}={value}\n"
            )


def print_summary(
    result: dict[str, Any],
) -> None:
    print(
        "Repository Change Detection"
    )

    print(
        "=" * 56
    )

    print(
        "Changed files.........: "
        f"{len(result['changed_files'])}"
    )

    print(
        "Full fan-out..........: "
        f"{result['full_fan_out']}"
    )

    print(
        "Affected components...: "
        f"{result['affected_component_count']}"
    )

    for component in (
        result[
            "affected_components"
        ]
    ):
        details = result[
            "component_details"
        ][component]

        print(
            f"- {component}: "
            f"application="
            f"{details['application_changed']} "
            f"infrastructure="
            f"{details['infrastructure_changed']}"
        )

    controls = result[
        "repository_controls"
    ]

    print(
        "GitHub Actions.........: "
        f"{controls['github_actions']['affected']}"
    )

    print(
        "Repository IaC........: "
        f"{controls['infrastructure']['affected']}"
    )

    print(
        "=" * 56
    )


def main() -> int:
    arguments = (
        parse_arguments()
    )

    try:
        document = load_yaml(
            arguments.manifest
        )

        changed_files = (
            load_changed_files(
                arguments.changed_files
            )
        )

        result = detect_changes(
            document=document,
            changed_files=changed_files,
        )

        write_json_output(
            arguments.output,
            result,
        )

        if (
            arguments.github_output
        ):
            write_github_outputs(
                arguments.github_output,
                result,
            )

        print_summary(
            result
        )

        return 0

    except ChangeDetectionError as error:
        print(
            "::error::Repository change "
            "detection failed."
        )

        print(
            f"::error::{error}"
        )

        return 1


if __name__ == "__main__":
    sys.exit(
        main()
    )