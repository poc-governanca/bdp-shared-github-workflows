#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


ALLOWED_TIERS = {"1", "2", "3"}

ALLOWED_SEVERITIES = {
    "UNKNOWN",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

BLOCKING_SEVERITIES = {
    "1": {"HIGH", "CRITICAL"},
    "2": {"HIGH", "CRITICAL"},
    "3": {"CRITICAL"},
}

FORBIDDEN_SCOPE_CHARACTERS = {
    "*",
    "?",
}


class ContainerEvaluationError(Exception):
    """Raised when container findings cannot be evaluated safely."""


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate Trivy container vulnerabilities against "
            "governed false-positive exceptions."
        )
    )

    parser.add_argument(
        "--results",
        required=True,
        type=Path,
        help="Path to raw Trivy container JSON results.",
    )

    parser.add_argument(
        "--exceptions",
        required=True,
        type=Path,
        help="Path to .security/trivy-ignore.yaml.",
    )

    parser.add_argument(
        "--package-types-policy",
        required=True,
        type=Path,
        help="Path to approved Trivy package types policy.",
    )

    parser.add_argument(
        "--tier",
        required=True,
        help="Asset Tier: 1, 2 or 3.",
    )

    parser.add_argument(
        "--image-ref",
        required=True,
        help="Container image reference scanned by Trivy.",
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to effective-container-results.json.",
    )

    return parser.parse_args()


# ============================================================
# FILE LOADING
# ============================================================

def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ContainerEvaluationError(
            f"Results file does not exist: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            document = json.load(file)

    except json.JSONDecodeError as error:
        raise ContainerEvaluationError(
            f"Invalid JSON in {path}: {error}"
        ) from error

    if not isinstance(document, dict):
        raise ContainerEvaluationError(
            "Trivy output must contain a JSON object."
        )

    return document


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ContainerEvaluationError(
            f"YAML file does not exist: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            document = yaml.safe_load(file)

    except yaml.YAMLError as error:
        raise ContainerEvaluationError(
            f"Invalid YAML in {path}: {error}"
        ) from error

    if document is None:
        return {}

    if not isinstance(document, dict):
        raise ContainerEvaluationError(
            f"Expected YAML object in {path}"
        )

    return document


# ============================================================
# BASIC VALIDATION
# ============================================================

def validate_tier(tier: str) -> None:
    if tier not in ALLOWED_TIERS:
        raise ContainerEvaluationError(
            f"Invalid Tier '{tier}'. Allowed values: 1, 2 or 3."
        )


def normalize_severity(value: Any) -> str:
    severity = str(value or "UNKNOWN").strip().upper()

    if severity not in ALLOWED_SEVERITIES:
        raise ContainerEvaluationError(
            f"Unsupported vulnerability severity: {severity}"
        )

    return severity


# ============================================================
# IMAGE NORMALIZATION
# ============================================================

def normalize_image_name(image_ref: str) -> str:
    value = image_ref.strip()

    if not value:
        raise ContainerEvaluationError(
            "image_ref cannot be empty."
        )

    if any(
        character in value
        for character in FORBIDDEN_SCOPE_CHARACTERS
    ):
        raise ContainerEvaluationError(
            f"Wildcards are not permitted in image_ref: {image_ref}"
        )

    #
    # Remove digest.
    #
    # Example:
    #
    # fastqa-api@sha256:abcdef
    # ↓
    # fastqa-api
    #
    value = value.split("@", 1)[0]

    #
    # Remove registry / organization.
    #
    # ghcr.io/poc-governanca/fastqa-api
    # ↓
    # fastqa-api
    #
    value = value.rsplit("/", 1)[-1]

    #
    # Remove tag.
    #
    # fastqa-api:v1.0.0
    # ↓
    # fastqa-api
    #
    if ":" in value:
        value = value.split(":", 1)[0]

    value = value.strip()

    if not value:
        raise ContainerEvaluationError(
            f"Unable to normalize image_ref: {image_ref}"
        )

    return value


# ============================================================
# PACKAGE NORMALIZATION
# ============================================================

def normalize_package(value: Any) -> str:
    package = str(value or "").strip()

    if not package:
        raise ContainerEvaluationError(
            "Package name cannot be empty."
        )

    if any(
        character in package
        for character in FORBIDDEN_SCOPE_CHARACTERS
    ):
        raise ContainerEvaluationError(
            f"Wildcard package name is prohibited: {package}"
        )

    return package


def normalize_package_type(value: Any) -> str:
    package_type = str(value or "").strip()

    if any(
        character in package_type
        for character in FORBIDDEN_SCOPE_CHARACTERS
    ):
        raise ContainerEvaluationError(
            f"Wildcard package_type is prohibited: {package_type}"
        )

    return package_type


# ============================================================
# PACKAGE TYPE POLICY
# ============================================================

def load_allowed_package_types(
    document: dict[str, Any],
) -> set[str]:

    if document.get("version") != 1:
        raise ContainerEvaluationError(
            "Unsupported package types policy version."
        )

    values = document.get(
        "allowed_package_types",
        [],
    )

    if not isinstance(values, list):
        raise ContainerEvaluationError(
            "allowed_package_types must be an array."
        )

    result: set[str] = set()

    for value in values:

        if not isinstance(value, str):
            raise ContainerEvaluationError(
                "Invalid package_type in policy."
            )

        normalized = normalize_package_type(
            value
        )

        if not normalized:
            raise ContainerEvaluationError(
                "Empty package_type is not permitted "
                "in the policy."
            )

        result.add(normalized)

    return result


# ============================================================
# GOVERNED EXCEPTIONS
# ============================================================

def extract_container_exceptions(
    document: dict[str, Any],
) -> list[dict[str, Any]]:

    entries = document.get(
        "exceptions",
        [],
    )

    if not isinstance(entries, list):
        raise ContainerEvaluationError(
            "exceptions must be an array."
        )

    result: list[dict[str, Any]] = []

    for entry in entries:

        if not isinstance(entry, dict):
            raise ContainerEvaluationError(
                "Each exception must be an object."
            )

        #
        # Ignore entries belonging to IaC.
        #
        if entry.get("category") != "container":
            continue

        finding_id = entry.get("id")

        if (
            not isinstance(finding_id, str)
            or not finding_id.strip()
        ):
            raise ContainerEvaluationError(
                "Container exception is missing a valid "
                "vulnerability ID."
            )

        scope = entry.get("scope")

        if not isinstance(scope, dict):
            raise ContainerEvaluationError(
                f"{finding_id}: container exception "
                "scope is missing or invalid."
            )

        image = scope.get("image")
        package = scope.get("package")
        package_type = scope.get(
            "package_type"
        )

        if (
            not isinstance(image, str)
            or not image.strip()
        ):
            raise ContainerEvaluationError(
                f"{finding_id}: scope.image is required."
            )

        if (
            not isinstance(package, str)
            or not package.strip()
        ):
            raise ContainerEvaluationError(
                f"{finding_id}: scope.package is required."
            )

        if (
            not isinstance(package_type, str)
            or not package_type.strip()
        ):
            raise ContainerEvaluationError(
                f"{finding_id}: scope.package_type "
                "is required."
            )

        reference = (
            entry
            .get("reference", {})
            .get("security_review")
        )

        if (
            not isinstance(reference, str)
            or not reference.strip()
        ):
            raise ContainerEvaluationError(
                f"{finding_id}: Security Review "
                "reference is required."
            )

        result.append(
            {
                "id": finding_id.strip(),
                "image": normalize_image_name(
                    image
                ),
                "package": normalize_package(
                    package
                ),
                "package_type":
                    normalize_package_type(
                        package_type
                    ),
                "security_review":
                    reference.strip(),
            }
        )

    return result


# ============================================================
# TRIVY FINDINGS
# ============================================================

def extract_vulnerabilities(
    document: dict[str, Any],
    logical_image: str,
) -> list[dict[str, Any]]:

    results = document.get(
        "Results",
        [],
    )

    if results is None:
        results = []

    if not isinstance(results, list):
        raise ContainerEvaluationError(
            "Trivy Results must be an array."
        )

    findings: list[dict[str, Any]] = []

    for result_index, result in enumerate(
        results
    ):

        if not isinstance(result, dict):
            raise ContainerEvaluationError(
                f"Trivy result {result_index} "
                "must be an object."
            )

        #
        # Trivy exposes result context through Type.
        #
        # We preserve it as package_type.
        #
        package_type = normalize_package_type(
            result.get("Type")
        )

        vulnerabilities = (
            result.get("Vulnerabilities")
            or []
        )

        if not isinstance(
            vulnerabilities,
            list,
        ):
            raise ContainerEvaluationError(
                f"Vulnerabilities for result "
                f"{result_index} must be an array."
            )

        for vulnerability_index, vulnerability in enumerate(
            vulnerabilities
        ):

            if not isinstance(
                vulnerability,
                dict,
            ):
                raise ContainerEvaluationError(
                    f"Vulnerability "
                    f"{result_index}/"
                    f"{vulnerability_index} "
                    "must be an object."
                )

            vulnerability_id = (
                vulnerability.get(
                    "VulnerabilityID"
                )
            )

            package = vulnerability.get(
                "PkgName"
            )

            if (
                not isinstance(
                    vulnerability_id,
                    str,
                )
                or not vulnerability_id.strip()
            ):
                raise ContainerEvaluationError(
                    "Trivy returned a vulnerability "
                    "without VulnerabilityID."
                )

            if (
                not isinstance(package, str)
                or not package.strip()
            ):
                raise ContainerEvaluationError(
                    f"{vulnerability_id}: "
                    "Trivy returned a vulnerability "
                    "without PkgName."
                )

            severity = normalize_severity(
                vulnerability.get(
                    "Severity"
                )
            )

            findings.append(
                {
                    "id":
                        vulnerability_id.strip(),

                    "image":
                        logical_image,

                    "package":
                        normalize_package(
                            package
                        ),

                    "package_type":
                        package_type,

                    "severity":
                        severity,

                    "installed_version":
                        str(
                            vulnerability.get(
                                "InstalledVersion"
                            )
                            or ""
                        ),

                    "fixed_version":
                        str(
                            vulnerability.get(
                                "FixedVersion"
                            )
                            or ""
                        ),

                    "title":
                        str(
                            vulnerability.get(
                                "Title"
                            )
                            or ""
                        ),

                    "description":
                        str(
                            vulnerability.get(
                                "Description"
                            )
                            or ""
                        ),

                    "primary_url":
                        str(
                            vulnerability.get(
                                "PrimaryURL"
                            )
                            or ""
                        ),
                }
            )

    return findings


# ============================================================
# EXCEPTION INDEX
# ============================================================

def build_exception_index(
    exceptions: list[dict[str, Any]],
) -> dict[
    tuple[str, str, str, str],
    dict[str, Any],
]:

    index: dict[
        tuple[str, str, str, str],
        dict[str, Any],
    ] = {}

    for exception in exceptions:

        key = (
            exception["id"],
            exception["image"],
            exception["package"],
            exception["package_type"],
        )

        if key in index:
            raise ContainerEvaluationError(
                "Duplicate governed container exception: "
                + " / ".join(key)
            )

        index[key] = exception

    return index


# ============================================================
# EVALUATION
# ============================================================

def evaluate_findings(
    findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
    allowed_package_types: set[str],
    tier: str,
) -> dict[str, Any]:

    validate_tier(tier)

    exception_index = (
        build_exception_index(
            exceptions
        )
    )

    matched_exceptions: set[
        tuple[str, str, str, str]
    ] = set()

    evaluated_findings: list[
        dict[str, Any]
    ] = []

    active_counts = Counter(
        {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
    )

    exempted_count = 0

    for finding in findings:

        severity = finding[
            "severity"
        ]

        key = (
            finding["id"],
            finding["image"],
            finding["package"],
            finding["package_type"],
        )

        exception = (
            exception_index.get(key)
        )

        effective = dict(finding)

        if exception:

            #
            # An exception can only be applied if the package
            # type has been explicitly approved.
            #
            if (
                finding["package_type"]
                not in allowed_package_types
            ):
                raise ContainerEvaluationError(
                    "A governed exception matches "
                    "an unapproved package_type: "
                    f"{finding['package_type']}. "
                    "Failing closed."
                )

            matched_exceptions.add(
                key
            )

            exempted_count += 1

            effective["status"] = (
                "EXEMPTED"
            )

            effective[
                "exception_reference"
            ] = exception[
                "security_review"
            ]

        else:

            effective["status"] = (
                "ACTIVE"
            )

            active_counts[
                severity
            ] += 1

        evaluated_findings.append(
            effective
        )

    # --------------------------------------------------------
    # Stale exceptions
    # --------------------------------------------------------

    stale_exceptions = []

    for key, exception in (
        exception_index.items()
    ):

        if key in matched_exceptions:
            continue

        stale_exceptions.append(
            {
                "id":
                    exception["id"],

                "image":
                    exception["image"],

                "package":
                    exception["package"],

                "package_type":
                    exception[
                        "package_type"
                    ],

                "status":
                    "STALE_EXCEPTION",

                "exception_reference":
                    exception[
                        "security_review"
                    ],
            }
        )

    # --------------------------------------------------------
    # Security Gate
    # --------------------------------------------------------

    blocking_severities = (
        BLOCKING_SEVERITIES[
            tier
        ]
    )

    blocking_findings = [
        finding
        for finding
        in evaluated_findings
        if (
            finding["status"]
            == "ACTIVE"
            and finding["severity"]
            in blocking_severities
        )
    ]

    gate = (
        "FAIL"
        if blocking_findings
        else "PASS"
    )

    return {
        "schema_version": 1,

        "scanner": "trivy",

        "category": "container",

        "tier": tier,

        "summary": {
            "active": {
                "critical":
                    active_counts[
                        "CRITICAL"
                    ],
                "high":
                    active_counts[
                        "HIGH"
                    ],
                "medium":
                    active_counts[
                        "MEDIUM"
                    ],
                "low":
                    active_counts[
                        "LOW"
                    ],
                "unknown":
                    active_counts[
                        "UNKNOWN"
                    ],
            },

            "exempted":
                exempted_count,

            "stale_exceptions":
                len(
                    stale_exceptions
                ),

            "blocking_findings":
                len(
                    blocking_findings
                ),
        },

        "gate":
            gate,

        "findings":
            evaluated_findings,

        "stale_exceptions":
            stale_exceptions,
    }


# ============================================================
# OUTPUT
# ============================================================

def write_output(
    path: Path,
    evaluation: dict[str, Any],
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
            evaluation,
            file,
            indent=2,
            ensure_ascii=False,
        )

        file.write("\n")


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    evaluation: dict[str, Any],
) -> None:

    summary = evaluation[
        "summary"
    ]

    active = summary[
        "active"
    ]

    print(
        "Container Security Evaluation"
    )

    print(
        "=" * 50
    )

    print(
        f"Image..............: "
        f"{evaluation['image']}"
    )

    print(
        f"Tier...............: "
        f"{evaluation['tier']}"
    )

    print(
        f"Critical Active....: "
        f"{active['critical']}"
    )

    print(
        f"High Active........: "
        f"{active['high']}"
    )

    print(
        f"Medium Active......: "
        f"{active['medium']}"
    )

    print(
        f"Low Active.........: "
        f"{active['low']}"
    )

    print(
        f"Unknown Active.....: "
        f"{active['unknown']}"
    )

    print(
        f"Exempted...........: "
        f"{summary['exempted']}"
    )

    print(
        f"Stale Exceptions...: "
        f"{summary['stale_exceptions']}"
    )

    print(
        f"Blocking Findings..: "
        f"{summary['blocking_findings']}"
    )

    print(
        "=" * 50
    )

    print(
        f"Security Gate......: "
        f"{evaluation['gate']}"
    )

    for stale in evaluation[
        "stale_exceptions"
    ]:

        print(
            "::warning::Stale container "
            "exception detected: "
            f"{stale['id']} "
            f"image={stale['image']} "
            f"package={stale['package']} "
            f"type={stale['package_type']} "
            f"reference="
            f"{stale['exception_reference']}. "
            "No matching active finding exists. "
            "Remove the exception from "
            ".security/trivy-ignore.yaml."
        )


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    args = parse_arguments()

    try:

        validate_tier(
            args.tier
        )

        logical_image = (
            normalize_image_name(
                args.image_ref
            )
        )

        trivy_document = (
            load_json(
                args.results
            )
        )

        exception_document = (
            load_yaml(
                args.exceptions
            )
        )

        package_policy = (
            load_yaml(
                args.package_types_policy
            )
        )

        allowed_package_types = (
            load_allowed_package_types(
                package_policy
            )
        )

        exceptions = (
            extract_container_exceptions(
                exception_document
            )
        )

        findings = (
            extract_vulnerabilities(
                trivy_document,
                logical_image,
            )
        )

        evaluation = (
            evaluate_findings(
                findings=findings,
                exceptions=exceptions,
                allowed_package_types=(
                    allowed_package_types
                ),
                tier=args.tier,
            )
        )

        evaluation[
            "image"
        ] = logical_image

        write_output(
            args.output,
            evaluation,
        )

        print_summary(
            evaluation
        )

        if (
            evaluation["gate"]
            == "FAIL"
        ):

            print(
                "::error::Container "
                "Security Gate failed "
                "because active blocking "
                "vulnerabilities exist."
            )

            return 1

        return 0

    except ContainerEvaluationError as error:

        print(
            "::error::Container security "
            "evaluation failed."
        )

        print(
            f"::error::{error}"
        )

        return 2


if __name__ == "__main__":
    sys.exit(
        main()
    )