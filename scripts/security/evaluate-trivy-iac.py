#!/usr/bin/env python3

import argparse
import json
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
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

FORBIDDEN_PATH_CHARACTERS = {
    "*",
    "?",
}


class IacEvaluationError(Exception):
    """Raised when IaC findings cannot be evaluated safely."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate Trivy IaC findings against governed "
            "false-positive exceptions."
        )
    )

    parser.add_argument(
        "--results",
        required=True,
        type=Path,
        help="Path to the raw Trivy IaC JSON results.",
    )

    parser.add_argument(
        "--exceptions",
        required=True,
        type=Path,
        help="Path to .security/trivy-ignore.yaml.",
    )

    parser.add_argument(
        "--tier",
        required=True,
        help="Asset Tier: 1, 2 or 3.",
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path for effective-iac-results.json.",
    )

    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise IacEvaluationError(
            f"Trivy results file does not exist: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            document = json.load(file)
    except json.JSONDecodeError as error:
        raise IacEvaluationError(
            f"Invalid JSON in Trivy results file: {error}"
        ) from error

    if not isinstance(document, dict):
        raise IacEvaluationError(
            "Trivy results must contain a JSON object."
        )

    return document


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise IacEvaluationError(
            f"Exceptions file does not exist: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            document = yaml.safe_load(file)
    except yaml.YAMLError as error:
        raise IacEvaluationError(
            f"Invalid YAML in exceptions file: {error}"
        ) from error

    if document is None:
        return {
            "version": 1,
            "exceptions": [],
        }

    if not isinstance(document, dict):
        raise IacEvaluationError(
            "Exceptions file must contain a YAML object."
        )

    return document


def validate_tier(tier: str) -> None:
    if tier not in ALLOWED_TIERS:
        raise IacEvaluationError(
            f"Invalid Tier '{tier}'. Allowed values: 1, 2, 3."
        )


def normalize_path(value: str) -> str:
    if not isinstance(value, str):
        raise IacEvaluationError(
            "Finding and exception paths must be strings."
        )

    normalized = value.strip().replace("\\", "/")

    while normalized.startswith("./"):
        normalized = normalized[2:]

    if not normalized:
        raise IacEvaluationError(
            "Finding or exception path cannot be empty."
        )

    if any(
        character in normalized
        for character in FORBIDDEN_PATH_CHARACTERS
    ):
        raise IacEvaluationError(
            f"Wildcards are not permitted in IaC paths: {value}"
        )

    path = PurePosixPath(normalized)

    if path.is_absolute():
        raise IacEvaluationError(
            f"Absolute paths are not permitted: {value}"
        )

    if ".." in path.parts:
        raise IacEvaluationError(
            f"Parent traversal is not permitted: {value}"
        )

    clean = str(path)

    if clean in {"", "."}:
        raise IacEvaluationError(
            f"Invalid path after normalization: {value}"
        )

    return clean


def normalize_severity(value: Any) -> str:
    severity = str(value or "UNKNOWN").upper().strip()

    if severity not in ALLOWED_SEVERITIES:
        raise IacEvaluationError(
            f"Unsupported Trivy severity: {severity}"
        )

    return severity


def extract_iac_exceptions(
    exception_document: dict[str, Any],
) -> list[dict[str, Any]]:
    entries = exception_document.get("exceptions", [])

    if not isinstance(entries, list):
        raise IacEvaluationError(
            "The exceptions field must be an array."
        )

    normalized: list[dict[str, Any]] = []

    for entry in entries:
        if not isinstance(entry, dict):
            raise IacEvaluationError(
                "Each exception must be an object."
            )

        if entry.get("category") != "iac":
            continue

        finding_id = entry.get("id")
        scope = entry.get("scope")
        reference = entry.get("reference", {})

        if not isinstance(finding_id, str) or not finding_id:
            raise IacEvaluationError(
                "IaC exception is missing a valid finding ID."
            )

        if not isinstance(scope, dict):
            raise IacEvaluationError(
                f"{finding_id}: IaC exception scope is invalid."
            )

        raw_path = scope.get("path")

        if not isinstance(raw_path, str) or not raw_path:
            raise IacEvaluationError(
                f"{finding_id}: IaC exception requires scope.path."
            )

        security_review = reference.get("security_review")

        if (
            not isinstance(security_review, str)
            or not security_review
        ):
            raise IacEvaluationError(
                f"{finding_id}: security review reference is missing."
            )

        normalized.append(
            {
                "id": finding_id,
                "path": normalize_path(raw_path),
                "security_review": security_review,
            }
        )

    return normalized


def extract_misconfigurations(
    trivy_document: dict[str, Any],
) -> list[dict[str, Any]]:
    results = trivy_document.get("Results", [])

    if results is None:
        results = []

    if not isinstance(results, list):
        raise IacEvaluationError(
            "Trivy Results must be an array."
        )

    findings: list[dict[str, Any]] = []

    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise IacEvaluationError(
                f"Trivy result {result_index} is not an object."
            )

        target = result.get("Target")

        misconfigurations = result.get(
            "Misconfigurations",
            [],
        )

        if misconfigurations is None:
            misconfigurations = []

        if not isinstance(misconfigurations, list):
            raise IacEvaluationError(
                f"Misconfigurations for result {result_index} "
                "must be an array."
            )

        if misconfigurations and (
            not isinstance(target, str) or not target.strip()
        ):
            raise IacEvaluationError(
                "Trivy returned IaC findings without a Target path. "
                "The approved exception scope cannot be preserved."
            )

        normalized_target = (
            normalize_path(target)
            if misconfigurations
            else None
        )

        for finding_index, finding in enumerate(
            misconfigurations
        ):
            if not isinstance(finding, dict):
                raise IacEvaluationError(
                    f"Finding {result_index}/{finding_index} "
                    "is not an object."
                )

            finding_id = (
                finding.get("ID")
                or finding.get("AVDID")
            )

            if (
                not isinstance(finding_id, str)
                or not finding_id.strip()
            ):
                raise IacEvaluationError(
                    "Trivy returned an IaC finding without an ID. "
                    "Failing closed."
                )

            severity = normalize_severity(
                finding.get("Severity")
            )

            cause_metadata = finding.get(
                "CauseMetadata",
                {},
            )

            if cause_metadata is None:
                cause_metadata = {}

            if not isinstance(cause_metadata, dict):
                raise IacEvaluationError(
                    f"{finding_id}: CauseMetadata must be an object."
                )

            findings.append(
                {
                    "id": finding_id.strip(),
                    "severity": severity,
                    "path": normalized_target,
                    "title": finding.get("Title", ""),
                    "description": finding.get(
                        "Description",
                        "",
                    ),
                    "message": finding.get("Message", ""),
                    "resolution": finding.get(
                        "Resolution",
                        "",
                    ),
                    "query": finding.get("Query", ""),
                    "namespace": finding.get(
                        "Namespace",
                        "",
                    ),
                    "primary_url": finding.get(
                        "PrimaryURL",
                        "",
                    ),
                    "start_line": cause_metadata.get(
                        "StartLine"
                    ),
                    "end_line": cause_metadata.get(
                        "EndLine"
                    ),
                }
            )

    return findings


def build_exception_index(
    exceptions: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for exception in exceptions:
        key = (
            exception["id"],
            exception["path"],
        )

        if key in index:
            raise IacEvaluationError(
                "Duplicate governed IaC exception for "
                f"{exception['id']} at {exception['path']}."
            )

        index[key] = exception

    return index


def evaluate_findings(
    findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
    tier: str,
) -> dict[str, Any]:
    exception_index = build_exception_index(
        exceptions
    )

    matched_exceptions: set[
        tuple[str, str]
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
        key = (
            finding["id"],
            finding["path"],
        )

        effective = dict(finding)

        exception = exception_index.get(key)

        if exception:
            matched_exceptions.add(key)
            exempted_count += 1

            effective["status"] = "EXEMPTED"
            effective["exception_reference"] = (
                exception["security_review"]
            )

        else:
            effective["status"] = "ACTIVE"
            active_counts[
                finding["severity"]
            ] += 1

        evaluated_findings.append(effective)

    stale_exceptions: list[
        dict[str, Any]
    ] = []

    for key, exception in exception_index.items():
        if key in matched_exceptions:
            continue

        stale_exceptions.append(
            {
                "id": exception["id"],
                "path": exception["path"],
                "status": "STALE_EXCEPTION",
                "exception_reference": (
                    exception["security_review"]
                ),
            }
        )

    blocking = BLOCKING_SEVERITIES[tier]

    blocking_findings = [
        finding
        for finding in evaluated_findings
        if (
            finding["status"] == "ACTIVE"
            and finding["severity"] in blocking
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
        "category": "iac",
        "tier": tier,
        "summary": {
            "active": {
                "critical": active_counts["CRITICAL"],
                "high": active_counts["HIGH"],
                "medium": active_counts["MEDIUM"],
                "low": active_counts["LOW"],
                "unknown": active_counts["UNKNOWN"],
            },
            "exempted": exempted_count,
            "stale_exceptions": len(
                stale_exceptions
            ),
            "blocking_findings": len(
                blocking_findings
            ),
        },
        "gate": gate,
        "findings": evaluated_findings,
        "stale_exceptions": stale_exceptions,
    }


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


def print_summary(
    evaluation: dict[str, Any],
) -> None:
    summary = evaluation["summary"]
    active = summary["active"]

    print("IaC Security Evaluation")
    print("=" * 48)
    print(f"Tier................: {evaluation['tier']}")
    print(f"Critical Active.....: {active['critical']}")
    print(f"High Active.........: {active['high']}")
    print(f"Medium Active.......: {active['medium']}")
    print(f"Low Active..........: {active['low']}")
    print(f"Unknown Active......: {active['unknown']}")
    print(f"Exempted............: {summary['exempted']}")
    print(
        "Stale Exceptions....: "
        f"{summary['stale_exceptions']}"
    )
    print(
        "Blocking Findings...: "
        f"{summary['blocking_findings']}"
    )
    print("=" * 48)
    print(f"Security Gate.......: {evaluation['gate']}")

    for stale in evaluation["stale_exceptions"]:
        print(
            "::warning::Stale Trivy exception detected: "
            f"{stale['id']} path={stale['path']} "
            f"reference={stale['exception_reference']}. "
            "No matching active finding exists. "
            "Remove the exception from "
            ".security/trivy-ignore.yaml."
        )


def main() -> int:
    arguments = parse_arguments()

    try:
        validate_tier(arguments.tier)

        trivy_document = load_json(
            arguments.results
        )

        exception_document = load_yaml(
            arguments.exceptions
        )

        exceptions = extract_iac_exceptions(
            exception_document
        )

        findings = extract_misconfigurations(
            trivy_document
        )

        evaluation = evaluate_findings(
            findings=findings,
            exceptions=exceptions,
            tier=arguments.tier,
        )

        write_output(
            arguments.output,
            evaluation,
        )

        print_summary(evaluation)

        if evaluation["gate"] == "FAIL":
            print(
                "::error::IaC Security Gate failed "
                "because active blocking findings exist."
            )

            return 1

        return 0

    except IacEvaluationError as error:
        print(
            "::error::IaC security evaluation failed."
        )

        print(
            f"::error::{error}"
        )

        return 2


if __name__ == "__main__":
    sys.exit(main())