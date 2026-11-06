from pathlib import Path
import importlib.util

import pytest


SCRIPT_PATH = (
    Path(__file__).parents[1]
    / "evaluate-trivy-container.py"
)

SPEC = importlib.util.spec_from_file_location(
    "evaluate_trivy_container",
    SCRIPT_PATH,
)

MODULE = importlib.util.module_from_spec(SPEC)

assert SPEC.loader is not None

SPEC.loader.exec_module(MODULE)


# ============================================================
# TEST FIXTURES
# ============================================================

def trivy_result(
    vulnerability_id: str = "CVE-2026-12345",
    package: str = "openssl",
    package_type: str = "test-os",
    severity: str = "HIGH",
    installed_version: str = "3.0.11",
    fixed_version: str = "3.0.14",
) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": (
            "ghcr.io/poc-governanca/"
            "fastqa-api:sha-a1b2c3d"
        ),
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "test-os",
                "Class": "os-pkgs",
                "Type": package_type,
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": (
                            vulnerability_id
                        ),
                        "PkgName": package,
                        "InstalledVersion": (
                            installed_version
                        ),
                        "FixedVersion": (
                            fixed_version
                        ),
                        "Severity": severity,
                        "Title": (
                            "Example container "
                            "vulnerability"
                        ),
                        "Description": (
                            "Example vulnerability "
                            "used by unit tests."
                        ),
                        "PrimaryURL": (
                            "https://example.invalid/"
                            "CVE-2026-12345"
                        ),
                    }
                ],
            }
        ],
    }


def governed_exception(
    vulnerability_id: str = "CVE-2026-12345",
    image: str = "fastqa-api",
    package: str = "openssl",
    package_type: str = "test-os",
) -> dict:
    return {
        "id": vulnerability_id,
        "image": MODULE.normalize_image_name(
            image
        ),
        "package": MODULE.normalize_package(
            package
        ),
        "package_type": (
            MODULE.normalize_package_type(
                package_type
            )
        ),
        "security_review": (
            "SEC-REVIEW-TEST-001"
        ),
    }


def extract_findings(
    document: dict,
    image_ref: str = (
        "ghcr.io/poc-governanca/"
        "fastqa-api:sha-a1b2c3d"
    ),
) -> list[dict]:
    logical_image = (
        MODULE.normalize_image_name(
            image_ref
        )
    )

    return MODULE.extract_vulnerabilities(
        document,
        logical_image,
    )


# ============================================================
# IMAGE NORMALIZATION
# ============================================================

@pytest.mark.parametrize(
    ("image_ref", "expected"),
    [
        (
            "fastqa-api:latest",
            "fastqa-api",
        ),
        (
            "fastqa-api:v1.5.0",
            "fastqa-api",
        ),
        (
            (
                "ghcr.io/poc-governanca/"
                "fastqa-api:v1.5.0"
            ),
            "fastqa-api",
        ),
        (
            (
                "ghcr.io/poc-governanca/"
                "fastqa-api@sha256:abcdef"
            ),
            "fastqa-api",
        ),
        (
            (
                "registry.example.com/team/"
                "fastqa-api:sha-a1b2c3d"
            ),
            "fastqa-api",
        ),
    ],
)
def test_image_normalization(
    image_ref: str,
    expected: str,
) -> None:
    assert (
        MODULE.normalize_image_name(
            image_ref
        )
        == expected
    )


@pytest.mark.parametrize(
    "image_ref",
    [
        "",
        " ",
        "*",
        "fastqa-*",
        "fastqa-?",
    ],
)
def test_invalid_image_reference_fails(
    image_ref: str,
) -> None:
    with pytest.raises(
        MODULE.ContainerEvaluationError
    ):
        MODULE.normalize_image_name(
            image_ref
        )


def test_images_with_different_names_are_not_equal() -> None:
    assert (
        MODULE.normalize_image_name(
            "fastqa-api:v1"
        )
        != MODULE.normalize_image_name(
            "fastqa-worker:v1"
        )
    )


# ============================================================
# PACKAGE NORMALIZATION
# ============================================================

def test_package_name_is_trimmed() -> None:
    assert (
        MODULE.normalize_package(
            "  openssl  "
        )
        == "openssl"
    )


@pytest.mark.parametrize(
    "package",
    [
        "",
        " ",
        "*",
        "open*",
        "open?",
    ],
)
def test_invalid_package_name_fails(
    package: str,
) -> None:
    with pytest.raises(
        MODULE.ContainerEvaluationError
    ):
        MODULE.normalize_package(
            package
        )


def test_package_type_is_trimmed() -> None:
    assert (
        MODULE.normalize_package_type(
            "  test-os  "
        )
        == "test-os"
    )


@pytest.mark.parametrize(
    "package_type",
    [
        "*",
        "test-*",
        "test-?",
    ],
)
def test_wildcard_package_type_fails(
    package_type: str,
) -> None:
    with pytest.raises(
        MODULE.ContainerEvaluationError
    ):
        MODULE.normalize_package_type(
            package_type
        )


# ============================================================
# PACKAGE TYPE POLICY
# ============================================================

def test_allowed_package_types_are_loaded() -> None:
    policy = {
        "version": 1,
        "allowed_package_types": [
            "test-os",
            "test-application",
        ],
    }

    result = (
        MODULE.load_allowed_package_types(
            policy
        )
    )

    assert result == {
        "test-os",
        "test-application",
    }


def test_empty_package_type_policy_is_valid() -> None:
    policy = {
        "version": 1,
        "allowed_package_types": [],
    }

    result = (
        MODULE.load_allowed_package_types(
            policy
        )
    )

    assert result == set()


def test_invalid_policy_version_fails() -> None:
    policy = {
        "version": 2,
        "allowed_package_types": [],
    }

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "Unsupported package types "
            "policy version"
        ),
    ):
        MODULE.load_allowed_package_types(
            policy
        )


def test_package_type_policy_must_be_array() -> None:
    policy = {
        "version": 1,
        "allowed_package_types": (
            "test-os"
        ),
    }

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "allowed_package_types "
            "must be an array"
        ),
    ):
        MODULE.load_allowed_package_types(
            policy
        )


# ============================================================
# FINDING EXTRACTION
# ============================================================

def test_extracts_container_vulnerability() -> None:
    findings = extract_findings(
        trivy_result()
    )

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding["id"]
        == "CVE-2026-12345"
    )

    assert (
        finding["image"]
        == "fastqa-api"
    )

    assert (
        finding["package"]
        == "openssl"
    )

    assert (
        finding["package_type"]
        == "test-os"
    )

    assert (
        finding["severity"]
        == "HIGH"
    )

    assert (
        finding["installed_version"]
        == "3.0.11"
    )

    assert (
        finding["fixed_version"]
        == "3.0.14"
    )


def test_missing_vulnerability_id_fails_closed() -> None:
    document = trivy_result()

    document["Results"][0][
        "Vulnerabilities"
    ][0].pop(
        "VulnerabilityID"
    )

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "without VulnerabilityID"
        ),
    ):
        extract_findings(document)


def test_missing_package_name_fails_closed() -> None:
    document = trivy_result()

    document["Results"][0][
        "Vulnerabilities"
    ][0].pop(
        "PkgName"
    )

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "without PkgName"
        ),
    ):
        extract_findings(document)


def test_invalid_results_structure_fails() -> None:
    document = {
        "Results": "invalid",
    }

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "Trivy Results must be an array"
        ),
    ):
        extract_findings(document)


def test_empty_results_are_allowed() -> None:
    findings = extract_findings(
        {
            "Results": [],
        }
    )

    assert findings == []


# ============================================================
# EXACT MATCHING
# ============================================================

def test_exact_scope_is_exempted() -> None:
    findings = extract_findings(
        trivy_result()
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os"
        },
        tier="1",
    )

    assert result["gate"] == "PASS"

    assert (
        result["summary"]["exempted"]
        == 1
    )

    assert (
        result["summary"][
            "blocking_findings"
        ]
        == 0
    )

    finding = result["findings"][0]

    assert (
        finding["status"]
        == "EXEMPTED"
    )

    assert (
        finding[
            "exception_reference"
        ]
        == "SEC-REVIEW-TEST-001"
    )


def test_different_cve_remains_active() -> None:
    findings = extract_findings(
        trivy_result(
            vulnerability_id=(
                "CVE-2026-99999"
            )
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os"
        },
        tier="1",
    )

    assert result["gate"] == "FAIL"

    assert (
        result["findings"][0][
            "status"
        ]
        == "ACTIVE"
    )


def test_different_image_remains_active() -> None:
    findings = extract_findings(
        trivy_result(),
        image_ref=(
            "ghcr.io/poc-governanca/"
            "fastqa-worker:v1"
        ),
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os"
        },
        tier="1",
    )

    assert (
        result["findings"][0][
            "status"
        ]
        == "ACTIVE"
    )


def test_different_package_remains_active() -> None:
    findings = extract_findings(
        trivy_result(
            package="libssl3"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os"
        },
        tier="1",
    )

    assert (
        result["findings"][0][
            "status"
        ]
        == "ACTIVE"
    )


def test_different_package_type_remains_active() -> None:
    findings = extract_findings(
        trivy_result(
            package_type="other-os"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os",
            "other-os",
        },
        tier="1",
    )

    assert (
        result["findings"][0][
            "status"
        ]
        == "ACTIVE"
    )


# ============================================================
# PACKAGE TYPE FAIL-CLOSED
# ============================================================

def test_matching_exception_with_unapproved_type_fails() -> None:
    findings = extract_findings(
        trivy_result()
    )

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "unapproved package_type"
        ),
    ):
        MODULE.evaluate_findings(
            findings=findings,
            exceptions=[
                governed_exception()
            ],
            allowed_package_types=set(),
            tier="1",
        )


def test_unapproved_type_without_exception_remains_active() -> None:
    findings = extract_findings(
        trivy_result()
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        allowed_package_types=set(),
        tier="1",
    )

    assert (
        result["findings"][0][
            "status"
        ]
        == "ACTIVE"
    )

    assert result["gate"] == "FAIL"


# ============================================================
# TIER ENFORCEMENT
# ============================================================

@pytest.mark.parametrize(
    "tier",
    [
        "1",
        "2",
    ],
)
def test_high_blocks_tier_1_and_2(
    tier: str,
) -> None:
    findings = extract_findings(
        trivy_result(
            severity="HIGH"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        allowed_package_types=set(),
        tier=tier,
    )

    assert result["gate"] == "FAIL"

    assert (
        result["summary"][
            "blocking_findings"
        ]
        == 1
    )


def test_high_does_not_block_tier_3() -> None:
    findings = extract_findings(
        trivy_result(
            severity="HIGH"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        allowed_package_types=set(),
        tier="3",
    )

    assert result["gate"] == "PASS"

    assert (
        result["summary"]["active"][
            "high"
        ]
        == 1
    )


def test_critical_blocks_tier_3() -> None:
    findings = extract_findings(
        trivy_result(
            severity="CRITICAL"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        allowed_package_types=set(),
        tier="3",
    )

    assert result["gate"] == "FAIL"


def test_medium_does_not_block_tier_1() -> None:
    findings = extract_findings(
        trivy_result(
            severity="MEDIUM"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        allowed_package_types=set(),
        tier="1",
    )

    assert result["gate"] == "PASS"

    assert (
        result["summary"]["active"][
            "medium"
        ]
        == 1
    )


# ============================================================
# STALE EXCEPTIONS
# ============================================================

def test_stale_exception_is_reported() -> None:
    result = MODULE.evaluate_findings(
        findings=[],
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os"
        },
        tier="1",
    )

    assert result["gate"] == "PASS"

    assert (
        result["summary"][
            "stale_exceptions"
        ]
        == 1
    )

    stale = (
        result[
            "stale_exceptions"
        ][0]
    )

    assert (
        stale["status"]
        == "STALE_EXCEPTION"
    )

    assert (
        stale["id"]
        == "CVE-2026-12345"
    )


# ============================================================
# DUPLICATE EXCEPTIONS
# ============================================================

def test_duplicate_exception_fails() -> None:
    exception = (
        governed_exception()
    )

    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match=(
            "Duplicate governed "
            "container exception"
        ),
    ):
        MODULE.evaluate_findings(
            findings=[],
            exceptions=[
                exception,
                exception.copy(),
            ],
            allowed_package_types={
                "test-os"
            },
            tier="1",
        )


# ============================================================
# EVIDENCE RETENTION
# ============================================================

def test_exempted_finding_remains_in_output() -> None:
    findings = extract_findings(
        trivy_result()
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[
            governed_exception()
        ],
        allowed_package_types={
            "test-os"
        },
        tier="1",
    )

    assert (
        len(result["findings"])
        == 1
    )

    finding = (
        result["findings"][0]
    )

    assert (
        finding["id"]
        == "CVE-2026-12345"
    )

    assert (
        finding["status"]
        == "EXEMPTED"
    )

    assert (
        finding[
            "installed_version"
        ]
        == "3.0.11"
    )

    assert (
        finding["fixed_version"]
        == "3.0.14"
    )


# ============================================================
# INVALID TIER
# ============================================================

@pytest.mark.parametrize(
    "tier",
    [
        "",
        "0",
        "4",
        "critical",
    ],
)
def test_invalid_tier_fails(
    tier: str,
) -> None:
    with pytest.raises(
        MODULE.ContainerEvaluationError,
        match="Invalid Tier",
    ):
        MODULE.evaluate_findings(
            findings=[],
            exceptions=[],
            allowed_package_types=set(),
            tier=tier,
        )