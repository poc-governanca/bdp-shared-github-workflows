from pathlib import Path
import importlib.util

import pytest


SCRIPT_PATH = (
    Path(__file__).parents[1]
    / "evaluate-trivy-iac.py"
)

SPEC = importlib.util.spec_from_file_location(
    "evaluate_trivy_iac",
    SCRIPT_PATH,
)

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def trivy_finding(
    finding_id="AVD-AWS-0086",
    severity="HIGH",
    target="infra/modules/storage/main.tf",
):
    return {
        "Results": [
            {
                "Target": target,
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": finding_id,
                        "Title": "Example finding",
                        "Description": "Example description",
                        "Message": "Example message",
                        "Resolution": "Example resolution",
                        "Severity": severity,
                        "PrimaryURL": (
                            "https://example.invalid/finding"
                        ),
                        "CauseMetadata": {
                            "StartLine": 1,
                            "EndLine": 5,
                        },
                    }
                ],
            }
        ]
    }


def exception(
    finding_id="AVD-AWS-0086",
    path="infra/modules/storage/main.tf",
):
    return {
        "id": finding_id,
        "path": MODULE.normalize_path(path),
        "security_review": "SEC-REVIEW-001234",
    }


def test_exact_id_and_path_is_exempted():
    findings = MODULE.extract_misconfigurations(
        trivy_finding()
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[exception()],
        tier="1",
    )

    assert result["gate"] == "PASS"
    assert result["summary"]["exempted"] == 1
    assert result["findings"][0]["status"] == "EXEMPTED"


def test_same_id_different_path_is_active():
    findings = MODULE.extract_misconfigurations(
        trivy_finding(
            target="infra/modules/database/main.tf"
        )
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[exception()],
        tier="1",
    )

    assert result["gate"] == "FAIL"
    assert result["summary"]["active"]["high"] == 1
    assert result["findings"][0]["status"] == "ACTIVE"


def test_high_blocks_tier_1():
    findings = MODULE.extract_misconfigurations(
        trivy_finding(severity="HIGH")
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        tier="1",
    )

    assert result["gate"] == "FAIL"


def test_high_blocks_tier_2():
    findings = MODULE.extract_misconfigurations(
        trivy_finding(severity="HIGH")
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        tier="2",
    )

    assert result["gate"] == "FAIL"


def test_high_does_not_block_tier_3():
    findings = MODULE.extract_misconfigurations(
        trivy_finding(severity="HIGH")
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        tier="3",
    )

    assert result["gate"] == "PASS"
    assert result["summary"]["active"]["high"] == 1


def test_critical_blocks_tier_3():
    findings = MODULE.extract_misconfigurations(
        trivy_finding(severity="CRITICAL")
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[],
        tier="3",
    )

    assert result["gate"] == "FAIL"


def test_path_normalization():
    assert MODULE.normalize_path(
        "./infra\\modules\\storage\\main.tf"
    ) == "infra/modules/storage/main.tf"


@pytest.mark.parametrize(
    "path",
    [
        "../infra/main.tf",
        "infra/**/main.tf",
        "infra/main?.tf",
        "/etc/passwd",
    ],
)
def test_unsafe_path_fails(path):
    with pytest.raises(
        MODULE.IacEvaluationError
    ):
        MODULE.normalize_path(path)


def test_missing_target_with_finding_fails_closed():
    document = trivy_finding()
    document["Results"][0].pop("Target")

    with pytest.raises(
        MODULE.IacEvaluationError,
        match="without a Target path",
    ):
        MODULE.extract_misconfigurations(document)


def test_missing_finding_id_fails_closed():
    document = trivy_finding()
    document["Results"][0][
        "Misconfigurations"
    ][0].pop("ID")

    with pytest.raises(
        MODULE.IacEvaluationError,
        match="without an ID",
    ):
        MODULE.extract_misconfigurations(document)


def test_stale_exception_is_reported():
    result = MODULE.evaluate_findings(
        findings=[],
        exceptions=[exception()],
        tier="1",
    )

    assert result["gate"] == "PASS"
    assert result["summary"]["stale_exceptions"] == 1
    assert (
        result["stale_exceptions"][0]["status"]
        == "STALE_EXCEPTION"
    )


def test_duplicate_exception_fails():
    duplicate = exception()

    with pytest.raises(
        MODULE.IacEvaluationError,
        match="Duplicate governed IaC exception",
    ):
        MODULE.evaluate_findings(
            findings=[],
            exceptions=[
                duplicate,
                duplicate.copy(),
            ],
            tier="1",
        )


def test_exempted_finding_remains_in_output():
    findings = MODULE.extract_misconfigurations(
        trivy_finding()
    )

    result = MODULE.evaluate_findings(
        findings=findings,
        exceptions=[exception()],
        tier="1",
    )

    assert len(result["findings"]) == 1
    assert result["findings"][0]["id"] == "AVD-AWS-0086"
    assert result["findings"][0]["status"] == "EXEMPTED"
    assert (
        result["findings"][0]["exception_reference"]
        == "SEC-REVIEW-001234"
    )