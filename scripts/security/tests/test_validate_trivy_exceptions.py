import importlib.util
import unittest
from datetime import date
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "validate-trivy-exceptions.py"
SPEC = importlib.util.spec_from_file_location("validate_trivy_exceptions", SCRIPT_PATH)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ValidateTrivyExceptionsTests(unittest.TestCase):
    def setUp(self):
        self.today = date(2026, 11, 5)
        self.document = {
            "version": 1,
            "exceptions": [
                {
                    "id": "CVE-2026-1234",
                    "reason": "Fix is scheduled for the next release.",
                    "expires": "2026-12-01",
                    "paths": ["app/package-lock.json"],
                }
            ],
        }

    def test_accepts_valid_exception(self):
        self.assertEqual(VALIDATOR.validate(self.document, self.today), [])

    def test_rejects_expired_exception(self):
        self.document["exceptions"][0]["expires"] = "2026-11-04"
        errors = VALIDATOR.validate(self.document, self.today)
        self.assertTrue(any("exception expired" in error for error in errors))

    def test_rejects_duplicate_identifier(self):
        self.document["exceptions"].append(self.document["exceptions"][0].copy())
        errors = VALIDATOR.validate(self.document, self.today)
        self.assertTrue(any("duplicate identifier" in error for error in errors))

    def test_rejects_invalid_identifier_and_date(self):
        self.document["exceptions"][0]["id"] = "cve-2026-1234"
        self.document["exceptions"][0]["expires"] = "not-a-date"
        errors = VALIDATOR.validate(self.document, self.today)
        self.assertTrue(any(".id:" in error for error in errors))
        self.assertTrue(any(".expires:" in error for error in errors))


if __name__ == "__main__":
    unittest.main()