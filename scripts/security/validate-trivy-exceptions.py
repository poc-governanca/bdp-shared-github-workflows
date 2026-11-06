#!/usr/bin/env python3
"""Validate a JSON file containing documented, time-bound Trivy exceptions."""

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any


IDENTIFIER_PATTERN = re.compile(r"^(CVE-[0-9]{4}-[0-9]{4,}|[A-Z][A-Z0-9_-]+)$")


def validate(document: Any, today: date) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["root: expected a JSON object"]

    extra_keys = set(document) - {"version", "exceptions"}
    if extra_keys:
        errors.append(f"root: unexpected properties: {', '.join(sorted(extra_keys))}")
    if document.get("version") != 1 or isinstance(document.get("version"), bool):
        errors.append("version: expected integer 1")

    exceptions = document.get("exceptions")
    if not isinstance(exceptions, list):
        errors.append("exceptions: expected an array")
        return errors

    seen_ids: set[str] = set()
    for index, exception in enumerate(exceptions):
        location = f"exceptions[{index}]"
        if not isinstance(exception, dict):
            errors.append(f"{location}: expected an object")
            continue

        extra_keys = set(exception) - {"id", "reason", "expires", "paths"}
        if extra_keys:
            errors.append(f"{location}: unexpected properties: {', '.join(sorted(extra_keys))}")

        identifier = exception.get("id")
        if not isinstance(identifier, str) or not IDENTIFIER_PATTERN.fullmatch(identifier):
            errors.append(f"{location}.id: expected a CVE or uppercase Trivy identifier")
        elif identifier in seen_ids:
            errors.append(f"{location}.id: duplicate identifier {identifier}")
        else:
            seen_ids.add(identifier)

        reason = exception.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            errors.append(f"{location}.reason: provide at least 10 non-whitespace characters")

        expiration = exception.get("expires")
        try:
            expiration_date = date.fromisoformat(expiration) if isinstance(expiration, str) else None
        except ValueError:
            expiration_date = None
        if expiration_date is None or expiration_date.isoformat() != expiration:
            errors.append(f"{location}.expires: expected a date in YYYY-MM-DD format")
        elif expiration_date < today:
            errors.append(f"{location}.expires: exception expired on {expiration}")

        paths = exception.get("paths")
        if paths is not None:
            if not isinstance(paths, list) or any(not isinstance(path, str) or not path.strip() for path in paths):
                errors.append(f"{location}.paths: expected an array of non-empty strings")
            elif len(paths) != len(set(paths)):
                errors.append(f"{location}.paths: duplicate paths are not allowed")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Path to the Trivy exceptions JSON file")
    args = parser.parse_args()
    path = Path(args.file)

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"ERROR: cannot read {path}: {error}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"ERROR: invalid JSON in {path}: {error}", file=sys.stderr)
        return 2

    errors = validate(document, date.today())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Validated {len(document['exceptions'])} Trivy exception(s) in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())