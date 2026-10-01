"""Repository contracts; this checker never imports or executes scanner code."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
STATUSES = ("Completed", "Partial", "Skipped", "Unsupported", "Error")
NATIVE_MUTATORS = re.compile(
    r"\b(?:WriteProcessMemory|VirtualProtect(?:Ex)?|CreateRemoteThread|AdjustTokenPrivileges|"
    r"ChangeServiceConfig\w*|StartService\w*|ControlService|RegSetValue\w*|SetSecurityInfo)\s*\("
)


def load_json(path: Path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON property: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_pairs)


def readonly_failures(root: Path = ROOT) -> list[str]:
    failures = []
    for path in sorted((root / "src").rglob("*.cs")):
        # Strip comments before checking actual declarations/calls. This is a guard,
        # not a substitute for CodeQL or a complete semantic proof of immutability.
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(encoding="utf-8-sig"), flags=re.S)
        for match in NATIVE_MUTATORS.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            failures.append(f"{path.relative_to(root)}:{line}: forbidden mutation API {match.group(0).strip()}")
    return failures


def validate_report(report: dict, expected_ids=None, require_success=False):
    schema = load_json(ROOT / ".github/ci/schemas/report-1.5.schema.json")
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(report)
    started = dt.datetime.fromisoformat(report["StartedUtc"].replace("Z", "+00:00"))
    finished = dt.datetime.fromisoformat(report["FinishedUtc"].replace("Z", "+00:00"))
    if finished < started:
        raise ValueError("Report finishes before it starts")
    ids = [check["Id"] for check in report["Checks"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate check IDs in report")
    if expected_ids is not None and set(ids) != set(expected_ids):
        raise ValueError("Report does not contain exactly the selected IDs")
    for status in STATUSES:
        if report["Summary"][status] != sum(check["Status"] == status for check in report["Checks"]):
            raise ValueError(f"Incorrect {status} summary")
    skipped = {check["Id"] for check in report["Checks"] if check["Status"] == "Skipped"}
    summary_ids = [entry["CheckId"] for entry in report["SkippedChecks"]]
    if len(summary_ids) != len(set(summary_ids)) or skipped != set(summary_ids):
        raise ValueError("Skipped-check summary does not match checks")
    by_id = {check["Id"]: check for check in report["Checks"]}
    for path in report["AttackPathAnalysis"]["Paths"]:
        for ref in path["EvidenceReferences"]:
            check = by_id.get(ref["CheckId"])
            index = ref["FindingIndex"]
            if not check or not isinstance(index, int) or index < 0 or index >= len(check["Findings"]):
                raise ValueError("Dangling evidence reference")
    if require_success and (report["RunStatus"] != "Completed" or report["Summary"]["Error"] or report["AttackPathAnalysis"]["Status"] == "Error"):
        raise ValueError("Scan completed with runner, collector, or analysis errors")


def documentation_failures(root: Path = ROOT) -> list[str]:
    failures = []
    for path in [root / "README.md", root / "ROADMAP.md", *sorted((root / "docs").glob("*.md"))]:
        text = path.read_text(encoding="utf-8-sig")
        for link in re.findall(r"\]\(([^)]+)\)", text):
            if re.match(r"(?:https?://|mailto:|#)", link):
                continue
            target = link.split("#", 1)[0].replace("\\", "/")
            if target and not (path.parent / target).is_file():
                failures.append(f"{path.relative_to(root)}: missing local link {target}")
        # Also check command examples, which are not Markdown links. Match both
        # separators without mistaking upstream URL paths for checkout files.
        for match in re.finditer(r"(?:\.\\|\./)?(?:tools|tests|\.github[/\\](?:ci|workflows))[/\\][A-Za-z0-9_.\-/\\]+\.(?:ps1|yml|yaml|py)", text):
            target = match.group(0).replace("\\", "/").removeprefix("./")
            if not (root / target).is_file():
                failures.append(f"{path.relative_to(root)}: missing example file {target}")
    return failures


def repository_failures(root: Path = ROOT) -> list[str]:
    failures = documentation_failures(root)
    catalog = load_json(root / "data/checks.json")
    ids = [entry["Id"] for entry in catalog]
    if len(ids) != 148 or set(ids) != set(range(1, 149)):
        failures.append("Catalog must contain exactly IDs 1 through 148")
    for entry in catalog:
        if entry["Scope"] not in ("Local", "Sensitive", "Network", "Domain") or entry["Coverage"] not in ("Implemented", "Partial", "Unsupported") or not entry["Title"] or not entry["Category"]:
            failures.append(f"Invalid catalog record {entry['Id']}")
        if entry["Coverage"] != "Implemented" and not entry.get("Limitation"):
            failures.append(f"Undisclosed coverage limit {entry['Id']}")
    coverage_ids = [int(value) for value in re.findall(r"^\| (\d+) \|", (root / "docs/COVERAGE.md").read_text(encoding="utf-8-sig"), re.M)]
    if coverage_ids != ids:
        failures.append("Coverage documentation does not match catalog IDs/order")
    for path in sorted((root / "data/reference").glob("*.json")):
        document = load_json(path)
        if path.name == "kb-builds.json":
            if not document or any(not re.fullmatch(r"\d+", key) or not isinstance(values, list) or any(not re.fullmatch(r"\d+\.\d+", value) for value in values) for key, values in document.items()):
                failures.append("Invalid KB/build cache")
            continue
        if document.get("SchemaVersion") != 1 or not isinstance(document.get("Entries"), list) or not document["Entries"]:
            failures.append(f"Invalid or empty reference snapshot {path.name}")
        if document.get("RetrievedUtc"):
            dt.datetime.fromisoformat(document["RetrievedUtc"].replace("Z", "+00:00"))
        for entry in document.get("Entries", []):
            if path.name == "drivers.json" and not re.fullmatch(r"[a-fA-F0-9]{64}", entry.get("SHA256", "")):
                failures.append("Invalid driver hash")
            if path.name == "windows-updates.json" and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", entry.get("FixedBuild", "")):
                failures.append("Invalid fixed Windows build")
    for path in sorted((root / ".github/workflows").glob("*.yml")):
        # BaseLoader preserves the 'on' key instead of YAML 1.1's Boolean mapping.
        workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        if not workflow.get("on") or not workflow.get("jobs"):
            failures.append(f"Empty workflow {path.name}")
        for match in re.finditer(r"uses:\s*([^\s#]+)", path.read_text(encoding="utf-8")):
            action = match.group(1)
            if not action.startswith("./") and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action):
                failures.append(f"Unpinned action {action}")
    return failures


def check_results(directory: Path, expected_cells: list[str]):
    found = {}
    paths = {}
    for path in sorted(directory.rglob("validation.json")):
        row = load_json(path)
        cell = row["Cell"]
        if cell in found:
            raise ValueError(f"Duplicate matrix result {cell}")
        found[cell] = row
        paths[cell] = path
    if set(found) != set(expected_cells):
        raise ValueError(f"Missing/unexpected matrix cells: expected {sorted(expected_cells)}, got {sorted(found)}")
    for cell, row in found.items():
        path = paths[cell]
        if row["Result"] != "Passed" or row["Total"] < row.get("MinimumExpectedTests", 1) or row["Passed"] != row["Total"] or row["Failed"] or row["Skipped"] or row["NotRun"]:
            raise ValueError(f"Incomplete or failing matrix cell {cell}")
        junit = path.parent / "tests.xml"
        if not junit.is_file():
            raise ValueError(f"Missing individual test results for {cell}")
        tree = ET.parse(junit)
        cases = tree.findall(".//testcase")
        if len(cases) != row["Total"] or any(case.find("failure") is not None or case.find("skipped") is not None for case in cases):
            raise ValueError(f"Test-result evidence does not agree for {cell}")
        coverage_path = path.parent / "coverage.xml"
        if not coverage_path.is_file():
            raise ValueError(f"Missing coverage evidence for {cell}")
        counter = ET.parse(coverage_path).getroot().find("./counter[@type='INSTRUCTION']")
        if counter is None:
            raise ValueError(f"Coverage artifact lacks command counters for {cell}")
        covered, missed = int(counter.attrib["covered"]), int(counter.attrib["missed"])
        if covered < 0 or missed < 0 or covered + missed == 0:
            raise ValueError(f"Invalid coverage counters for {cell}")
        percentage = 100 * covered / (covered + missed)
        if percentage < row.get("CoverageTarget", 80) or abs(percentage - row["CoveragePercent"]) > 0.01:
            raise ValueError(f"Coverage evidence does not agree with the summary for {cell}")
        map_path = path.parent / "check-coverage.json"
        if row.get("MinimumExpectedTests", 0) >= 250:
            coverage_map = load_json(map_path)
            map_ids = [entry["Id"] for entry in coverage_map]
            if len(map_ids) != 148 or set(map_ids) != set(range(1, 149)):
                raise ValueError(f"Missing or duplicate per-check coverage accounting for {cell}")


def freshness(root: Path = ROOT):
    now = dt.datetime.now(dt.timezone.utc)
    stale = []
    for path in sorted((root / "data/reference").glob("*.json")):
        doc = load_json(path)
        if "RetrievedUtc" not in doc:
            continue
        dates = {"snapshot": doc["RetrievedUtc"], **doc.get("MonthRetrievedUtc", {})}
        for period, value in dates.items():
            age = (now - dt.datetime.fromisoformat(value.replace("Z", "+00:00"))).days
            print(f"{path.name} / {period}: {age} days old")
            if age > 30 or age < 0:
                stale.append(f"{path.name}/{period}")
    if stale:
        raise ValueError("Reference freshness requires review: " + ", ".join(stale))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("repository", "readonly", "report", "results", "freshness"))
    parser.add_argument("--path", type=Path)
    parser.add_argument("--expected", nargs="+")
    args = parser.parse_args()
    if args.mode in ("repository", "readonly"):
        failures = repository_failures() if args.mode == "repository" else readonly_failures()
        if failures:
            raise ValueError("\n".join(failures))
    elif args.mode == "report":
        if not args.path or not args.expected:
            parser.error("report requires --path and --expected IDs")
        validate_report(load_json(args.path), [int(value) for value in args.expected], require_success=True)
    elif args.mode == "results":
        if not args.path or not args.expected:
            parser.error("results requires --path and --expected cells")
        check_results(args.path, args.expected)
    else:
        freshness()
    print(f"PASS: {args.mode}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, yaml.YAMLError, jsonschema.ValidationError, OSError, ET.ParseError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
