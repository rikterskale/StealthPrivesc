"""Negative tests for the CI checker itself: success must require evidence."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema
import repository_checks as checks


def report_fixture():
    return {
        "SchemaVersion": "1.5", "ToolVersion": "0.2.1", "RunStatus": "Completed",
        "StartedUtc": "2026-01-01T00:00:00Z", "FinishedUtc": "2026-01-01T00:00:01Z",
        "ProcessArchitecture": "x64", "OperatingSystemArchitecture": "x64", "PowerShellVersion": "7.6.6",
        "Scope": {"Network": False, "Domain": False, "Sensitive": False, "MaxItems": 10, "MaxFileBytes": 1024, "CommandTimeoutSeconds": 1},
        "Checks": [{"Id": 1, "Title": "Fixture", "Category": "Identity", "Coverage": "Implemented", "Status": "Completed", "DurationMs": 0, "Findings": [], "Limitations": [], "Diagnostics": [], "Verification": {"CollectorStarted": True, "RerunCommand": "fixture", "Commands": [], "SourceReferences": [], "OmittedCommandCount": 0}}],
        "Summary": {"Completed": 1, "Partial": 0, "Skipped": 0, "Unsupported": 0, "Error": 0},
        "SkippedChecks": [], "Diagnostics": [],
        "AttackPathAnalysis": {"EngineVersion": "1.1", "Status": "Partial", "Paths": [], "RuleCoverage": [], "Limitations": []},
    }


class ReportContracts(unittest.TestCase):
    def test_valid_narrow_report_is_not_required_to_have_complete_analysis(self):
        checks.validate_report(report_fixture(), [1], require_success=True)

    def test_zero_error_exit_is_not_a_successful_report(self):
        report = report_fixture()
        report["Checks"][0]["Status"] = "Error"
        report["Summary"].update(Completed=0, Error=1)
        with self.assertRaises(ValueError):
            checks.validate_report(report, [1], require_success=True)

    def test_failed_runner_and_analysis_are_rejected(self):
        for field in ("runner", "analysis"):
            report = report_fixture()
            if field == "runner":
                report["RunStatus"] = "Failed"
            else:
                report["AttackPathAnalysis"]["Status"] = "Error"
            with self.subTest(field=field), self.assertRaises(ValueError):
                checks.validate_report(report, [1], require_success=True)

    def test_missing_duplicate_and_unexpected_ids_are_rejected(self):
        report = report_fixture()
        with self.assertRaises(ValueError):
            checks.validate_report(report, [1, 2])
        report["Checks"].append(copy.deepcopy(report["Checks"][0]))
        with self.assertRaises(ValueError):
            checks.validate_report(report, [1])

    def test_incorrect_summary_is_rejected(self):
        report = report_fixture()
        report["Summary"]["Completed"] = 2
        with self.assertRaises(ValueError):
            checks.validate_report(report)

    def test_missing_fields_and_bad_timestamps_fail_schema_validation(self):
        for field in ("missing", "timestamp", "limit"):
            report = report_fixture()
            if field == "missing":
                del report["Checks"][0]["Verification"]
            elif field == "timestamp":
                report["StartedUtc"] = "not-a-date"
            else:
                report["Scope"]["MaxItems"] = 0
            with self.subTest(field=field), self.assertRaises(jsonschema.ValidationError):
                checks.validate_report(report)

    def test_skipped_summary_and_dangling_evidence_are_rejected(self):
        report = report_fixture()
        report["SkippedChecks"] = [{"CheckId": 1, "ReasonCode": "fixture", "Explanation": "fixture", "SuggestedActions": []}]
        with self.assertRaises(ValueError):
            checks.validate_report(report)
        report["SkippedChecks"] = []
        report["AttackPathAnalysis"]["Paths"] = [{"EvidenceReferences": [{"CheckId": 1, "FindingIndex": 0}]}]
        with self.assertRaises(ValueError):
            checks.validate_report(report)


class RepositoryContracts(unittest.TestCase):
    def test_duplicate_json_properties_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"Id":1,"Id":2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                checks.load_json(path)

    def test_native_mutation_is_detected_outside_the_primary_native_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            path = root / "src/AdditionalNative.cs"
            path.write_text("// WriteProcessMemory() in a comment\nclass Fixture {}", encoding="utf-8")
            self.assertEqual([], checks.readonly_failures(root))
            path.write_text("class Fixture { void WriteProcessMemory() {} }", encoding="utf-8")
            self.assertEqual(1, len(checks.readonly_failures(root)))

    def test_backslash_command_examples_and_local_links_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "ROADMAP.md").write_text("# Roadmap", encoding="utf-8")
            (root / "README.md").write_text("`pwsh .\\tools\\Missing.ps1`\n[broken](docs/missing.md)", encoding="utf-8")
            self.assertEqual(2, len(checks.documentation_failures(root)))


class MatrixContracts(unittest.TestCase):
    def test_missing_duplicate_zero_test_and_failure_results_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                checks.check_results(root, ["required"])
            row = {"Cell": "required", "Result": "Passed", "Total": 1, "Passed": 1, "Failed": 0, "Skipped": 0, "NotRun": 0, "CoveragePercent": 100, "CoverageTarget": 80}
            (root / "validation.json").write_text(json.dumps(row), encoding="utf-8")
            (root / "tests.xml").write_text('<testsuites><testsuite><testcase name="fixture"/></testsuite></testsuites>', encoding="utf-8")
            (root / "coverage.xml").write_text('<report><counter type="INSTRUCTION" missed="0" covered="1"/></report>', encoding="utf-8")
            checks.check_results(root, ["required"])
            for key, value in (("Total", 0), ("Skipped", 1), ("Result", "Failed"), ("NotRun", 1)):
                changed = {**row, key: value}
                (root / "validation.json").write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(key=key), self.assertRaises(ValueError):
                    checks.check_results(root, ["required"])
            (root / "validation.json").write_text(json.dumps(row), encoding="utf-8")
            (root / "coverage.xml").write_text('<report><counter type="INSTRUCTION" missed="1" covered="0"/></report>', encoding="utf-8")
            with self.assertRaises(ValueError):
                checks.check_results(root, ["required"])
            (root / "coverage.xml").write_text('<report><counter type="INSTRUCTION" missed="0" covered="1"/></report>', encoding="utf-8")
            (root / "duplicate").mkdir()
            (root / "duplicate/validation.json").write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaises(ValueError):
                checks.check_results(root, ["required"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
