# Continuous integration contracts

CI infrastructure is source-checkout-only under `.github/ci/`. Runtime archives
retain source, catalog/reference data, documentation and distribution notices;
they omit CI dependencies and test scripts. The existing runtime files are not
replaced by this CI implementation.

## Required hosted checks

The [CI workflow](../.github/workflows/ci.yml) defines 12 hosted runtime cells:
Server 2022 and 2025, PowerShell 5.1 / 7.4.13 / 7.6.6, and x86 / x64 processes.
Actual versions and process bitness must match their matrix declarations.

Required stages are:

1. Repository contracts: catalog IDs/metadata, valid reference snapshots,
   documentation links and command paths using both separator styles, action pins,
   and regression tests for the checker itself.
2. `actionlint` workflow validation using a checksum-verified tool.
3. Four Pester suites per cell: source/manifest/dispatch and real CLI listing;
   offline diagnostics, gates, limits and redaction; reference applicability;
   synthetic report export and offline analysis. C# is compiled without invoking
   its APIs. No memory-patching or evasion behavior is exercised.
4. Required PSScriptAnalyzer correctness rules. The five discovery-data
   suppressions in Pester files are individually named and justified; they are
   not a whole-directory exemption. Third-party parser source is parsed but not
   restyled by first-party lint rules.
5. At least 250 discovered tests, no unexpected skips/inconclusive/not-run tests,
   and >= 80% command coverage in `ReferenceData.ps1` and `Verification.ps1`.
   This is scoped PowerShell command coverage, not branch/native/global coverage.
6. Versioned JSON-schema and semantic report checks, including exact selected
   IDs, totals, skip summaries, and valid evidence references.
7. Runtime ZIP validation from a fresh extraction: inventory, SHA256, notices,
   no CI-only directories, and catalog listing through the actual launcher.
8. Scan integration: read-only guard first, then selected IDs, status/error counts,
   opt-in gates and JSON/HTML/log artifacts. A completed runner with collector
   errors is a failure. Native mutation APIs block this stage before execution.
9. CodeQL C# and Python analysis. The [analysis project](../.github/ci/NativeAnalysis.csproj)
   compiles the exact shipped C# sources, including files normally compiled by
   `Add-Type`, without running native methods. Dependency review applies to PRs.
10. Final **CI** check: all applicable jobs must succeed and every expected
    matrix cell must provide matching individual-test and coverage evidence.

The guard against native mutation scans every native source, rather than only
`Native.cs`. It is a defensive contract check, not a complete semantic proof that
arbitrary code is immutable. Static analysis and review remain necessary.

## Evidence and incomplete coverage

Each hosted cell retains `tests.xml`, `coverage.xml`, `analysis.json`,
`validation.json`, `check-coverage.json`, logs, synthetic reports, package results,
and integration results for 14 days. Runtime versions, image identity, commit and
reproduction arguments are recorded. Missing/duplicate cells, zero or insufficient
test discovery, mismatched individual results, failures and missing coverage
artifacts prevent the final gate from passing.

`check-coverage.json` distinguishes dispatch/source-reference coverage for all
148 IDs from collector behavior, which remains `NotRun` in offline suites.
Integration smoke checks do not establish a positive/negative fixture for every
collector. Domain, sensitive stores, optional products, restricted tokens, all
Windows editions, and real API failure paths need additional representative lab
evidence. These gaps are not converted into passing tests.

The [dedicated workflow](../.github/workflows/platform-validation.yml) uses
main-ref/manual-only disposable VMs and validates actual OS and standard/elevated
account context. See [platform provisioning](PLATFORMS.md). A declared job is not
evidence of a completed run. Missing runners leave the associated platform
unvalidated. Public PRs must never be run on persistent privileged lab machines.

## Dependencies and execution boundaries

Action references are immutable commit SHAs. Pester, PSScriptAnalyzer and portable
runtimes have explicit [pins](../.github/ci/dependencies.psd1); portable archives
are checked against official SHA256 values before extraction. Python dependencies
are pinned in [requirements](../.github/ci/requirements.txt). Dependabot covers
Actions and Python; review PowerShell/module pins periodically against upstream
releases. Modules are saved to a job-local path, never installed machine-wide.

Jobs use read-only contents permissions by default; only CodeQL jobs receive the
security-event permissions needed to publish analysis. PR runs cancel superseded
PR runs, matrix cells continue independently, and suite/integration/job deadlines
prevent indefinite validation. The final gate rejects cancellation and missing
evidence. The [freshness workflow](../.github/workflows/reference-freshness.yml)
reports dated snapshots separately, keeping live upstream access out of fixture
tests and avoiding silent data updates.

## Merge enforcement

The [main ruleset configuration](../.github/ci/main-ruleset.json) requires a PR,
resolved review conversations, and the **CI** status check from GitHub Actions,
with the branch up to date. Reviewer approval is optional: no approving reviews,
designated reviewers, code-owner approval, last-push approval, or extra approval
for unattributed changes are required. Deletion and force-push are blocked. No
admin bypass is included. CodeQL errors and high/critical security alerts also
block merging.

Workflow changes do not reach GitHub until committed and pushed. Hosted validation
and actual runner evidence must be inspected before calling this implementation
fully validated. Read-only contract failures must be resolved rather than
suppressed or treated as an environmental skip.
