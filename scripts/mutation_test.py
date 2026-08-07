"""
mutation_test.py - measure the Alloy pipeline's bug-catching

RESEARCH CONTEXT
The Alloy access-control model produces two independent kinds of
verification: assert blocks and ten
generated + ten hand-written C# integration tests (concrete regression tests
against the real server, with solver-generated example data). This script
applies a small catalog of mutations to the real access-control code (server/)
and to the Alloy model itself (alloy/static/predicates.als), one at a time
and records which layer detect each one.

Every mutated file is backed up in memory before mutation and restored
afterward.

TWO DETECTION PROBES
Probe A (model mutations only)

Probe B (all runnable mutations)

USAGE
    # Validate every find-string matches its target file exactly once,
    # without running anything expensive
    python scripts/mutation_test.py --repo-root . --dry-run

    # Establish a clean baseline (no mutation applied) before trusting any
    # mutated result.
    python scripts/mutation_test.py --repo-root . --baseline-only

    # Run the full experiment for every runnable mutation, writing a JSON
    # results file
    python scripts/mutation_test.py --repo-root . --run --out mutation_results.json

    # Run a subset (comma-separated mutation IDs):
    python scripts/mutation_test.py --repo-root . --run --mutations L1,A1 --out ...
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import alloy_checks

# Mutation catalog

MUTATIONS: list[dict] = [
    {
        "id": "S1",
        "category": "sql",
        "runnable_here": False,
        "file": "server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql",
        "line": 12,
        "find": "AND [Status] = 2 -- Confirmed",
        "replace": "AND [Status] <> 2 -- Confirmed",
        "description": "Invert the Confirmed-status gate in the OrganizationUser CTE.",
        "predicted": "TODO",
    },
    {
        "id": "S2",
        "category": "sql",
        "runnable_here": False,
        "file": "server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql",
        "line": 41,
        "find": "O.[Id] = C.[OrganizationId] AND O.[Enabled] = 1",
        "replace": "O.[Id] = C.[OrganizationId]",
        "description": "Drop the org-enabled kill-switch check from the Organization JOIN.",
        "predicted": "TODO",
    },
    {
        "id": "S3",
        "category": "sql",
        "runnable_here": False,
        "file": "server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql",
        "line": 47,
        "find": "CU.[CollectionId] IS NULL AND GU.[OrganizationUserId] = OU.[Id]",
        "replace": "GU.[OrganizationUserId] = OU.[Id]",
        "description": "Drop the null-guard on the GroupUser JOIN (group grants always considered).",
        "predicted": "TODO",
    },
    # LINQ: executed via SQLite
    {
        "id": "L1",
        "category": "linq",
        "runnable_here": True,
        "file": "server/src/Infrastructure.EntityFramework/Repositories/Queries/UserCipherDetailsQuery.cs",
        "line": 23,
        "find": "Status = OrganizationUserStatusType.Confirmed",
        "replace": "Status = OrganizationUserStatusType.Revoked",
        "description": "Swap the Confirmed-status join key for Revoked.",
        "predicted": (
            "TODO"
        ),
    },
    {
        "id": "L2",
        "category": "linq",
        "runnable_here": True,
        "file": "server/src/Infrastructure.EntityFramework/Repositories/Queries/UserCipherDetailsQuery.cs",
        "line": 27,
        "find": "Enabled = true } equals",
        "replace": "Enabled = false } equals",
        "description": "Invert the org-enabled kill-switch join key.",
        "predicted": (
            "TODO"
        ),
    },
    {
        "id": "L3",
        "category": "linq",
        "runnable_here": True,
        "file": "server/src/Infrastructure.EntityFramework/Repositories/Queries/UserCipherDetailsQuery.cs",
        "line": 40,
        "find": "CollectionId = (Guid?)cu.CollectionId, OrganizationUserId = ou.Id } equals",
        "replace": "CollectionId = (Guid?)null, OrganizationUserId = ou.Id } equals",
        "description": (
            "TODO"
        ),
        "predicted": (
            "TODO"
        ),
    },
    # Dapper/SqlServer: the winning-row tie-break itself (needs SQL Server)
    # Companion to S1-S3, but targets C# not the TVF
    {
        "id": "C1",
        "category": "dapper",
        "runnable_here": False,
        "file": "server/src/Infrastructure.Dapper/Vault/Repositories/CipherRepository.cs",
        "line": 107,
        "window": 2,
        "find": (
            "                        .ThenByDescending(og => og.Edit)\n"
            "                        .ThenByDescending(og => og.ViewPassword).First())"
        ),
        "replace": (
            "                        .ThenByDescending(og => og.ViewPassword)\n"
            "                        .ThenByDescending(og => og.Edit).First())"
        ),
        "description": "Swap the Edit/ViewPassword tie-break priority in GetManyByUserIdAsync's OrderByDescending chain.",
        "predicted": (
            "TOOD"
        ),
    },
    # Alloy model: executed
    {
        "id": "A1",
        "category": "model",
        "runnable_here": True,
        "file": "alloy/static/predicates.als",
        "line": 67,
        "find": "    (no cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col)",
        "replace": "    no cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col",
        "description": (
            "Remove the parens around groupGrant's first clause"
        ),
        "predicted": (
            "TODO"
        ),
    },
    {
        "id": "A2",
        "category": "model",
        "runnable_here": True,
        "file": "alloy/static/predicates.als",
        "line": 203,
        "find": "            and (c.owner & Organization).enabled = True  -- org must be enabled\n",
        "replace": "",
        "description": (
            "Remove the org-enabled check from canSee's path-2 (collection-grant) branch"
        ),
        "predicted": (
            "TODO"
        ),
    },
    {
        "id": "A3",
        "category": "model",
        "runnable_here": True,
        "file": "alloy/static/predicates.als",
        "line": 217,
        "find": "            and ou.role in (Owner + Admin)\n",
        "replace": "            and ou.role in (Member + Custom)\n",
        "description": (
            "Flip canSee's admin-bypass role check."
        ),
        "predicted": (
            "TODO"
        ),
    },
    # Winning-row predicates: the Alloy-side counterpart to C1
    {
        "id": "W1",
        "category": "model",
        "runnable_here": True,
        "file": "alloy/static/predicates.als",
        "line": 144,
        "window": 6,
        "find": (
            "        and resolvedEdit[ou, colA] and not resolvedEdit[ou, colB]\n"
            "    )\n"
            "    or (\n"
            "        (resolvedManage[ou, colA] iff resolvedManage[ou, colB])\n"
            "        and (resolvedEdit[ou, colA] iff resolvedEdit[ou, colB])\n"
            "        and resolvedViewPassword[ou, colA] and not resolvedViewPassword[ou, colB]"
        ),
        "replace": (
            "        and resolvedViewPassword[ou, colA] and not resolvedViewPassword[ou, colB]\n"
            "    )\n"
            "    or (\n"
            "        (resolvedManage[ou, colA] iff resolvedManage[ou, colB])\n"
            "        and (resolvedViewPassword[ou, colA] iff resolvedViewPassword[ou, colB])\n"
            "        and resolvedEdit[ou, colA] and not resolvedEdit[ou, colB]"
        ),
        "description": "Swap the Edit/ViewPassword tie-break priority in collectionBeats",
        "predicted": (
            "TODO"
        ),
    },
    {
        "id": "W2",
        "category": "model",
        "runnable_here": True,
        "file": "alloy/static/predicates.als",
        "line": 164,
        "window": 3,
        "find": (
            "    isGrantHoldingCollection[ou, c, col]\n"
            "    and (no col2: Collection |\n"
            "        isGrantHoldingCollection[ou, c, col2] and collectionBeats[ou, col2, col])\n"
        ),
        "replace": "    isGrantHoldingCollection[ou, c, col]\n",
        "description": (
            "Drop winningCollection's maximality clause entirely, reverting to "
            "isGrantHoldingCollection alone, reintroduces the independent OR"
        ),
        "predicted": (
            "TODO"
        ),
    },
    {
        "id": "W3",
        "category": "model",
        "runnable_here": True,
        "file": "alloy/static/predicates.als",
        "line": 113,
        "find": "    or (groupGrant[ou, col] and",
        "replace": "    or (",
        "description": (
            "Remove the groupGrant guard from resolvedEdit's group-grant disjunct"
        ),
        "predicted": (
            "TODO"
        ),
    },
]

# CHECK_NAMES, ALLOY_JAR, ALLOY_MODEL, and the wrapper-module mechanism used to
# actually run checks commands in alloy_checks.py, shared with
# scripts/check_assertions.py see probe_a_assertions() below.

# Relative to --repo-root
ALLOY_INSTANCES_DIR = "alloy/instances"
ALLOY_FIXTURES_DIR = "alloy/fixtures"
GENERATED_CS = "server/test/Infrastructure.IntegrationTest/Vault/Repositories/AlloyCipherFixtureTests.cs"
TEST_DB_SOURCE = "server/test/Infrastructure.IntegrationTest/test.db"
INTEGRATION_TEST_PROJ_DIR = "test/Infrastructure.IntegrationTest"  # relative to server/

# MSSQL-only: the SQL-category mutations (S1-S3) target the real T-SQL TVF, which only
# runs via the Dapper/SQL-Server repository path -- a scratch-copy-per-run strategy like
# SQLite's (see make_scratch_db) is impractical for a real SQL Server instance (DB
# creation is expensive), so these mutations instead run against ONE
# persistent, already-migrated database, mutating and restoring the TVF
# in-place via DROP FUNCTION + CREATE FUNCTION. Isolation across runs still holds:
# AlloyCipherFixtureHelpers.CreateEntitiesFromFixture (server/test/.../AlloyCipherFixtureHelpers.cs)
# generates a fresh GUID + unique runTag per test invocation, so leftover rows from a
# prior mutation's run never leak into a later run's GetManyByUserIdAsync(freshUserId)
# results, only the TVF definition needs resetting between mutations, not the data.
#
MSSQL_DEV_DIR = "server/dev"  # cwd for docker compose invocations (holds docker-compose.yml)
MSSQL_HELPER_CONTAINER_PATH = "/tmp/mutation_apply.sql"  # container-side only, no bind mount
MSSQL_TVF_FILE = "server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql"
MSSQL_SQLCMD_PATH = "/opt/mssql-tools18/bin/sqlcmd"


class MutationTestError(Exception):
    pass


# Backup / restore harness
# server/ is entirely untracked in this repo

class BackupManager:
    def __init__(self):
        self._file_backups: dict[Path, bytes | None] = {}
        self._dir_backups: dict[Path, Path] = {}
        self._tmp_root = Path(tempfile.mkdtemp(prefix="mutation_test_backup_"))
        atexit.register(self.restore_all)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._on_signal)

    def _on_signal(self, signum, frame):
        sys.stderr.write(f"\n[mutation_test] caught signal {signum}, restoring before exit...\n")
        self.restore_all()
        sys.exit(1)

    def backup_file(self, path: Path) -> None:
        """Record a file's current content (or absence) exactly once."""
        if path in self._file_backups:
            return
        self._file_backups[path] = path.read_bytes() if path.exists() else None

    def backup_dir(self, path: Path) -> None:
        """Record a directory's current contents (or absence) exactly once."""
        if path in self._dir_backups:
            return
        dest = self._tmp_root / f"dir_{len(self._dir_backups)}_{path.name}"
        if path.exists():
            shutil.copytree(path, dest)
        self._dir_backups[path] = dest

    def restore_all(self) -> None:
        for path, content in self._file_backups.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        self._file_backups.clear()
        for path, backup in self._dir_backups.items():
            if path.exists():
                shutil.rmtree(path)
            if backup.exists():
                shutil.copytree(backup, path)
        self._dir_backups.clear()


def apply_mutation(mutation: dict, repo_root: Path, backups: BackupManager, *, dry_run: bool) -> None:
    """
    Apply one mutation's find/replace, scoped to a small window of lines rather than
    the whole file. Raises MutationTestError if the find string does not match EXACTLY
    ONCE within that window -- this is the primary correctness gate for the whole
    catalog.
    """
    path = repo_root / mutation["file"]
    if not path.exists():
        raise MutationTestError(f"{mutation['id']}: target file does not exist: {path}")
    if "line" not in mutation:
        # Fail loudly on a missing anchor rather than defaulting to line 1 or falling
        # back to whole-file matching, a forgotten line field is a bug
        raise MutationTestError(f"{mutation['id']}: missing required 'line' field.")
    line_no = mutation["line"]
    window = mutation.get("window", 1)
    if line_no < 1 or window < 1:
        raise MutationTestError(f"{mutation['id']}: 'line' and 'window' must both be >= 1.")

    text = path.read_text()
    lines = text.splitlines(keepends=True)

    start = line_no - 1
    end = start + window
    if start < 0 or end > len(lines):
        raise MutationTestError(
            f"{mutation['id']}: line {line_no} (window {window}) is out of range for "
            f"{path} ({len(lines)} lines total) -- the catalog has likely drifted from "
            f"the real file; re-run `grep -n` against the current file to find the new line."
        )

    window_text = "".join(lines[start:end])
    count = window_text.count(mutation["find"])
    if count != 1:
        span = f"{line_no}" if window == 1 else f"{line_no}-{line_no + window - 1}"
        raise MutationTestError(
            f"{mutation['id']}: find string matched {count} times within {path}:{span} "
            f"(expected exactly 1).\n"
            f"--- expected (find) ---\n{mutation['find']!r}\n"
            f"--- actual window content ---\n{window_text!r}"
        )

    backups.backup_file(path)
    if not dry_run:
        new_window_text = window_text.replace(mutation["find"], mutation["replace"], 1)
        # Collapse the window back to a single joined chunk, THEN splice it into the
        # full line list. Stays correct even when replace adds/removes lines within the
        # window
        lines[start:end] = [new_window_text]
        path.write_text("".join(lines))


# Probe A: Alloy check commands via the JAR's exec CLI

def probe_a_assertions(repo_root: Path, tmp_dir: Path) -> dict[str, bool]:
    """Run every assertion in alloy_checks.CHECK_NAMES; return {name: violated_bool}."""
    return alloy_checks.run_check_commands(repo_root, tmp_dir)


# Probe B: xUnit integration tests against a scratch SQLite DB

_TRX_NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"


def parse_trx(trx_path: Path) -> list[dict]:
    """Return [{'test_name': ..., 'outcome': 'Passed'|'Failed'|'NotExecuted'|...}]."""
    if not trx_path.exists():
        return []
    tree = ET.parse(trx_path)
    root = tree.getroot()
    results = []
    for r in root.iter(f"{_TRX_NS}UnitTestResult"):
        results.append({"test_name": r.get("testName"), "outcome": r.get("outcome")})
    return results


# Class name substrings that identify which of the two test files a TRX row came
# from. AlloyCipherFixtureTests.cs is auto-generated from the Alloy model
# (alloy_to_fixture.py). AlloyCipherAccessTests.cs is hand-written, covering
# mostly the same scenarios independently.
_GENERATED_TEST_CLASS = "AlloyCipherFixtureTests"
_HAND_WRITTEN_TEST_CLASS = "AlloyCipherAccessTests"


def classify_test(test_name: str) -> str | None:
    """
    Return generated, hand_written, or None (unrecognized class) for one TRX
    test_name. Matches on the class name substring rather than parsing the full
    qualified name, since that's stable across namespace/provider-tag changes.
    """
    if _GENERATED_TEST_CLASS in test_name:
        return "generated"
    if _HAND_WRITTEN_TEST_CLASS in test_name:
        return "hand_written"
    return None


def summarize_probe_b(probe_b: dict) -> dict:
    """
    Break down one probe_b result's TRX outcomes by test origin (generated vs.
    hand-written) instead of one combined count. Only counts rows that actually
    ran (Passed/Failed), NotExecuted/Skip rows exist for every unconfigured
    provider (see DatabaseDataAttribute) and would otherwise dilute the counts
    with noise unrelated to whether this mutation was caught.
    """
    summary = {
        "generated": {"total": 0, "passed": 0, "failed": 0, "failed_names": []},
        "hand_written": {"total": 0, "passed": 0, "failed": 0, "failed_names": []},
    }
    for r in probe_b.get("trx_results", []):
        if r["outcome"] not in ("Passed", "Failed"):
            continue
        cls = classify_test(r["test_name"])
        if cls is None:
            continue
        bucket = summary[cls]
        bucket["total"] += 1
        if r["outcome"] == "Passed":
            bucket["passed"] += 1
        else:
            bucket["failed"] += 1
            # Strip namespace/class prefix and provider tag for a short, readable name
            short_name = r["test_name"].split(".")[-1].split(" [")[0]
            bucket["failed_names"].append(short_name)
    return summary


def print_probe_b_summary(summary: dict, *, indent: str = "    ") -> None:
    """Print a summarize_probe_b() result, one line per test class."""
    for label, key in (("generated", "generated"), ("hand-written", "hand_written")):
        b = summary[key]
        line = f"{indent}{label:13s} {b['passed']}/{b['total']} passed"
        if b["failed_names"]:
            line += f" -- caught by: {', '.join(sorted(b['failed_names']))}"
        print(line)


def probe_b_dotnet_tests(repo_root: Path, scratch_db: Path, trx_name: str) -> dict:
    """
    Run the Alloy-derived integration tests
    """
    server_dir = repo_root / "server"
    results_dir = repo_root / ".mutation_test_trx"
    results_dir.mkdir(exist_ok=True)
    trx_path = results_dir / trx_name

    env = os.environ.copy()
    env["BW_TEST_DATABASES__0__TYPE"] = "Sqlite"
    env["BW_TEST_DATABASES__0__CONNECTIONSTRING"] = f"Data Source={scratch_db}"

    proc = subprocess.run(
        [
            "dotnet", "test", INTEGRATION_TEST_PROJ_DIR,
            "--filter", "FullyQualifiedName~Alloy",
            "--logger", f"trx;LogFileName={trx_path.name}",
            "--results-directory", str(results_dir),
        ],
        cwd=server_dir, env=env, capture_output=True, text=True,
    )
    return {
        "trx_results": parse_trx(trx_path),
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }

def probe_b_dotnet_tests_mssql(repo_root: Path, connection_string: str, trx_name: str) -> dict:
    """
    MSSQL twin of probe_b_dotnet_tests: same test filter and TRX parsing, but points
    DatabaseDataAttribute at a real SQL Server instance instead of a scratch SQLite file.
    """
    server_dir = repo_root / "server"
    results_dir = repo_root / ".mutation_test_trx"
    results_dir.mkdir(exist_ok=True)
    trx_path = results_dir / trx_name

    env = os.environ.copy()
    env["BW_TEST_DATABASES__0__TYPE"] = "SqlServer"
    env["BW_TEST_DATABASES__0__CONNECTIONSTRING"] = connection_string
    env.pop("BW_TEST_DATABASES__0__USEEF", None)  # explicitly unset

    proc = subprocess.run(
        [
            "dotnet", "test", INTEGRATION_TEST_PROJ_DIR,
            "--filter", "FullyQualifiedName~Alloy",
            "--logger", f"trx;LogFileName={trx_path.name}",
            "--results-directory", str(results_dir),
        ],
        cwd=server_dir, env=env, capture_output=True, text=True,
    )
    return {
        "trx_results": parse_trx(trx_path),
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }


def push_tvf_to_mssql(repo_root: Path, function_sql_text: str) -> dict:
    """
    Push a CREATE FUNCTION body (the current, possibly-mutated content of
    UserCipherDetails.sql, or the original when restoring) into the running MSSQL
    container's vault_dev database.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sql", delete=False, encoding="utf-8") as f:
        batch = f"DROP FUNCTION [dbo].[UserCipherDetails];\nGO\n{function_sql_text}\nGO\n"
        f.write(batch)
        local_tmp = f.name
    # NamedTemporaryFile defaults to 0600 (owner-only)
    os.chmod(local_tmp, 0o644)

    try:
        cp_proc = subprocess.run(
            ["docker", "compose", "cp", local_tmp, f"mssql:{MSSQL_HELPER_CONTAINER_PATH}"],
            cwd=repo_root / MSSQL_DEV_DIR, capture_output=True, text=True,
        )
        if cp_proc.returncode != 0:
            return {
                "returncode": cp_proc.returncode,
                "stdout_tail": cp_proc.stdout[-2000:],
                "stderr_tail": f"docker compose cp failed: {cp_proc.stderr[-2000:]}",
            }

        sqlcmd_base = [
            "docker", "compose", "exec", "-T", "mssql",
            MSSQL_SQLCMD_PATH,
            "-S", "localhost", "-U", "sa", "-P", os.environ.get("MSSQL_PASSWORD", ""),
            "-C", "-d", "vault_dev",
        ]
        proc = subprocess.run(
            [*sqlcmd_base, "-i", MSSQL_HELPER_CONTAINER_PATH],
            cwd=repo_root / MSSQL_DEV_DIR, capture_output=True, text=True,
        )

        verify_proc = subprocess.run(
            [*sqlcmd_base, "-h", "-1", "-Q",
             "SET NOCOUNT ON; SELECT ISNULL(CAST(OBJECT_ID('dbo.UserCipherDetails') AS VARCHAR(20)), 'NULL');"],
            cwd=repo_root / MSSQL_DEV_DIR, capture_output=True, text=True,
        )
        function_exists = verify_proc.returncode == 0 and "NULL" not in verify_proc.stdout

        return {
            "returncode": proc.returncode if function_exists else 1,
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:] if function_exists else (
                proc.stderr[-1000:] + "\n[push_tvf_to_mssql] POST-PUSH VERIFICATION FAILED: "
                f"OBJECT_ID('dbo.UserCipherDetails') is NULL after this push -- sqlcmd exited "
                f"{proc.returncode} but the function does not exist. verify_proc output: "
                f"{verify_proc.stdout!r} {verify_proc.stderr!r}"
            ),
        }
    finally:
        Path(local_tmp).unlink(missing_ok=True)


# Model-mutation fixture regeneration

def regenerate_fixtures(repo_root: Path) -> dict:
    """
    Re-run scripts/alloy_to_fixture.py against the
    alloy/predicates.als. Returns {'ok': bool, 'returncode', 'stdout', 'stderr'}.
    A non-zero returncode most often means a run command went UNSAT under
    the mutated model, a meaningful outcome (the tooling breaks),
    distinct from a generated test failed result.
    """
    proc = subprocess.run(
        [sys.executable, "scripts/alloy_to_fixture.py", "--repo-root", "."],
        cwd=repo_root, capture_output=True, text=True,
    )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }


# Orchestration

def run_one_mutation(
    mutation: dict,
    repo_root: Path,
    db_source: Path | None,
    alloy_tmp: Path,
    *,
    db_type: str = "sqlite",
    mssql_connection_string: str | None = None,
) -> dict:
    """
    db_source: an already-migrated SQLite DB to copy fresh for THIS mutation alone
    (db_type="sqlite" only -- ignored for "sqlserver").
    """
    if mutation["category"] in ("sql", "dapper") and db_type != "sqlserver":
        raise MutationTestError(
            f"{mutation['id']}: category {mutation['category']!r} mutations require "
            f"--db-type sqlserver (got db_type={db_type!r}) -- running under sqlite "
            f"would silently probe an unrelated code path and produce a meaningless result."
        )

    backups = BackupManager()
    result: dict = {"id": mutation["id"], "category": mutation["category"], "description": mutation["description"]}

    try:
        if mutation["category"] == "sql":
            apply_mutation(mutation, repo_root, backups, dry_run=False)  # mutates the .sql file on disk
            mutated_body = (repo_root / mutation["file"]).read_text(encoding="utf-8-sig")
            push_result = push_tvf_to_mssql(repo_root, mutated_body)
            result["mssql_push"] = push_result
            if push_result["returncode"] != 0:
                result["probe_b"] = {"skipped": "mssql_push_failed", "detail": push_result}
            else:
                result["probe_b"] = probe_b_dotnet_tests_mssql(
                    repo_root, mssql_connection_string, f"{mutation['id']}.trx"
                )
        elif mutation["category"] == "dapper":
            # C# code mutation targeting the SQL-Server-only Dapper repository
            # no DB-side push needed
            apply_mutation(mutation, repo_root, backups, dry_run=False)
            result["probe_b"] = probe_b_dotnet_tests_mssql(
                repo_root, mssql_connection_string, f"{mutation['id']}.trx"
            )
        elif mutation["category"] == "model":
            # Back up pipeline outputs before regenerating them from the mutated model.
            backups.backup_dir(repo_root / ALLOY_INSTANCES_DIR)
            backups.backup_dir(repo_root / ALLOY_FIXTURES_DIR)
            backups.backup_file(repo_root / GENERATED_CS)

            apply_mutation(mutation, repo_root, backups, dry_run=False)
            result["probe_a"] = probe_a_assertions(repo_root, alloy_tmp)

            gen = regenerate_fixtures(repo_root)
            result["fixture_regeneration"] = gen
            if not gen["ok"]:
                # UNSAT (or any other regeneration failure)
                result["probe_b"] = {"skipped": "pipeline_generation_failed"}
            elif db_type == "sqlserver":
                result["probe_b"] = probe_b_dotnet_tests_mssql(
                    repo_root, mssql_connection_string, f"{mutation['id']}.trx"
                )
            else:
                scratch_db = make_scratch_db(repo_root, db_source)
                result["probe_b"] = probe_b_dotnet_tests(repo_root, scratch_db, f"{mutation['id']}.trx")
        else:
            # linq
            scratch_db = make_scratch_db(repo_root, db_source)
            apply_mutation(mutation, repo_root, backups, dry_run=False)
            result["probe_b"] = probe_b_dotnet_tests(repo_root, scratch_db, f"{mutation['id']}.trx")

    finally:
        backups.restore_all()
        if mutation["category"] == "sql":
            # The file is restored on disk by backups.restore_all() above, but the LIVE
            # DATABASE still has the mutated function until we push the original back
            original_body = (repo_root / mutation["file"]).read_text(encoding="utf-8-sig")
            result["mssql_restore"] = push_tvf_to_mssql(repo_root, original_body)

    return result


def run_baseline(
    repo_root: Path,
    db_source: Path | None,
    alloy_tmp: Path,
    *,
    db_type: str = "sqlite",
    mssql_connection_string: str | None = None,
) -> dict:
    """
    Baseline against the unmutated repo: both probes, so mutation results have
    a genuine control to compare against rather than an assumed-clean one.
    """
    if db_type == "sqlserver":
        return {
            "probe_a": probe_a_assertions(repo_root, alloy_tmp),
            "probe_b": probe_b_dotnet_tests_mssql(repo_root, mssql_connection_string, "baseline.trx"),
        }
    scratch_db = make_scratch_db(repo_root, db_source)
    return {
        "probe_a": probe_a_assertions(repo_root, alloy_tmp),
        "probe_b": probe_b_dotnet_tests(repo_root, scratch_db, "baseline.trx"),
    }


def make_scratch_db(repo_root: Path, db_source: Path | None = None) -> Path:
    """
    Copy a source SQLite DB to a fresh scratch location. Defaults to the
    committed server/test/Infrastructure.IntegrationTest/test.db
    """
    src = db_source if db_source is not None else (repo_root / TEST_DB_SOURCE)
    scratch_dir = Path(tempfile.mkdtemp(prefix="mutation_test_db_"))
    dest = scratch_dir / "test.db"
    shutil.copy(src, dest)
    return dest


def dry_run(repo_root: Path, mutations: list[dict]) -> None:
    print(f"Dry-run: validating {len(mutations)} mutation find-strings...\n")
    failures = []
    for m in mutations:
        backups = BackupManager()
        try:
            apply_mutation(m, repo_root, backups, dry_run=True)
            window = m.get("window", 1)
            span = f"{m['line']}" if window == 1 else f"{m['line']}-{m['line'] + window - 1}"
            print(f"  OK   {m['id']:4s} ({m['category']}) -- unique match at {m['file']}:{span}")
        except MutationTestError as e:
            print(f"  FAIL {m['id']:4s} -- {e}")
            failures.append(m["id"])
        finally:
            backups.restore_all()
    print()
    if failures:
        print(f"{len(failures)} mutation(s) failed validation: {', '.join(failures)}")
        sys.exit(1)
    print("All mutations validated: every find-string matches exactly once within its line window.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--dry-run", action="store_true", help="Validate find-strings only; no execution.")
    parser.add_argument("--baseline-only", action="store_true", help="Run the clean baseline probe and exit.")
    parser.add_argument("--run", action="store_true", help="Run the full mutation experiment.")
    parser.add_argument("--mutations", default=None, help="Comma-separated mutation IDs to run (default: all runnable_here).")
    parser.add_argument("--out", default="mutation_results.json", help="Where to write JSON results.")
    parser.add_argument(
        "--db-source", default=None,
        help="Path to an already-migrated SQLite DB to copy from",
    )
    parser.add_argument(
        "--db-type", choices=["sqlite", "sqlserver"], default="sqlite",
        help="Backend Probe B runs against. sqlserver is required for category='sql' ",
    )
    parser.add_argument(
        "--mssql-connection-string", default=None,
        help="Connection string to the already-migrated, persistent MSSQL",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    db_source = Path(args.db_source).resolve() if args.db_source else None

    if args.db_type == "sqlserver" and not args.mssql_connection_string and not args.dry_run:
        parser.error("--db-type sqlserver requires --mssql-connection-string.")

    if args.mutations:
        wanted = set(args.mutations.split(","))
        selected = [m for m in MUTATIONS if m["id"] in wanted]
    else:
        selected = [m for m in MUTATIONS if m["runnable_here"]]

    if args.dry_run:
        dry_run(repo_root, MUTATIONS)  # validate all mutations
        return

    mismatched = [m["id"] for m in selected if m["category"] in ("sql", "dapper") and args.db_type != "sqlserver"]
    if mismatched:
        parser.error(
            f"category 'sql'/'dapper' mutation(s) {', '.join(mismatched)} require --db-type sqlserver "
            f"(got --db-type {args.db_type!r})."
        )

    if args.db_type == "sqlite":
        print(f"DB source: {db_source or TEST_DB_SOURCE} (a fresh scratch copy is made for each run)")
    else:
        print(f"DB type: sqlserver, persistent DB (no per-run scratch copy)")
    alloy_tmp = Path(tempfile.mkdtemp(prefix="mutation_test_alloy_"))

    if args.baseline_only:
        result = run_baseline(
            repo_root, db_source, alloy_tmp,
            db_type=args.db_type, mssql_connection_string=args.mssql_connection_string,
        )
        print(json.dumps({"baseline": result}, indent=2, default=str))
        return

    if not args.run:
        parser.error("Specify one of --dry-run, --baseline-only, or --run.")

    print("Running baseline (no mutation)...")
    baseline = run_baseline(
        repo_root, db_source, alloy_tmp,
        db_type=args.db_type, mssql_connection_string=args.mssql_connection_string,
    )
    if not baseline["probe_b"].get("skipped"):
        baseline["probe_b_summary"] = summarize_probe_b(baseline["probe_b"])
        print_probe_b_summary(baseline["probe_b_summary"])

    results = {"baseline": baseline, "mutations": []}
    for m in selected:
        print(f"\n=== Mutation {m['id']} ({m['category']}): {m['description']}")
        r = run_one_mutation(
            m, repo_root, db_source, alloy_tmp,
            db_type=args.db_type, mssql_connection_string=args.mssql_connection_string,
        )
        if not r["probe_b"].get("skipped"):
            r["probe_b_summary"] = summarize_probe_b(r["probe_b"])
            print_probe_b_summary(r["probe_b_summary"])
        results["mutations"].append(r)

    out_path = repo_root / args.out
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
