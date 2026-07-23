from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ALLOY_JAR = "scripts/lib/alloy6.jar"
ALLOY_MODEL = "alloy/static/predicates.als"

CHECK_NAMES = [
    "RevokedCannotSee",
    "DisabledOrgBlocksAccess",
    "UncollectedCipherInvisible",
    "PersonalCipherIsPrivate",
    "ReadOnlyPreventsEdit",
    "NoAccessWithoutGrant",
]

_CHECK_WRAPPER_NAME = "_alloy_checks_wrapper.als"

_CHECK_WRAPPER_TEMPLATE = """\
module alloy_checks_wrapper
open predicates

check RevokedCannotSee for 4
check DisabledOrgBlocksAccess for 4
check UncollectedCipherInvisible for 4
check PersonalCipherIsPrivate for 4
check ReadOnlyPreventsEdit for 4
check NoAccessWithoutGrant for 4
"""


def run_alloy_command(jar: Path, model_path: Path, command_name: str, out_dir: Path) -> bool:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    result = subprocess.run(
        [
            "java", "-jar", str(jar),
            "exec", "-c", command_name, "-t", "xml", "-q", "-f",
            "-o", str(out_dir), str(model_path),
        ],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Alloy CLI exec failed for '{command_name}' (exit {result.returncode}) -- "
            f"this is NOT a SAT/UNSAT result, something went wrong before the solver even "
            f"ran (missing JAR/model path, bad Java install,...). Treating this as "
            f"'holds'/'not violated' would be silently wrong.\n"
            f"jar: {jar}\nmodel: {model_path}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return (out_dir / f"{command_name}-solution-0.xml").exists()


def run_check_commands(repo_root: Path, tmp_dir: Path) -> dict[str, bool]:
    jar = repo_root / ALLOY_JAR
    alloy_dir = repo_root / "alloy" / "static"
    wrapper = alloy_dir / _CHECK_WRAPPER_NAME
    wrapper.write_text(_CHECK_WRAPPER_TEMPLATE)
    try:
        results = {}
        for name in CHECK_NAMES:
            out_dir = tmp_dir / f"check_{name}"
            results[name] = run_alloy_command(jar, wrapper, name, out_dir)
        return results
    finally:
        wrapper.unlink(missing_ok=True)
