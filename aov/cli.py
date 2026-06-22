#!/usr/bin/env python3
import json
import os
import fnmatch
import html
import hashlib
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import click
import httpx
import toml

CONFIG_PATH = Path.home() / ".valicode" / "config.toml"
LEGACY_CONFIG_PATH = Path.home() / ".aov" / "config.toml"
DEFAULT_API_BASE = "https://api.valicode.sbs/v1"
DEFAULT_IGNORE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "coverage",
    ".venv", "venv", "__pycache__", ".turbo", ".cache",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
DEFAULT_IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z",
    ".bin", ".exe", ".dll", ".so", ".dylib", ".pyc",
}
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
    ".cs", ".cpp", ".c", ".h", ".rb", ".php", ".swift", ".kt",
    ".scala", ".sh", ".yaml", ".yml", ".json", ".toml", ".md",
    ".sql", ".graphql", ".prisma", ".Dockerfile",
}
LOCKFILE_NAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
    "Cargo.lock", "Gemfile.lock", "composer.lock",
}
DEFAULT_MAX_UPLOAD_BYTES = 500 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
OUTPUT_FORMATS = ["table", "json", "sarif", "markdown", "html", "junit", "summary", "mermaid", "chat"]


def load_config() -> dict:
    if CONFIG_PATH.exists():
        return toml.loads(CONFIG_PATH.read_text())
    if LEGACY_CONFIG_PATH.exists():
        return toml.loads(LEGACY_CONFIG_PATH.read_text())
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(toml.dumps(cfg))


def get_api_base() -> str:
    cfg = load_config()
    return (
        os.environ.get("VALICODE_API_BASE")
        or os.environ.get("AOV_API_BASE")
        or cfg.get("api_base")
        or DEFAULT_API_BASE
    ).rstrip("/")


@click.group()
@click.version_option("2.0.0", prog_name="valicode")
def cli():
    """Valicode - audit AI-generated code before it ships."""


@cli.command()
@click.option("--check-api", is_flag=True, help="Also call the Valicode API health/docs endpoint")
def doctor(check_api):
    """Validate the local CLI security-analysis environment."""
    cfg = load_config()
    capabilities = sandbox_capabilities()
    checks = [
        ("api_key", bool(cfg.get("api_key")), "API key configured in ~/.valicode/config.toml", True),
        ("git", shutil.which("git") is not None, "git executable available", True),
        ("semgrep", shutil.which("semgrep") is not None, "semgrep executable available for local parity checks", False),
        ("docker", capabilities["docker_available"], "Docker available for isolated validation", False),
        ("microvm", capabilities["microvm_available"], capabilities["microvm_detail"], False),
    ]

    in_git_repo = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip() == "true"
    checks.append(("git_repo", in_git_repo, "current directory is inside a git repository", True))

    if check_api:
        try:
            response = httpx.get(get_api_base().rsplit("/v1", 1)[0] + "/health", timeout=10)
            checks.append(("api_reachable", response.status_code < 500, "Valicode API reachable", True))
        except httpx.HTTPError:
            checks.append(("api_reachable", False, "Valicode API reachable", True))

    click.echo(f"{'Check':18} {'Status':8} Detail")
    for check_id, ok, detail, required in checks:
        click.echo(f"{check_id:18} {'PASS' if ok else 'FAIL':8} {detail}")

    if not all(ok for _, ok, _, required in checks if required):
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True), required=False)
@click.option("--diff", "diff_file", type=click.Path(exists=True), help="Path to a .diff file")
@click.option("--staged", is_flag=True, help="Analyze staged git changes")
@click.option("--pr", type=int, help="GitHub PR number")
@click.option("--repo", help="GitHub repo (owner/repo)")
@click.option("--output", type=click.Choice(OUTPUT_FORMATS), default="table")
@click.option("--save-report", type=click.Path(file_okay=False), help="Write a full local report bundle to this directory")
@click.option("--fail-under", type=int, default=0, help="Exit 1 if score below threshold")
@click.option("--context/--no-context", default=True, help="Include safe repository context for cross-file analysis")
@click.option("--run-tests", is_flag=True, help="Run detected local tests and include the redacted result")
@click.option("--sandbox", type=click.Choice(["auto", "microvm", "docker", "local", "none"]), default="auto")
@click.option("--validate-fixes", is_flag=True, help="Apply suggested patches in a temporary workspace and validate them")
def analyze(path, diff_file, staged, pr, repo, output, save_report, fail_under, context, run_tests, sandbox, validate_fixes):
    """Analyze a file, diff, staged changes, or GitHub PR."""
    cfg = load_config()
    api_key = cfg.get("api_key")
    if not api_key:
        click.echo("Error: No API key configured. Run valicode login first.", err=True)
        sys.exit(1)

    diff_content = _get_diff_content(path, diff_file, staged, pr, repo, cfg)
    if not diff_content:
        click.echo("No changes to analyze.")
        sys.exit(0)

    repo_context = build_repository_context(Path.cwd(), include_files=context)
    if run_tests:
        repo_context["test_runs"] = run_local_validation(Path.cwd(), sandbox=sandbox)
    click.echo(f"Analyzing code with {len(repo_context.get('files', []))} context file(s)...")
    try:
        response = httpx.post(
            f"{get_api_base()}/analyses",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={"diff": diff_content, "repo": repo, "repo_context": repo_context, "force_reanalysis": True},
            timeout=120,
        )
        response.raise_for_status()
        result = response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            click.echo("Authentication failed. Check your API key.", err=True)
        elif exc.response.status_code == 429:
            click.echo("Rate limit exceeded. Wait before retrying.", err=True)
        else:
            click.echo(f"API error {exc.response.status_code}", err=True)
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo("Request timed out.", err=True)
        sys.exit(1)

    if validate_fixes:
        result["fix_validations"] = validate_suggested_fixes(Path.cwd(), result, api_key, sandbox=sandbox)

    if save_report:
        written = save_report_bundle(Path(save_report), result)
        click.echo(f"Report bundle written to {Path(save_report).resolve()} ({len(written)} files)")
    print_result(result, output)
    if output in {"table", "summary", "chat"}:
        print_analysis_links(result)

    score = result.get("score", 100)
    if result.get("merge_gate", {}).get("status") == "fail":
        click.echo("\nMerge gate failed because validated blockers were found.", err=True)
        sys.exit(1)
    if fail_under and score < fail_under:
        click.echo(f"\nScore {score} is below threshold {fail_under}. Failing.", err=True)
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--production", is_flag=True, help="Run full production-readiness workspace scan")
@click.option("--repo", help="GitHub repo (owner/repo)")
@click.option("--output", type=click.Choice(OUTPUT_FORMATS), default="table")
@click.option("--save-report", type=click.Path(file_okay=False), help="Write a full local report bundle to this directory")
@click.option("--fail-under", type=int, default=0, help="Exit 1 if score below threshold")
@click.option("--max-upload-mb", type=int, default=500, help="Maximum workspace payload size in MB")
@click.option("--max-file-kb", type=int, default=2048, help="Maximum individual file size in KB")
@click.option("--include-lockfiles", is_flag=True, help="Include lockfiles in the workspace payload")
@click.option("--dry-run", is_flag=True, help="Show files that would be sent without calling the API")
@click.option("--sandbox", type=click.Choice(["auto", "microvm", "docker", "local", "none"]), default="auto", help="Isolation policy for build and test execution")
@click.option("--fuzz-command", help="Explicit fuzz command to run under the selected sandbox")
@click.option("--validate-fixes", is_flag=True, help="Validate suggested patches in an isolated temporary workspace")
def scan(path, production, repo, output, save_report, fail_under, max_upload_mb, max_file_kb, include_lockfiles, dry_run, sandbox, fuzz_command, validate_fixes):
    """Scan a whole workspace, ignoring dependencies, build output, and binaries."""
    cfg = load_config()
    api_key = cfg.get("api_key")
    if not api_key and not dry_run:
        click.echo("Error: No API key configured. Run valicode login first.", err=True)
        sys.exit(1)

    root = Path(path).resolve()
    files, ignored = collect_workspace_files(
        root,
        max_total_bytes=max_upload_mb * 1024 * 1024,
        max_file_bytes=max_file_kb * 1024,
        include_lockfiles=include_lockfiles,
    )

    if not files:
        click.echo("No source files found to scan.")
        sys.exit(0)

    manifest = {
        "mode": "production" if production else "workspace",
        "root": str(root),
        "files_scanned": len(files),
        "bytes_scanned": sum(item["size"] for item in files),
        "ignored_count": len(ignored),
        "eligible_files": len(files),
    }

    if dry_run:
        _print_scan_manifest(files, ignored, manifest)
        return

    diff_content = workspace_files_to_diff(root, files)
    context = build_repository_context(root, include_files=False)
    context["scan"] = manifest
    if production:
        click.echo("Running local validation commands...")
        context["test_runs"] = run_local_validation(root, sandbox=sandbox)
        if fuzz_command:
            context["test_runs"].extend(run_explicit_command(root, fuzz_command, sandbox=sandbox, kind="fuzz"))
        context["sandbox"] = {"requested": sandbox, **sandbox_capabilities()}
    click.echo("Scanning workspace...")
    try:
        response = httpx.post(
            f"{get_api_base()}/analyses",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={"diff": diff_content, "repo": repo, "repo_context": context, "force_reanalysis": True},
            timeout=300,
        )
        response.raise_for_status()
        result = response.json()
    except httpx.HTTPStatusError as exc:
        click.echo(f"API error {exc.response.status_code}", err=True)
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo("Workspace scan timed out.", err=True)
        sys.exit(1)

    if validate_fixes:
        result["fix_validations"] = validate_suggested_fixes(root, result, api_key, sandbox=sandbox)

    result["workspace_manifest"] = manifest
    if save_report:
        written = save_report_bundle(Path(save_report), result)
        click.echo(f"Report bundle written to {Path(save_report).resolve()} ({len(written)} files)")
    print_result(result, output)
    if output == "table":
        click.echo(f"Workspace files scanned: {manifest['files_scanned']} / bytes: {manifest['bytes_scanned']} / ignored: {manifest['ignored_count']}")
        print_analysis_links(result)
    elif output in {"summary", "chat"}:
        print_analysis_links(result)

    score = result.get("score", 100)
    if result.get("merge_gate", {}).get("status") == "fail":
        click.echo("\nMerge gate failed because validated blockers or failed checks were found.", err=True)
        sys.exit(1)
    if fail_under and score < fail_under:
        click.echo(f"\nScore {score} is below threshold {fail_under}. Failing.", err=True)
        sys.exit(1)


def build_repository_context(root: Path, *, include_files: bool = True) -> dict:
    root = root.resolve()
    if (root / ".git").exists() is False and shutil.which("git"):
        git_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, text=True, check=False,
        ).stdout.strip()
        if git_root:
            root = Path(git_root).resolve()
    files, ignored = collect_workspace_files(
        root,
        max_total_bytes=25 * 1024 * 1024 if include_files else DEFAULT_MAX_UPLOAD_BYTES,
        max_file_bytes=512 * 1024,
        include_lockfiles=True,
    )
    suffix_counts: dict[str, int] = {}
    for item in files:
        suffix = Path(item["path"]).suffix.lower() or Path(item["path"]).name
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
    language_map = {
        ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript/React",
        ".js": "JavaScript", ".jsx": "JavaScript/React", ".go": "Go",
        ".rs": "Rust", ".java": "Java", ".cs": "C#", ".php": "PHP",
    }
    dominant = max(suffix_counts, key=suffix_counts.get) if suffix_counts else ""
    context = {
        "primary_language": language_map.get(dominant, dominant or "unknown"),
        "frameworks": detect_frameworks(root),
        "base_sha": git_value(root, ["rev-parse", "HEAD~1"]),
        "head_sha": git_value(root, ["rev-parse", "HEAD"]),
        "scan": {
            "mode": "contextual-diff" if include_files else "workspace",
            "eligible_files": len(files),
            "ignored_count": len(ignored),
            "bytes_scanned": sum(item["size"] for item in files),
        },
    }
    if include_files:
        context["files"] = [
            {
                "path": item["path"],
                "content": (root / item["path"]).read_text(encoding="utf-8", errors="replace"),
                "size": item["size"],
            }
            for item in files
        ]
    return context


def git_value(root: Path, args: list[str]) -> str | None:
    if not shutil.which("git"):
        return None
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    return result.stdout.strip() or None


def detect_frameworks(root: Path) -> list[str]:
    frameworks = []
    package_json = root / "package.json"
    if package_json.exists():
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
            dependencies = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
            for package_name, label in {"next": "Next.js", "react": "React", "vue": "Vue", "express": "Express", "nestjs": "NestJS"}.items():
                if package_name in dependencies:
                    frameworks.append(label)
        except (OSError, json.JSONDecodeError):
            pass
    pyproject = (root / "pyproject.toml")
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
        for marker, label in {"fastapi": "FastAPI", "django": "Django", "flask": "Flask"}.items():
            if marker in content:
                frameworks.append(label)
    return sorted(set(frameworks))


def run_local_validation(root: Path, *, sandbox: str = "local") -> list[dict]:
    commands: list[list[str]] = []
    if shutil.which("gitleaks"):
        commands.append(["gitleaks", "detect", "--source", ".", "--no-git", "--redact", "--exit-code", "1"])
    if shutil.which("ruff") and any(root.rglob("*.py")):
        commands.append(["ruff", "check", "."])
    if (root / "pyproject.toml").exists() and shutil.which("python"):
        commands.append([sys.executable, "-m", "compileall", "-q", "."])
        commands.append([sys.executable, "-m", "pytest", "-q"])
    if (root / "package.json").exists():
        try:
            package = json.loads((root / "package.json").read_text(encoding="utf-8"))
            scripts = package.get("scripts", {})
            manager = "pnpm" if (root / "pnpm-lock.yaml").exists() else "npm"
            if "test" in scripts and shutil.which(manager):
                commands.append([manager, "test"] if manager == "pnpm" else [manager, "test", "--", "--runInBand"])
            if "lint" in scripts and shutil.which(manager):
                commands.append([manager, "lint"])
        except (OSError, json.JSONDecodeError):
            pass
    if (root / "go.mod").exists() and shutil.which("go"):
        commands.append(["go", "test", "./..."])
    if (root / "Cargo.toml").exists() and shutil.which("cargo"):
        commands.append(["cargo", "test", "--quiet"])

    runs = []
    for command in commands[:8]:
        runs.extend(_execute_validation_command(root, command, sandbox=sandbox, kind="validation"))
    return runs


def run_explicit_command(root: Path, command: str, *, sandbox: str, kind: str) -> list[dict]:
    try:
        args = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        return [{"command": command, "status": "failed", "exit_code": None, "duration_ms": 0, "output_summary": f"Invalid command: {exc}", "kind": kind}]
    return _execute_validation_command(root, args, sandbox=sandbox, kind=kind)


def sandbox_capabilities() -> dict:
    microvm_runner = load_config().get("microvm_runner")
    firecracker = shutil.which("firecracker")
    has_kvm = Path("/dev/kvm").exists()
    if os.name == "nt":
        microvm_detail = "Firecracker microVM requires a Linux host with KVM; this Windows host cannot run it directly."
    elif microvm_runner:
        microvm_detail = f"microvm_runner configured: {microvm_runner}"
    elif firecracker and has_kvm:
        microvm_detail = "firecracker and /dev/kvm detected; configure microvm_runner to execute validation commands."
    else:
        microvm_detail = "Firecracker microVM unavailable; install Firecracker on Linux/KVM or configure microvm_runner."
    return {
        "docker_available": shutil.which("docker") is not None,
        "microvm_available": bool(microvm_runner and os.name != "nt"),
        "microvm_runner": microvm_runner,
        "microvm_detail": microvm_detail,
    }


def _execute_validation_command(root: Path, command: list[str], *, sandbox: str, kind: str) -> list[dict]:
    command_text = " ".join(command)
    selected = sandbox
    cfg = load_config()
    if sandbox == "auto":
        selected = "docker" if shutil.which("docker") and cfg.get("audit_image") else "none"
    if selected == "none":
        return [{
            "command": command_text, "status": "skipped", "exit_code": None, "duration_ms": 0,
            "output_summary": "Execution skipped: configure audit_image for Docker or explicitly use --sandbox local.",
            "kind": kind, "sandbox": "none",
        }]

    actual_command = command
    cwd = root
    temp_workspace = None
    if selected == "microvm":
        microvm_runner = cfg.get("microvm_runner")
        if os.name == "nt" or not microvm_runner:
            return [{
                "command": command_text, "status": "skipped", "exit_code": None, "duration_ms": 0,
                "output_summary": sandbox_capabilities()["microvm_detail"],
                "kind": kind, "sandbox": "microvm",
            }]
        temp_workspace = tempfile.TemporaryDirectory(prefix="valicode-microvm-")
        workspace = Path(temp_workspace.name) / "workspace"
        shutil.copytree(root, workspace, ignore=shutil.ignore_patterns(*DEFAULT_IGNORE_DIRS))
        actual_command = [microvm_runner, str(workspace), *command]
        cwd = workspace
    if selected == "docker":
        image = cfg.get("audit_image")
        if not image or not shutil.which("docker"):
            return [{
                "command": command_text, "status": "skipped", "exit_code": None, "duration_ms": 0,
                "output_summary": "Docker sandbox unavailable or audit_image is not configured.",
                "kind": kind, "sandbox": "docker",
            }]
        temp_workspace = tempfile.TemporaryDirectory(prefix="valicode-audit-")
        workspace = Path(temp_workspace.name) / "workspace"
        shutil.copytree(root, workspace, ignore=shutil.ignore_patterns(*DEFAULT_IGNORE_DIRS))
        actual_command = [
            "docker", "run", "--rm", "--network", "none", "--cpus", "2", "--memory", "2g",
            "--pids-limit", "256", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "-v", f"{workspace}:/workspace", "-w", "/workspace", image, *command,
        ]
        cwd = workspace

    try:
        started = time.perf_counter()
        try:
            result = subprocess.run(actual_command, cwd=cwd, capture_output=True, text=True, timeout=180, check=False)
            output = redact_local_output((result.stdout or "") + "\n" + (result.stderr or ""))
            return [{
                "command": command_text,
                "status": "passed" if result.returncode == 0 else "failed",
                "exit_code": result.returncode,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "output_summary": output[-4000:],
                "kind": kind, "sandbox": selected,
            }]
        except subprocess.TimeoutExpired:
            return [{
                "command": command_text, "status": "failed", "exit_code": None,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "output_summary": "Command timed out after 180 seconds.",
                "kind": kind, "sandbox": selected,
            }]
    finally:
        if temp_workspace is not None:
            temp_workspace.cleanup()


def redact_local_output(output: str) -> str:
    import re
    output = re.sub(r"(?i)(api[_-]?key|secret|token|password)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", output)
    output = re.sub(r"(?i)(sk-|ghp_|github_pat_)[A-Za-z0-9_-]{12,}", "[REDACTED]", output)
    return output


def validate_suggested_fixes(root: Path, result: dict, api_key: str, *, sandbox: str) -> list[dict]:
    validations = []
    analysis_id = result.get("id")
    if not analysis_id or not shutil.which("git"):
        return [{"status": "skipped", "reason": "Analysis id or git executable is unavailable."}]
    for issue in [item for item in result.get("issues", []) if item.get("fix_patch") and item.get("id")][:20]:
        patch = issue["fix_patch"]
        patch_hash = hashlib.sha256(patch.encode()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="valicode-fix-") as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            shutil.copytree(root, workspace, ignore=shutil.ignore_patterns(*DEFAULT_IGNORE_DIRS))
            patch_file = Path(temp_dir) / "fix.patch"
            patch_file.write_text(patch, encoding="utf-8")
            check = subprocess.run(["git", "apply", "--check", str(patch_file)], cwd=workspace, capture_output=True, text=True, check=False)
            syntax_valid = check.returncode == 0
            test_runs = []
            if syntax_valid:
                applied = subprocess.run(["git", "apply", str(patch_file)], cwd=workspace, capture_output=True, text=True, check=False)
                syntax_valid = applied.returncode == 0
                if syntax_valid:
                    test_runs = run_local_validation(workspace, sandbox=sandbox)
            executed = [run for run in test_runs if run.get("status") in {"passed", "failed"}]
            tests_passed = bool(executed) and all(run.get("status") == "passed" for run in executed)
            status_value = "validated" if syntax_valid and tests_passed else "syntax_valid" if syntax_valid else "rejected"
            summary = "Patch applies cleanly. " if syntax_valid else redact_local_output(check.stderr or "Patch does not apply cleanly.")
            if test_runs:
                summary += "; ".join(f"{run.get('command')}={run.get('status')}" for run in test_runs)
            payload = {
                "issue_id": issue["id"], "patch_hash": patch_hash, "status": status_value,
                "syntax_valid": syntax_valid, "tests_passed": tests_passed if executed else None,
                "validation_summary": summary[:2000],
            }
            try:
                response = httpx.post(
                    f"{get_api_base()}/analyses/{analysis_id}/fix-validation",
                    headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                    json=payload,
                    timeout=30,
                )
                response.raise_for_status()
                payload["recorded"] = True
            except httpx.HTTPError:
                payload["recorded"] = False
            validations.append(payload)
    return validations


def _get_diff_content(path, diff_file, staged, pr, repo, cfg) -> str | None:
    if staged:
        result = subprocess.run(["git", "diff", "--cached"], capture_output=True, text=True, check=False)
        return result.stdout or None
    if diff_file:
        return Path(diff_file).read_text()
    if path:
        path_obj = Path(path)
        if path_obj.is_dir():
            click.echo("Error: Directories must be scanned with valicode scan.", err=True)
            sys.exit(1)
        content = path_obj.read_text()
        return f"+++ b/{path}\n" + "\n".join(f"+{line}" for line in content.splitlines())
    if pr and repo:
        token = cfg.get("github_token")
        headers = {"Accept": "application/vnd.github.diff"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = httpx.get(f"https://api.github.com/repos/{repo}/pulls/{pr}", headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.text
    return None


def collect_workspace_files(
    root: Path,
    *,
    max_total_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    include_lockfiles: bool = False,
) -> tuple[list[dict], list[dict]]:
    ignore_patterns = load_valicodeignore(root)
    files: list[dict] = []
    ignored: list[dict] = []
    total = 0

    for current_root, dirnames, filenames in os.walk(root):
        current_path = Path(current_root)
        rel_dir = current_path.relative_to(root).as_posix()

        kept_dirs = []
        for dirname in dirnames:
            rel_path = dirname if rel_dir == "." else f"{rel_dir}/{dirname}"
            if dirname in DEFAULT_IGNORE_DIRS or matches_ignore(rel_path, ignore_patterns):
                ignored.append({"path": rel_path, "reason": "ignored_dir"})
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            file_path = current_path / filename
            rel_path = file_path.relative_to(root).as_posix()
            reason = should_ignore_file(file_path, rel_path, ignore_patterns, include_lockfiles, max_file_bytes)
            if reason:
                ignored.append({"path": rel_path, "reason": reason})
                continue
            size = file_path.stat().st_size
            if total + size > max_total_bytes:
                ignored.append({"path": rel_path, "reason": "max_upload_exceeded"})
                continue
            total += size
            files.append({"path": rel_path, "size": size})

    return sorted(files, key=lambda item: item["path"]), ignored


def load_valicodeignore(root: Path) -> list[str]:
    ignore_file = root / ".valicodeignore"
    if not ignore_file.exists():
        return []
    patterns = []
    for line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped)
    return patterns


def matches_ignore(rel_path: str, patterns: list[str]) -> bool:
    normalized = rel_path.strip("/")
    for pattern in patterns:
        normalized_pattern = pattern.strip("/")
        if fnmatch.fnmatch(normalized, normalized_pattern) or fnmatch.fnmatch(normalized, f"{normalized_pattern}/*"):
            return True
    return False


def should_ignore_file(
    file_path: Path,
    rel_path: str,
    ignore_patterns: list[str],
    include_lockfiles: bool,
    max_file_bytes: int,
) -> str | None:
    name = file_path.name
    suffix = file_path.suffix.lower()
    if matches_ignore(rel_path, ignore_patterns):
        return "valicodeignore"
    if name == ".valicodeignore":
        return "valicodeignore"
    if name.startswith(".env") and name not in {".env.example", ".env.sample"}:
        return "env_file"
    if suffix in DEFAULT_IGNORE_EXTENSIONS:
        return "binary_or_asset"
    if name in LOCKFILE_NAMES and not include_lockfiles:
        return "lockfile"
    if file_path.stat().st_size > max_file_bytes:
        return "max_file_size"
    if is_binary_file(file_path):
        return "binary"
    if suffix and suffix not in SOURCE_EXTENSIONS and name not in {"Dockerfile", "Makefile", ".env.example", ".env.sample"}:
        return "unsupported_extension"
    return None


def is_binary_file(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return True
    return b"\x00" in chunk


def workspace_files_to_diff(root: Path, files: list[dict]) -> str:
    parts = []
    for item in files:
        rel_path = item["path"]
        file_path = root / rel_path
        content = file_path.read_text(encoding="utf-8", errors="replace")
        parts.append(f"diff --git a/{rel_path} b/{rel_path}")
        parts.append("--- /dev/null")
        parts.append(f"+++ b/{rel_path}")
        parts.append("@@ -0,0 +1,0 @@")
        parts.extend(f"+{line}" for line in content.splitlines())
    return "\n".join(parts) + "\n"


def _print_scan_manifest(files: list[dict], ignored: list[dict], manifest: dict) -> None:
    click.echo("Valicode workspace scan")
    click.echo(f"{manifest['files_scanned']} file(s) / {manifest['bytes_scanned']} bytes / {manifest['ignored_count']} ignored")
    click.echo(f"{'Path':60} Size")
    for item in files[:100]:
        click.echo(f"{item['path'][:60]:60} {item['size']}")
    if len(files) > 100:
        click.echo(f"... {len(files) - 100} more file(s)")
    ignored_reasons: dict[str, int] = {}
    for item in ignored:
        ignored_reasons[item["reason"]] = ignored_reasons.get(item["reason"], 0) + 1
    if ignored_reasons:
        click.echo("Ignored: " + ", ".join(f"{reason}={count}" for reason, count in sorted(ignored_reasons.items())))


def _print_table(result: dict) -> None:
    score = result.get("score", 0)
    issues = result.get("issues", [])
    click.echo("Valicode")
    click.echo(f"Score: {score}/100 / {len(issues)} issue(s) found / {result.get('files_analyzed', 0)} file(s) analyzed")
    coverage = result.get("coverage") or {}
    gate = result.get("merge_gate") or {}
    if coverage:
        click.echo(
            f"Coverage: {coverage.get('coverage_percent', 0)}% "
            f"({coverage.get('analyzed_files', 0)}/{coverage.get('eligible_files', 0)} files)"
        )
    click.echo(f"Merge gate: {str(gate.get('status', 'unknown')).upper()} / blockers: {gate.get('blocker_count', 0)}")
    runs = result.get("analysis_runs") or []
    if runs:
        click.echo("Checks: " + ", ".join(
            f"{run.get('tool')}={run.get('status')} ({run.get('findings_count', 0)} findings, {run.get('duration_ms', 0)}ms)"
            for run in runs
        ))
    test_runs = result.get("test_runs") or []
    if test_runs:
        click.echo("Local validation: " + ", ".join(f"{run.get('command')}={run.get('status')}" for run in test_runs))
    if result.get("summary"):
        click.echo(result.get("summary", ""))
    fingerprint = result.get("ai_fingerprint") or {}
    if fingerprint.get("any_ai_detected"):
        confidence = round(float(fingerprint.get("dominant_confidence") or 0) * 100)
        click.echo(f"AI: {fingerprint.get('dominant_tool', 'unknown')} ({confidence}% confidence)")
    if not issues:
        click.echo("No issues detected.")
        return
    click.echo(f"{'Severity':10} {'Category':14} {'File':30} {'Line':6} Issue")
    order = ["critical", "high", "medium", "low", "info"]
    for issue in sorted(issues, key=lambda item: order.index(item.get("severity", "info"))):
        sev = issue.get("severity", "info")
        click.echo(
            f"{sev.upper():10} "
            f"{issue.get('category', '')[:14]:14} "
            f"{issue.get('file_path', '')[-30:]:30} "
            f"{str(issue.get('line_start', '')):6} "
            f"{issue.get('title', '')}"
        )
        confidence = round(float(issue.get("confidence") or 0) * 100)
        flags = []
        if issue.get("is_new"):
            flags.append("new")
        if issue.get("blocks_merge"):
            flags.append("blocks merge")
        click.echo(f"  Confidence: {confidence}% / validation: {issue.get('validation_status', 'unknown')} / {', '.join(flags) or 'existing risk'}")
        if issue.get("impact"):
            click.echo(f"  Impact: {issue['impact']}")
        if issue.get("code_snippet"):
            click.echo("  Evidence: " + str(issue["code_snippet"]).replace("\n", " | ")[:300])
        if issue.get("suggestion"):
            click.echo(f"  Fix: {issue['suggestion']}")
        if issue.get("remediation_test"):
            click.echo(f"  Regression test: {issue['remediation_test']}")

    breakdown = result.get("score_breakdown") or []
    if breakdown:
        click.echo("\nScore breakdown:")
        for item in breakdown[:20]:
            click.echo(f"  -{item.get('penalty', 0):>5}: {item.get('reason', '')}")


def _to_sarif(result: dict) -> str:
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Valicode", "rules": []}},
                "results": [],
            }
        ],
    }
    for issue in result.get("issues", []):
        sarif["runs"][0]["results"].append(
            {
                "ruleId": issue.get("rule_id") or issue.get("category", "aov"),
                "level": "error" if issue.get("severity") in ("critical", "high") else "warning",
                "message": {"text": issue.get("title", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": issue.get("file_path", "")},
                            "region": {"startLine": issue.get("line_start") or 1},
                        }
                    }
                ],
            }
        )
    return json.dumps(sarif, indent=2)


def print_result(result: dict, output: str) -> None:
    if output == "json":
        click.echo(json.dumps(result, indent=2, default=str))
    elif output == "sarif":
        click.echo(_to_sarif(result))
    elif output == "markdown":
        click.echo(_to_markdown(result))
    elif output == "html":
        click.echo(_to_html(result))
    elif output == "junit":
        click.echo(_to_junit(result))
    elif output == "summary":
        click.echo(_to_summary(result))
    elif output == "mermaid":
        click.echo(_to_mermaid(result))
    elif output == "chat":
        click.echo(_to_chat_alert(result))
    else:
        _print_table(result)


def print_analysis_links(result: dict) -> None:
    links = result.get("links") or {}
    if not links:
        return
    click.echo("")
    if links.get("dashboard"):
        click.echo(f"Dashboard: {links['dashboard']}")
    if links.get("pdf"):
        click.echo(f"PDF: {links['pdf']}")
    if links.get("sarif"):
        click.echo(f"SARIF: {links['sarif']}")


def save_report_bundle(output_dir: Path, result: dict) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "findings.json": json.dumps(result, indent=2, default=str),
        "findings.sarif": _to_sarif(result),
        "summary.md": _to_markdown(result),
        "report.html": _to_html(result),
        "report.pdf": _to_pdf_bytes(result),
        "chat-alert.txt": _to_chat_alert(result),
        "junit.xml": _to_junit(result),
        "summary.txt": _to_summary(result),
        "architecture.mmd": _to_mermaid(result, graph="architecture"),
        "dataflow.mmd": _to_mermaid(result, graph="dataflow"),
        "score-breakdown.json": json.dumps(result.get("score_breakdown") or [], indent=2, default=str),
    }
    written = []
    for name, content in files.items():
        path = output_dir / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def _to_summary(result: dict) -> str:
    issues = result.get("issues", [])
    lines = [
        f"Valicode score: {result.get('score', 0)}/100",
        f"Issues: {len(issues)}",
        f"Files analyzed: {result.get('files_analyzed', 0)}",
        f"Merge gate: {(result.get('merge_gate') or {}).get('status', 'unknown')}",
    ]
    if result.get("summary"):
        lines.append("")
        lines.append(str(result["summary"]))
    by_severity: dict[str, int] = {}
    for issue in issues:
        severity = issue.get("severity", "info")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    if by_severity:
        lines.append("")
        lines.append("By severity: " + ", ".join(f"{key}={value}" for key, value in sorted(by_severity.items())))
    return "\n".join(lines)


def _to_chat_alert(result: dict) -> str:
    issues = result.get("issues", [])
    blockers = [
        issue for issue in issues
        if issue.get("severity") in {"critical", "high"} or issue.get("blocks_merge")
    ]
    shown = blockers[:10] if blockers else issues[:10]
    score = result.get("score", 0)
    gate = (result.get("merge_gate") or {}).get("status", "unknown")
    severity_counts: dict[str, int] = {}
    for issue in issues:
        severity = issue.get("severity", "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if not issues:
        return "\n".join([
            "Valicode alert",
            f"Score: {score}/100",
            "No issues detected.",
        ])

    lines = [
        "Valicode alert",
        f"Score: {score}/100 | Merge gate: {str(gate).upper()} | Issues: {len(issues)}",
        "Severity: " + ", ".join(f"{key}={severity_counts[key]}" for key in ["critical", "high", "medium", "low", "info"] if key in severity_counts),
        "",
        "Errors to fix:",
    ]
    for index, issue in enumerate(shown, start=1):
        location = _issue_location(issue)
        confidence = round(float(issue.get("confidence") or 0) * 100)
        lines.append(f"{index}. [{str(issue.get('severity', 'info')).upper()}] {issue.get('title', 'Issue')}")
        lines.append(f"   Where: {location}")
        if issue.get("category"):
            lines.append(f"   Type: {issue.get('category')}")
        if confidence:
            lines.append(f"   Confidence: {confidence}%")
        if issue.get("impact"):
            lines.extend(f"   Impact: {line}" for line in _wrap_pdf_text(str(issue["impact"]), width=88))
        if issue.get("suggestion"):
            lines.extend(f"   Fix: {line}" for line in _wrap_pdf_text(str(issue["suggestion"]), width=88))
        elif issue.get("remediation_test"):
            lines.extend(f"   Test: {line}" for line in _wrap_pdf_text(str(issue["remediation_test"]), width=88))
        lines.append("")
    if len(issues) > len(shown):
        lines.append(f"... {len(issues) - len(shown)} more issue(s). Open report.pdf or findings.json for the full list.")
    if result.get("id"):
        lines.append(f"Analysis ID: {result['id']}")
    return "\n".join(lines).strip()


def _issue_location(issue: dict) -> str:
    path = issue.get("file_path") or issue.get("path") or "unknown file"
    line = issue.get("line_start") or issue.get("line") or issue.get("start_line")
    if line:
        return f"{path}:{line}"
    return str(path)


def _to_markdown(result: dict) -> str:
    issues = result.get("issues", [])
    lines = [
        "# Valicode Audit Report",
        "",
        f"- Score: `{result.get('score', 0)}/100`",
        f"- Issues: `{len(issues)}`",
        f"- Files analyzed: `{result.get('files_analyzed', 0)}`",
        f"- Merge gate: `{(result.get('merge_gate') or {}).get('status', 'unknown')}`",
    ]
    if result.get("summary"):
        lines.extend(["", "## Summary", "", str(result["summary"])])
    if result.get("score_breakdown"):
        lines.extend(["", "## Score Breakdown", ""])
        for item in result["score_breakdown"][:30]:
            lines.append(f"- `-{item.get('penalty', 0)}` {item.get('reason', '')}")
    if issues:
        lines.extend(["", "## Findings", ""])
        for issue in issues:
            location = f"{issue.get('file_path', '')}:{issue.get('line_start', '')}".rstrip(":")
            lines.extend([
                f"### {issue.get('title', 'Issue')}",
                "",
                f"- Severity: `{issue.get('severity', 'info')}`",
                f"- Category: `{issue.get('category', 'logic')}`",
                f"- Location: `{location}`",
                f"- Confidence: `{round(float(issue.get('confidence') or 0) * 100)}%`",
            ])
            if issue.get("description"):
                lines.append(f"- Description: {issue['description']}")
            if issue.get("suggestion"):
                lines.append(f"- Fix: {issue['suggestion']}")
            if issue.get("remediation_test"):
                lines.append(f"- Regression test: {issue['remediation_test']}")
            if issue.get("code_snippet"):
                lines.extend(["", "```", str(issue["code_snippet"])[:1200], "```", ""])
    return "\n".join(lines)


def _to_html(result: dict) -> str:
    issue_rows = []
    for issue in result.get("issues", []):
        issue_rows.append(
            "<tr>"
            f"<td>{html.escape(str(issue.get('severity', 'info')))}</td>"
            f"<td>{html.escape(str(issue.get('category', 'logic')))}</td>"
            f"<td>{html.escape(str(issue.get('file_path', '')))}:{html.escape(str(issue.get('line_start', '')))}</td>"
            f"<td>{html.escape(str(issue.get('title', '')))}</td>"
            f"<td>{html.escape(str(issue.get('suggestion', '')))}</td>"
            "</tr>"
        )
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Valicode Audit Report</title>
  <style>
    body { font-family: Inter, Arial, sans-serif; margin: 32px; color: #18181b; }
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { border-bottom: 1px solid #e4e4e7; padding: 8px; text-align: left; vertical-align: top; }
    .score { font-size: 40px; font-weight: 700; }
    .muted { color: #71717a; }
  </style>
</head>
<body>
  <h1>Valicode Audit Report</h1>
  <div class="score">""" + html.escape(str(result.get("score", 0))) + """/100</div>
  <p class="muted">""" + html.escape(str(len(result.get("issues", [])))) + """ issue(s), """ + html.escape(str(result.get("files_analyzed", 0))) + """ file(s) analyzed.</p>
  <p>""" + html.escape(str(result.get("summary", ""))) + """</p>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Location</th><th>Issue</th><th>Fix</th></tr></thead>
    <tbody>""" + "\n".join(issue_rows) + """</tbody>
  </table>
</body>
</html>
"""


def _to_junit(result: dict) -> str:
    issues = result.get("issues", [])
    cases = []
    for issue in issues:
        name = html.escape(str(issue.get("rule_id") or issue.get("title") or "valicode-issue"))
        message = html.escape(str(issue.get("title", "")))
        details = html.escape(f"{issue.get('file_path', '')}:{issue.get('line_start', '')} {issue.get('description', '')}")
        cases.append(f'<testcase classname="Valicode" name="{name}"><failure message="{message}">{details}</failure></testcase>')
    return f'<?xml version="1.0" encoding="UTF-8"?><testsuite name="Valicode" tests="{len(issues)}" failures="{len(issues)}">' + "".join(cases) + "</testsuite>"


def _to_pdf_bytes(result: dict) -> bytes:
    lines = _pdf_report_lines(result)
    pages = [lines[index:index + 46] for index in range(0, len(lines), 46)] or [[]]
    objects: list[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    font_obj = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_refs: list[int] = []
    page_payloads: list[tuple[int, bytes]] = []
    pages_obj = 0
    for page_number, page_lines in enumerate(pages, start=1):
        content = _pdf_page_stream(page_lines, page_number, len(pages))
        content_obj = add_object(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")
        page_ref = add_object(b"")
        page_refs.append(page_ref)
        page_payloads.append((page_ref, b"<< /Type /Page /Parent {PAGES} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 " + str(font_obj).encode("ascii") + b" 0 R >> >> /Contents " + str(content_obj).encode("ascii") + b" 0 R >>"))
    pages_obj = add_object(b"<< /Type /Pages /Kids [" + b" ".join(f"{ref} 0 R".encode("ascii") for ref in page_refs) + b"] /Count " + str(len(page_refs)).encode("ascii") + b" >>")
    for page_ref, payload in page_payloads:
        objects[page_ref - 1] = payload.replace(b"{PAGES}", str(pages_obj).encode("ascii"))
    catalog_obj = add_object(b"<< /Type /Catalog /Pages " + str(pages_obj).encode("ascii") + b" 0 R >>")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _pdf_report_lines(result: dict) -> list[str]:
    issues = result.get("issues", [])
    lines = [
        "Valicode Audit Report",
        "",
        f"Score: {result.get('score', 0)}/100",
        f"Issues: {len(issues)}",
        f"Files analyzed: {result.get('files_analyzed', 0)}",
        f"Merge gate: {(result.get('merge_gate') or {}).get('status', 'unknown')}",
        "",
    ]
    if result.get("summary"):
        lines.extend(_wrap_pdf_text(f"Summary: {result['summary']}"))
        lines.append("")
    if result.get("workspace_manifest"):
        manifest = result["workspace_manifest"]
        lines.extend([
            "Workspace",
            f"Files scanned: {manifest.get('files_scanned', 0)}",
            f"Bytes scanned: {manifest.get('bytes_scanned', 0)}",
            f"Ignored: {manifest.get('ignored_count', 0)}",
            "",
        ])
    if result.get("score_breakdown"):
        lines.append("Score Breakdown")
        for item in result["score_breakdown"][:20]:
            lines.extend(_wrap_pdf_text(f"-{item.get('penalty', 0)}: {item.get('reason', '')}"))
        lines.append("")
    if issues:
        lines.append("Findings")
        for index, issue in enumerate(issues[:80], start=1):
            location = f"{issue.get('file_path', '')}:{issue.get('line_start', '')}".rstrip(":")
            header = f"{index}. [{str(issue.get('severity', 'info')).upper()}] {issue.get('title', 'Issue')}"
            lines.extend(_wrap_pdf_text(header))
            lines.extend(_wrap_pdf_text(f"Location: {location}"))
            if issue.get("suggestion"):
                lines.extend(_wrap_pdf_text(f"Fix: {issue['suggestion']}"))
            lines.append("")
        if len(issues) > 80:
            lines.append(f"... {len(issues) - 80} additional finding(s) omitted from PDF. See findings.json for full data.")
    return lines


def _pdf_page_stream(lines: list[str], page_number: int, page_count: int) -> bytes:
    commands = ["BT", "/F1 11 Tf", "50 742 Td", "14 TL"]
    for line in lines:
        commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("T*")
    commands.extend(["/F1 9 Tf", f"0 -18 Td", f"(Page {page_number} of {page_count}) Tj", "ET"])
    return "\n".join(commands).encode("latin-1", errors="replace")


def _wrap_pdf_text(value: str, width: int = 96) -> list[str]:
    words = str(value).replace("\n", " ").split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def _pdf_escape(value: str) -> str:
    text = str(value).encode("latin-1", errors="replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _to_mermaid(result: dict, graph: str = "architecture") -> str:
    if graph == "dataflow":
        dataflow = result.get("dataflow") or result.get("data_flow") or {}
        edges = dataflow.get("edges") if isinstance(dataflow, dict) else None
        if edges:
            lines = ["flowchart LR"]
            for edge in edges[:80]:
                source = _mermaid_node(edge.get("source") or edge.get("from") or "input")
                target = _mermaid_node(edge.get("target") or edge.get("to") or "output")
                label = str(edge.get("label") or edge.get("type") or "")
                lines.append(f"  {source} -->|{_mermaid_label(label)}| {target}")
            return "\n".join(lines)
    graph_data = result.get("architecture_graph") or result.get("architecture") or {}
    if isinstance(graph_data, dict) and graph_data.get("edges"):
        lines = ["flowchart TD"]
        for edge in graph_data["edges"][:80]:
            source = _mermaid_node(edge.get("source") or edge.get("from") or "component")
            target = _mermaid_node(edge.get("target") or edge.get("to") or "dependency")
            lines.append(f"  {source} --> {target}")
        return "\n".join(lines)
    files = sorted({issue.get("file_path") for issue in result.get("issues", []) if issue.get("file_path")})
    lines = ["flowchart TD", "  audit[Valicode audit]"]
    for path in files[:40]:
        lines.append(f"  audit --> {_mermaid_node(path)}")
    return "\n".join(lines)


def _mermaid_node(value: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in str(value))[:60].strip("_") or "node"
    label = _mermaid_label(str(value)[:80])
    return f'{safe}["{label}"]'


def _mermaid_label(value: str) -> str:
    return str(value).replace('"', "'").replace("\n", " ")


def api_request(method: str, path: str, *, json_body: dict | None = None, params: dict | None = None, raw: bool = False):
    cfg = load_config()
    api_key = cfg.get("api_key")
    if not api_key:
        click.echo("Error: No API key configured. Run valicode login first.", err=True)
        sys.exit(1)
    url = f"{get_api_base()}/{path.lstrip('/')}"
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    try:
        response = httpx.request(method, url, headers=headers, json=json_body, params=_clean_params(params), timeout=60)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        message = _response_error_message(exc.response)
        click.echo(f"API error {exc.response.status_code}: {message}", err=True)
        sys.exit(1)
    except httpx.HTTPError as exc:
        click.echo(f"API request failed: {exc}", err=True)
        sys.exit(1)
    if raw:
        return response
    if not response.content:
        return {}
    return response.json()


def _clean_params(params: dict | None) -> dict | None:
    if not params:
        return None
    return {key: value for key, value in params.items() if value is not None}


def _response_error_message(response: httpx.Response) -> str:
    try:
        data = response.json()
        return str(data.get("message") or data.get("detail") or data.get("error") or data)
    except ValueError:
        return response.text[:500]


def print_payload(data, *, json_output: bool = False) -> None:
    if json_output:
        click.echo(json.dumps(data, indent=2, default=str))
        return
    if isinstance(data, dict):
        _print_dict_payload(data)
    elif isinstance(data, list):
        _print_rows(data)
    else:
        click.echo(str(data))


def _print_dict_payload(data: dict) -> None:
    for key, value in data.items():
        if isinstance(value, list):
            click.echo(f"{key}:")
            _print_rows(value)
        elif isinstance(value, dict):
            click.echo(f"{key}:")
            for child_key, child_value in value.items():
                click.echo(f"  {child_key}: {_format_cell(child_value)}")
        else:
            click.echo(f"{key}: {_format_cell(value)}")


def _print_rows(rows: list[dict]) -> None:
    if not rows:
        click.echo("No records.")
        return
    if not all(isinstance(row, dict) for row in rows):
        for row in rows:
            click.echo(_format_cell(row))
        return
    columns = _select_columns(rows)
    widths = {column: min(36, max(len(column), *(len(_format_cell(row.get(column))) for row in rows[:50]))) for column in columns}
    click.echo("  ".join(column[:widths[column]].ljust(widths[column]) for column in columns))
    for row in rows:
        click.echo("  ".join(_format_cell(row.get(column))[:widths[column]].ljust(widths[column]) for column in columns))


def _select_columns(rows: list[dict]) -> list[str]:
    preferred = [
        "id", "email", "name", "full_name", "repository", "plan", "role", "status", "score",
        "severity", "category", "title", "created_at", "last_used_at", "requests", "errors",
    ]
    present = []
    keys = set().union(*(row.keys() for row in rows))
    for key in preferred:
        if key in keys:
            present.append(key)
    for key in sorted(keys):
        if key not in present and len(present) < 8:
            present.append(key)
    return present[:8]


def _format_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)[:120]
    return str(value)


@cli.command()
def login():
    """Authenticate with your Valicode account."""
    api_key = click.prompt("Paste your API key", hide_input=True)
    cfg = load_config()
    cfg["api_key"] = api_key.strip()
    save_config(cfg)
    click.echo("API key saved.")


@cli.group()
def config():
    """Manage local CLI configuration."""


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)
    click.echo(f"Saved {key}.")


@cli.command()
@click.option("--json", "json_output", is_flag=True, help="Print raw JSON")
def dashboard(json_output: bool):
    """Show the same operational overview as the web dashboard."""
    data = api_request("GET", "dashboard/overview")
    if json_output:
        print_payload(data, json_output=True)
        return
    latest = data.get("latest_analysis") or {}
    quota = data.get("quota") or {}
    click.echo("Valicode dashboard")
    click.echo(f"Current score: {latest.get('score', 'none')}")
    click.echo(f"Clean streak: {data.get('streak_days', 0)} day(s)")
    click.echo(f"This week: {data.get('week_avg', 'n/a')} / previous: {data.get('prev_week_avg', 'n/a')}")
    click.echo(f"Usage: {quota.get('used', 0)} / {quota.get('limit', 'unlimited')} ({quota.get('plan', 'unknown')})")
    if data.get("action_required"):
        click.echo(f"Action required: {data['action_required'].get('message')}")
    if data.get("repos_needing_attention"):
        click.echo("\nRepos needing attention:")
        _print_rows(data["repos_needing_attention"])


@cli.group("analyses")
def analyses_group():
    """Browse analysis history and reports."""


@analyses_group.command("list")
@click.option("--limit", default=20, show_default=True)
@click.option("--offset", default=0, show_default=True)
@click.option("--json", "json_output", is_flag=True)
def analyses_list(limit: int, offset: int, json_output: bool):
    data = api_request("GET", "analyses", params={"limit": limit, "offset": offset})
    print_payload(data if json_output else data.get("analyses", data), json_output=json_output)


@analyses_group.command("overview")
@click.option("--json", "json_output", is_flag=True)
def analyses_overview(json_output: bool):
    print_payload(api_request("GET", "analyses/overview"), json_output=json_output)


@analyses_group.command("show")
@click.argument("analysis_id")
@click.option("--json", "json_output", is_flag=True)
def analyses_show(analysis_id: str, json_output: bool):
    print_payload(api_request("GET", f"analyses/{analysis_id}"), json_output=json_output)


@analyses_group.command("report")
@click.argument("analysis_id")
@click.option("--json", "json_output", is_flag=True)
def analyses_report(analysis_id: str, json_output: bool):
    print_payload(api_request("GET", f"analyses/{analysis_id}/report"), json_output=json_output)


@analyses_group.command("compliance")
@click.argument("analysis_id")
@click.option("--json", "json_output", is_flag=True)
def analyses_compliance(analysis_id: str, json_output: bool):
    print_payload(api_request("GET", f"analyses/{analysis_id}/compliance"), json_output=json_output)


@analyses_group.command("autofix")
@click.argument("analysis_id")
@click.option("--json", "json_output", is_flag=True)
def analyses_autofix(analysis_id: str, json_output: bool):
    print_payload(api_request("POST", f"analyses/{analysis_id}/autofix"), json_output=json_output)


@cli.group("repos")
def repos_group():
    """Manage repositories and repository-level rule settings."""


@repos_group.command("list")
@click.option("--json", "json_output", is_flag=True)
def repos_list(json_output: bool):
    data = api_request("GET", "repositories")
    print_payload(data if json_output else data.get("repositories", data), json_output=json_output)


@repos_group.command("show")
@click.argument("repository_id")
@click.option("--json", "json_output", is_flag=True)
def repos_show(repository_id: str, json_output: bool):
    print_payload(api_request("GET", f"repositories/{repository_id}"), json_output=json_output)


@repos_group.command("add")
@click.argument("full_name")
@click.option("--github-repo-id", required=True, help="GitHub numeric repository id")
@click.option("--default-branch", default="main", show_default=True)
@click.option("--json", "json_output", is_flag=True)
def repos_add(full_name: str, github_repo_id: str, default_branch: str, json_output: bool):
    payload = {"full_name": full_name, "github_repo_id": int(github_repo_id), "default_branch": default_branch}
    print_payload(api_request("POST", "repositories", json_body=payload), json_output=json_output)


@repos_group.command("rules")
@click.argument("repository_id", required=False)
@click.option("--json", "json_output", is_flag=True)
def repos_rules(repository_id: str | None, json_output: bool):
    data = api_request("GET", "rules", params={"repository_id": repository_id})
    print_payload(data if json_output else data.get("rules", data), json_output=json_output)


@repos_group.command("set-rules")
@click.argument("repository_id")
@click.option("--disable", "disabled_rules", multiple=True, help="Rule id to disable. Repeat for multiple rules.")
@click.option("--json", "json_output", is_flag=True)
def repos_set_rules(repository_id: str, disabled_rules: tuple[str, ...], json_output: bool):
    payload = {"disabled_rules": list(disabled_rules)}
    print_payload(api_request("PATCH", f"repositories/{repository_id}/rules", json_body=payload), json_output=json_output)


@cli.group("issues")
def issues_group():
    """List and triage open findings."""


@issues_group.command("list")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--limit", default=100, show_default=True)
@click.option("--json", "json_output", is_flag=True)
def issues_list(severity: str | None, limit: int, json_output: bool):
    data = api_request("GET", "account/issues", params={"severity": severity, "limit": limit})
    print_payload(data if json_output else data.get("issues", data), json_output=json_output)


@issues_group.command("feedback")
@click.argument("analysis_id")
@click.argument("issue_id")
@click.option("--value", required=True, type=click.Choice(["confirmed", "false_positive", "not_sure"]))
@click.option("--comment", default="")
@click.option("--json", "json_output", is_flag=True)
def issues_feedback(analysis_id: str, issue_id: str, value: str, comment: str, json_output: bool):
    payload = {"feedback": value, "comment": comment}
    print_payload(api_request("POST", f"analyses/{analysis_id}/issues/{issue_id}/feedback", json_body=payload), json_output=json_output)


@issues_group.command("status")
@click.argument("analysis_id")
@click.argument("issue_id")
@click.argument("status", type=click.Choice(["open", "confirmed", "false_positive", "fixed", "ignored", "reopened"]))
@click.option("--json", "json_output", is_flag=True)
def issues_status(analysis_id: str, issue_id: str, status: str, json_output: bool):
    payload = {"status": status}
    print_payload(api_request("PATCH", f"analyses/{analysis_id}/issues/{issue_id}/status", json_body=payload), json_output=json_output)


@cli.group("keys")
def keys_group():
    """Manage API keys."""


@keys_group.command("list")
@click.option("--json", "json_output", is_flag=True)
def keys_list(json_output: bool):
    data = api_request("GET", "api-keys")
    print_payload(data if json_output else data.get("keys", data), json_output=json_output)


@keys_group.command("create")
@click.argument("label")
@click.option("--expires-in-days", type=int)
@click.option("--json", "json_output", is_flag=True)
def keys_create(label: str, expires_in_days: int | None, json_output: bool):
    payload = {"label": label, "expires_in_days": expires_in_days}
    data = api_request("POST", "api-keys", json_body=payload)
    if json_output:
        print_payload(data, json_output=True)
        return
    click.echo("API key created. Copy it now; it will not be shown again.")
    click.echo(data.get("raw_key") or data.get("api_key", ""))


@keys_group.command("revoke")
@click.argument("key_id")
@click.option("--json", "json_output", is_flag=True)
def keys_revoke(key_id: str, json_output: bool):
    print_payload(api_request("DELETE", f"api-keys/{key_id}"), json_output=json_output)


@cli.command("usage")
@click.option("--json", "json_output", is_flag=True)
def usage_command(json_output: bool):
    """Show quota and recent API usage."""
    print_payload(api_request("GET", "account/usage"), json_output=json_output)


@cli.group("billing")
def billing_group():
    """Manage plan and billing links."""


@billing_group.command("summary")
@click.option("--json", "json_output", is_flag=True)
def billing_summary_command(json_output: bool):
    print_payload(api_request("GET", "billing"), json_output=json_output)


@billing_group.command("checkout")
@click.argument("plan", type=click.Choice(["pro", "team", "enterprise"]))
@click.option("--json", "json_output", is_flag=True)
def billing_checkout(plan: str, json_output: bool):
    print_payload(api_request("POST", f"billing/checkout/{plan}"), json_output=json_output)


@billing_group.command("portal")
@click.option("--json", "json_output", is_flag=True)
def billing_portal(json_output: bool):
    print_payload(api_request("POST", "billing/portal"), json_output=json_output)


@cli.group("integrations")
def integrations_group():
    """Manage GitHub, Slack, email digest, and CI integrations."""


@integrations_group.command("status")
@click.option("--json", "json_output", is_flag=True)
def integrations_status(json_output: bool):
    print_payload(api_request("GET", "dashboard/integrations"), json_output=json_output)


@integrations_group.command("slack-set")
@click.argument("webhook_url")
@click.option("--json", "json_output", is_flag=True)
def integrations_slack_set(webhook_url: str, json_output: bool):
    print_payload(api_request("PATCH", "dashboard/integrations", json_body={"slack_webhook_url": webhook_url}), json_output=json_output)


@integrations_group.command("slack-clear")
@click.option("--json", "json_output", is_flag=True)
def integrations_slack_clear(json_output: bool):
    print_payload(api_request("PATCH", "dashboard/integrations", json_body={"slack_webhook_url": ""}), json_output=json_output)


@integrations_group.command("slack-test")
@click.option("--json", "json_output", is_flag=True)
def integrations_slack_test(json_output: bool):
    print_payload(api_request("POST", "dashboard/integrations/test-slack"), json_output=json_output)


@integrations_group.command("digest")
@click.argument("state", type=click.Choice(["on", "off"]))
@click.option("--json", "json_output", is_flag=True)
def integrations_digest(state: str, json_output: bool):
    print_payload(api_request("PATCH", "dashboard/integrations", json_body={"weekly_digest_enabled": state == "on"}), json_output=json_output)


@cli.group("account")
def account_group():
    """Manage the current account."""


@account_group.command("me")
@click.option("--json", "json_output", is_flag=True)
def account_me(json_output: bool):
    print_payload(api_request("GET", "account/me"), json_output=json_output)


@account_group.command("preferences")
@click.option("--weekly-digest/--no-weekly-digest", default=True)
@click.option("--critical-alerts/--no-critical-alerts", default=True)
@click.option("--json", "json_output", is_flag=True)
def account_preferences(weekly_digest: bool, critical_alerts: bool, json_output: bool):
    payload = {"weekly_digest": weekly_digest, "critical_alerts": critical_alerts}
    print_payload(api_request("PATCH", "account/preferences", json_body=payload), json_output=json_output)


@cli.group("admin")
def admin_group():
    """Admin controls for users, beta access, billing, rules, and system health."""


@admin_group.command("overview")
@click.option("--json", "json_output", is_flag=True)
def admin_overview(json_output: bool):
    print_payload(api_request("GET", "admin/overview"), json_output=json_output)


@admin_group.command("users")
@click.option("--search")
@click.option("--plan")
@click.option("--status")
@click.option("--page", default=1, show_default=True)
@click.option("--per-page", default=20, show_default=True)
@click.option("--json", "json_output", is_flag=True)
def admin_users(search: str | None, plan: str | None, status: str | None, page: int, per_page: int, json_output: bool):
    data = api_request("GET", "admin/users", params={"search": search, "plan": plan, "status": status, "page": page, "per_page": per_page})
    print_payload(data if json_output else data.get("users", data), json_output=json_output)


@admin_group.command("user-update")
@click.argument("user_id")
@click.option("--plan", type=click.Choice(["free", "pro", "team", "enterprise"]))
@click.option("--role", type=click.Choice(["user", "admin"]))
@click.option("--status", type=click.Choice(["active", "suspended"]))
@click.option("--suspend/--unsuspend", "suspended", default=None, help="Suspend or reactivate the user.")
@click.option("--json", "json_output", is_flag=True)
def admin_user_update(user_id: str, plan: str | None, role: str | None, status: str | None, suspended: bool | None, json_output: bool):
    payload = _clean_params({"plan": plan, "role": role, "status": status, "suspended": suspended}) or {}
    print_payload(api_request("PATCH", f"admin/users/{user_id}", json_body=payload), json_output=json_output)


@admin_group.command("impersonate")
@click.argument("user_id")
@click.option("--json", "json_output", is_flag=True)
def admin_impersonate(user_id: str, json_output: bool):
    data = api_request("POST", f"admin/users/{user_id}/impersonate")
    if json_output:
        print_payload(data, json_output=True)
        return
    click.echo(f"Temporary read-only token for {data.get('target_user', {}).get('email')}:")
    click.echo(data.get("token", ""))
    click.echo(f"Expires in {data.get('expires_in', 900)} seconds.")


@admin_group.command("revoke-user-keys")
@click.argument("user_id")
@click.option("--json", "json_output", is_flag=True)
def admin_revoke_user_keys(user_id: str, json_output: bool):
    print_payload(api_request("DELETE", f"admin/users/{user_id}/api-keys"), json_output=json_output)


@admin_group.command("revoke-access")
@click.argument("user_id")
@click.option("--json", "json_output", is_flag=True)
def admin_revoke_access(user_id: str, json_output: bool):
    print_payload(api_request("POST", f"admin/users/{user_id}/revoke-access"), json_output=json_output)


@admin_group.command("export-users")
@click.option("--output", type=click.Path(dir_okay=False), default="valicode-users.csv", show_default=True)
def admin_export_users(output: str):
    response = api_request("GET", "admin/users/export", raw=True)
    Path(output).write_bytes(response.content)
    click.echo(f"Exported users to {Path(output).resolve()}")


@admin_group.command("beta")
@click.option("--status")
@click.option("--search")
@click.option("--page", default=1, show_default=True)
@click.option("--per-page", default=20, show_default=True)
@click.option("--json", "json_output", is_flag=True)
def admin_beta(status: str | None, search: str | None, page: int, per_page: int, json_output: bool):
    data = api_request("GET", "admin/beta-applications", params={"status": status, "q": search, "page": page, "per_page": per_page})
    print_payload(data if json_output else data.get("applications", data), json_output=json_output)


@admin_group.command("beta-set")
@click.argument("application_id")
@click.argument("status", type=click.Choice(["pending", "approved", "rejected"]))
@click.option("--json", "json_output", is_flag=True)
def admin_beta_set(application_id: str, status: str, json_output: bool):
    print_payload(api_request("PATCH", f"admin/beta-applications/{application_id}", json_body={"status": status}), json_output=json_output)


@admin_group.command("rules")
@click.option("--json", "json_output", is_flag=True)
def admin_rules_command(json_output: bool):
    data = api_request("GET", "admin/rules")
    print_payload(data if json_output else data.get("rules", data), json_output=json_output)


@admin_group.command("rule-set")
@click.argument("rule_id")
@click.argument("state", type=click.Choice(["on", "off"]))
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--fail-merge/--no-fail-merge", default=None)
@click.option("--json", "json_output", is_flag=True)
def admin_rule_set(rule_id: str, state: str, severity: str | None, fail_merge: bool | None, json_output: bool):
    payload = _clean_params({"enabled": state == "on", "severity_override": severity, "fail_merge": fail_merge}) or {}
    print_payload(api_request("PATCH", f"admin/rules/{rule_id}", json_body=payload), json_output=json_output)


@admin_group.command("subscriptions")
@click.option("--json", "json_output", is_flag=True)
def admin_subscriptions(json_output: bool):
    data = api_request("GET", "admin/subscriptions")
    print_payload(data if json_output else data.get("subscriptions", data), json_output=json_output)


@admin_group.command("usage")
@click.option("--days", default=30, show_default=True)
@click.option("--json", "json_output", is_flag=True)
def admin_usage(days: int, json_output: bool):
    print_payload(api_request("GET", "admin/usage", params={"days": days}), json_output=json_output)


@admin_group.command("audit")
@click.option("--limit", default=100, show_default=True)
@click.option("--json", "json_output", is_flag=True)
def admin_audit(limit: int, json_output: bool):
    data = api_request("GET", "admin/audit-logs", params={"limit": limit})
    print_payload(data if json_output else data.get("logs", data), json_output=json_output)


@admin_group.command("system")
@click.option("--json", "json_output", is_flag=True)
def admin_system(json_output: bool):
    print_payload(api_request("GET", "admin/system"), json_output=json_output)


if __name__ == "__main__":
    cli()
