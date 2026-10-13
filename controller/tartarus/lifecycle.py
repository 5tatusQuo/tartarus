from __future__ import annotations

import json
import re
import tarfile
import time
from pathlib import Path
from typing import Any

from .config import Config
from .errors import TartarusError
from .ludus import run_ludus
from .manifest import validate
from .remote import Remote, range_guests
from .telemetry import record_lifecycle
from .util import atomic_json, load_json, safe_id, utc_now


def start_remote_run(
    config: Config,
    range_id: str,
    run_file: Path,
    duration: int,
    debug: bool = False,
    sample_override: Path | None = None,
) -> dict[str, object]:
    from .verify import verify_range

    readiness = verify_range(config, range_id)
    if not readiness["passed"]:
        raise TartarusError("range readiness verification failed; sample was not staged")
    run = load_json(run_file)
    verification_path = run_file.parent / "artifacts" / "verification" / "pre-run.json"
    atomic_json(verification_path, readiness)
    run["artifacts"].append(
        {
            "relative_path": verification_path.relative_to(run_file.parent).as_posix(),
            "media_type": "application/json",
            "size": verification_path.stat().st_size,
            "collection_status": "collected",
            "collected_at": utc_now(),
        }
    )
    validate("run-manifest", run)
    atomic_json(run_file, run)
    safe_id(run["run_id"], "run ID")
    if not 1 <= duration <= 3600:
        raise TartarusError("duration must be between 1 and 3600 seconds")
    sample = sample_override or (
        config.evidence_root
        / run["case_id"]
        / "samples"
        / run["sample"]["sample_id"]
        / "sample.bin"
    )
    if not sample.is_file():
        raise TartarusError("controller sample is missing")
    guests = range_guests(config, range_id)
    sandbox = Remote(config, guests["sandbox"])
    remnux = Remote(config, guests["remnux"])
    required = config.artifact_quota_gib * 1024**3
    for role, remote in (("sandbox", sandbox), ("remnux", remnux)):
        available = int(
            remote.run(("df", "-B1", "--output=avail", "/var/spool/tartarus")).stdout.splitlines()[
                -1
            ]
        )
        if available < required:
            raise TartarusError(f"{role} spool lacks the configured evidence capacity")
    _stage(
        remnux,
        sample,
        run["run_id"],
        "/var/spool/tartarus/static",
        owner=remnux.guest.user,
        sample_mode="0400",
    )
    _static_analysis(remnux, run_file, run)
    routes = remnux.run(("ip", "-j", "route", "show", "default")).stdout
    try:
        interface = json.loads(routes)[0]["dev"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
        raise TartarusError("could not resolve the REMnux capture interface") from exc
    run["status"] = "starting"
    run["range_id"] = range_id
    run["debug_session"] = debug
    atomic_json(run_file, run)
    try:
        remnux.run(
            ("/usr/local/sbin/tartarus-capture", "start", run["run_id"], interface), sudo=True
        )
        _stage(
            sandbox,
            sample,
            run["run_id"],
            "/var/spool/tartarus/runs",
        )
        sandbox.run(
            (
                "/usr/local/sbin/tartarus-run",
                "start",
                run["run_id"],
                run["telemetry_profile"],
                str(duration),
                "true" if debug else "false",
            ),
            sudo=True,
        )
        run["status"] = "running"
        run["execution_limit_seconds"] = duration
        run["remote_started_at"] = utc_now()
        atomic_json(run_file, run)
    except (TartarusError, KeyboardInterrupt):
        try:
            sandbox.run(("/usr/local/sbin/tartarus-run", "stop", run["run_id"]), sudo=True)
        except TartarusError:
            pass
        try:
            remnux.run(("/usr/local/sbin/tartarus-capture", "stop", run["run_id"]), sudo=True)
        except TartarusError:
            pass
        run["status"] = "failed"
        run["range_id"] = range_id
        run["debug_session"] = debug
        run["visibility_gaps"].append("run_start_failed")
        try:
            verification = rebuild_sandbox(config, range_id)
            run["sandbox_rebuilt_at"] = utc_now()
            run["recovery_verified"] = verification["passed"]
        except TartarusError:
            run["sandbox_rebuilt_at"] = utc_now()
            run["recovery_verified"] = False
            run["visibility_gaps"].append("sandbox_rebuild_failed")
        validate("run-manifest", run)
        atomic_json(run_file, run)
        raise
    record_lifecycle(
        config,
        range_id,
        {
            "timestamp": run["remote_started_at"],
            "event": "run_started",
            "case_id": run["case_id"],
            "run_id": run["run_id"],
            "sample_id": run["sample"]["sample_id"],
            "telemetry_profile": run["telemetry_profile"],
        },
    )
    return run


def start_static_analysis_run(
    config: Config,
    range_id: str,
    run_file: Path,
    duration: int,
    sample: Path,
    elf: dict[str, Any],
    readiness: dict[str, Any],
) -> dict[str, object]:
    """Stage an incompatible ELF for deep static analysis without sandbox execution."""
    if not readiness["passed"]:
        raise TartarusError("range readiness verification failed; sample was not staged")
    if not 1 <= duration <= 3600:
        raise TartarusError("duration must be between 1 and 3600 seconds")
    if not sample.is_file():
        raise TartarusError("controller sample is missing")
    run = load_json(run_file)
    verification_path = run_file.parent / "artifacts" / "verification" / "pre-run.json"
    atomic_json(verification_path, readiness)
    run["artifacts"].append(
        {
            "relative_path": verification_path.relative_to(run_file.parent).as_posix(),
            "media_type": "application/json",
            "size": verification_path.stat().st_size,
            "collection_status": "collected",
            "collected_at": utc_now(),
        }
    )
    remnux = Remote(config, range_guests(config, range_id)["remnux"])
    _stage(
        remnux,
        sample,
        run["run_id"],
        "/var/spool/tartarus/static",
        owner=remnux.guest.user,
        sample_mode="0400",
    )
    _static_analysis(remnux, run_file, run)
    run.update(
        status="running",
        range_id=range_id,
        debug_session=False,
        execution_mode="static_only",
        sample_architecture=(
            f"ELF{elf['class']} {elf['endianness']}-endian machine {elf['machine']}"
        ),
        execution_limit_seconds=duration,
        remote_started_at=utc_now(),
    )
    run["visibility_gaps"].append("dynamic_execution_unsupported_architecture")
    validate("run-manifest", run)
    atomic_json(run_file, run)
    return run


def cancel_pre_execution_run(config: Config, run_file: Path) -> dict[str, object]:
    """Remove analysis-host staging after an agent cancels before execution."""
    run = load_json(run_file)
    if not run.get("range_id"):
        raise TartarusError("run has no range context for cancellation cleanup")
    remnux = Remote(config, range_guests(config, run["range_id"])["remnux"])
    remnux.run(
        (
            "rm",
            "-rf",
            f"/var/spool/tartarus/static/{run['run_id']}",
            f"/var/spool/tartarus/ghidra/{run['run_id']}",
        ),
        sudo=True,
    )
    run["status"] = "failed"
    if "agent_cancelled_before_execution" not in run["visibility_gaps"]:
        run["visibility_gaps"].append("agent_cancelled_before_execution")
    validate("run-manifest", run)
    atomic_json(run_file, run)
    return run


def stop_static_analysis_run(config: Config, run_file: Path) -> dict[str, object]:
    """Collect REMnux evidence and verify containment for a static-only run."""
    run = load_json(run_file)
    if run.get("status") != "running" or run.get("execution_mode") != "static_only":
        raise TartarusError("run is not an active static-only analysis")
    run["status"] = "stopping"
    atomic_json(run_file, run)
    remnux = Remote(config, range_guests(config, run["range_id"])["remnux"])
    gaps: list[str] = []
    records: list[dict[str, object]] = []
    ghidra_dir = f"/var/spool/tartarus/ghidra/{run['run_id']}"
    if _remote_directory_exists(remnux, ghidra_dir):
        try:
            records.append(
                _pull_directory(
                    config,
                    remnux,
                    ghidra_dir,
                    run_file.parent,
                    "ghidra",
                    run["run_id"],
                )
            )
        except TartarusError:
            gaps.append("ghidra_collection_failed")
    try:
        remnux.run(
            (
                "rm",
                "-rf",
                f"/var/spool/tartarus/static/{run['run_id']}",
                ghidra_dir,
            ),
            sudo=True,
        )
    except TartarusError:
        gaps.append("remnux_cleanup_failed")
    from .verify import verify_range

    verification = verify_range(config, run["range_id"])
    latest = load_json(run_file)
    known = {artifact["relative_path"] for artifact in run["artifacts"]}
    run["artifacts"].extend(
        artifact for artifact in latest["artifacts"] if artifact["relative_path"] not in known
    )
    run["artifacts"].extend(records)
    run["stopped_at"] = utc_now()
    run["recovery_verified"] = verification["passed"]
    run["visibility_gaps"] = [
        "dynamic_execution_unsupported_architecture",
        *gaps,
        *_visibility_gaps(run_file.parent),
    ]
    run["status"] = "collected_with_gaps"
    validate("run-manifest", run)
    atomic_json(run_file, run)
    if not verification["passed"]:
        raise TartarusError("range verification failed after static-only analysis")
    return run


def _static_analysis(remote: Remote, run_file: Path, run: dict[str, Any]) -> None:
    sample = f"/var/spool/tartarus/static/{run['run_id']}/sample"
    results: dict[str, object] = {}
    for name, command in (("info", "iIj"), ("functions", "aaa;aflj"), ("strings", "izj")):
        output = remote.run(
            (
                "r2",
                "-q",
                "-e",
                "io.cache=true",
                "-c",
                f"e cfg.sandbox=true;{command}",
                sample,
            ),
            timeout=300,
        ).stdout
        if len(output.encode("utf-8")) > 4 * 1024 * 1024:
            raise TartarusError(f"radare2 {name} output exceeded 4 MiB")
        try:
            results[name] = json.loads(output)
        except json.JSONDecodeError:
            results[name] = {"parse_error": True, "bounded_output": output[:65536]}
    analyze = remote.run(("which", "analyzeHeadless")).stdout.strip()
    project = f"/var/spool/tartarus/ghidra/{run['run_id']}"
    remote.run(("mkdir", "-p", project))
    remote.run((analyze, project, "tartarus", "-import", sample, "-overwrite"), timeout=900)
    output_path = run_file.parent / "artifacts" / "static" / "radare2.json"
    atomic_json(output_path, results)
    run["artifacts"].append(
        {
            "relative_path": output_path.relative_to(run_file.parent).as_posix(),
            "media_type": "application/json",
            "size": output_path.stat().st_size,
            "collection_status": "collected",
            "collected_at": utc_now(),
        }
    )


def stop_remote_run(
    config: Config, run_file: Path, *, approve_quota_override: bool = False
) -> dict[str, object]:
    run = load_json(run_file)
    if run.get("status") not in {"starting", "running", "stopping"} or not run.get("range_id"):
        raise TartarusError("run is not active on a range")
    if run["status"] != "stopping":
        run["status"] = "stopping"
        validate("run-manifest", run)
        atomic_json(run_file, run)
    guests = range_guests(config, run["range_id"])
    sandbox = Remote(config, guests["sandbox"])
    remnux = Remote(config, guests["remnux"])
    gaps: list[str] = []
    for role, remote, command in (
        ("sandbox", sandbox, ("/usr/local/sbin/tartarus-run", "stop", run["run_id"])),
        ("remnux", remnux, ("/usr/local/sbin/tartarus-capture", "stop", run["run_id"])),
    ):
        try:
            remote.run(command, sudo=True)
        except TartarusError:
            gaps.append(f"{role}_stop_failed")
    records: list[dict[str, object]] = []
    collectors = (
        lambda: _pull_directory(
            config,
            sandbox,
            f"/var/spool/tartarus/runs/{run['run_id']}",
            run_file.parent,
            "sandbox",
            run["run_id"],
            approve_quota_override=approve_quota_override,
        ),
        lambda: _pull_capture(
            config,
            remnux,
            run_file.parent,
            run["run_id"],
            approve_quota_override=approve_quota_override,
        ),
    )
    for role, collector in zip(("sandbox", "remnux"), collectors, strict=True):
        try:
            records.append(collector())
        except TartarusError:
            gaps.append(f"{role}_collection_failed")
    ghidra_dir = f"/var/spool/tartarus/ghidra/{run['run_id']}"
    if _remote_directory_exists(remnux, ghidra_dir):
        try:
            records.append(
                _pull_directory(
                    config,
                    remnux,
                    ghidra_dir,
                    run_file.parent,
                    "ghidra",
                    run["run_id"],
                    approve_quota_override=approve_quota_override,
                )
            )
        except TartarusError:
            gaps.append("ghidra_collection_failed")
    try:
        remnux.run(
            (
                "rm",
                "-rf",
                f"/var/spool/tartarus/static/{run['run_id']}",
                ghidra_dir,
            ),
            sudo=True,
        )
    except TartarusError:
        gaps.append("remnux_cleanup_failed")
    run = load_json(run_file)
    run["stopped_at"] = utc_now()
    run["artifacts"].extend(records)
    run["visibility_gaps"] = [*gaps, *_visibility_gaps(run_file.parent)]
    try:
        verification = rebuild_sandbox(config, run["range_id"])
        run["sandbox_rebuilt_at"] = utc_now()
        run["recovery_verified"] = verification["passed"]
    except TartarusError:
        run["sandbox_rebuilt_at"] = utc_now()
        run["recovery_verified"] = False
        run["visibility_gaps"].append("sandbox_rebuild_failed")
    run["status"] = (
        "collected"
        if not run["visibility_gaps"] and run["recovery_verified"]
        else "collected_with_gaps"
    )
    latest_run = load_json(run_file)
    known_paths = {artifact["relative_path"] for artifact in run["artifacts"]}
    run["artifacts"].extend(
        artifact
        for artifact in latest_run["artifacts"]
        if artifact["relative_path"] not in known_paths
    )
    validate("run-manifest", run)
    atomic_json(run_file, run)
    record_lifecycle(
        config,
        run["range_id"],
        {
            "timestamp": run["stopped_at"],
            "event": "run_collected_and_rebuilt",
            "case_id": run["case_id"],
            "run_id": run["run_id"],
            "sample_id": run["sample"]["sample_id"],
            "artifacts": run["artifacts"],
            "status": run["status"],
            "recovery_verified": run["recovery_verified"],
            "visibility_gaps": run["visibility_gaps"],
        },
    )
    if not run["recovery_verified"]:
        raise TartarusError(
            "sandbox recovery failed after collection; the run manifest records the failure"
        )
    return run


def rebuild_sandbox(
    config: Config, range_id: str, *, wait_seconds: int = 1800
) -> dict[str, object]:
    guest = range_guests(config, range_id)["sandbox"]
    try:
        initial_status = json.loads(
            run_ludus(
                ("--range", range_id, "testing", "status", "--json"),
                config=config.ludus_config,
            ).stdout
        )
    except json.JSONDecodeError as exc:
        raise TartarusError("could not parse Ludus status before sandbox rebuild") from exc
    testing_was_enabled = initial_status.get("testingEnabled") is True
    if testing_was_enabled:
        run_ludus(
            ("--range", range_id, "testing", "stop"),
            config=config.ludus_config,
            timeout=300,
        )
    run_ludus(
        ("--range", range_id, "vm", "destroy", str(guest.vmid), "--no-prompt"),
        config=config.ludus_config,
        timeout=300,
    )
    run_ludus(
        ("--range", range_id, "range", "deploy", "--force"),
        config=config.ludus_config,
        timeout=180,
    )
    deadline = time.monotonic() + wait_seconds
    # A successful deploy command is authoritative evidence that this rebuild was
    # submitted. Some Ludus versions block until the deployment is already in
    # SUCCESS, so the following polling loop can legitimately miss the transient
    # RUNNING/DEPLOYING states.
    observed_active_deployment = True
    while time.monotonic() < deadline:
        try:
            status = json.loads(
                run_ludus(
                    ("--range", range_id, "testing", "status", "--json"),
                    config=config.ludus_config,
                ).stdout
            )
            state = str(status.get("rangeState", "")).upper()
            if state in {"RUNNING", "DEPLOYING"}:
                observed_active_deployment = True
            if state in {"ERROR", "FAILED", "FAILURE"}:
                raise TartarusError(f"sandbox redeployment failed with state {state}")
            if state != "SUCCESS" or not observed_active_deployment:
                time.sleep(15)
                continue
            if testing_was_enabled and status.get("testingEnabled") is not True:
                run_ludus(
                    ("--range", range_id, "testing", "start"),
                    config=config.ludus_config,
                    timeout=300,
                )
            rebuilt = range_guests(config, range_id)["sandbox"]
            if rebuilt.name == guest.name:
                from .verify import verify_range

                verification = verify_range(config, range_id)
                if verification["passed"]:
                    return verification
        except json.JSONDecodeError:
            pass
        time.sleep(15)
    raise TartarusError("sandbox redeployment did not become ready before the deadline")


def _stage(
    remote: Remote,
    sample: Path,
    run_id: str,
    root: str,
    *,
    owner: str = "root",
    sample_mode: str = "0500",
    destination_name: str = "sample",
) -> None:
    upload = f"/tmp/tartarus-{run_id}-sample"
    remote.push(sample, upload)
    try:
        remote.run(
            ("install", "-d", "-o", owner, "-g", owner, "-m", "0700", f"{root}/{run_id}"),
            sudo=True,
        )
        remote.run(
            (
                "install",
                "-o",
                owner,
                "-g",
                owner,
                "-m",
                sample_mode,
                upload,
                f"{root}/{run_id}/{destination_name}",
            ),
            sudo=True,
        )
    except TartarusError:
        try:
            remote.run(("rm", "-rf", f"{root}/{run_id}"), sudo=True)
        except TartarusError:
            pass
        raise
    finally:
        remote.run(("rm", "-f", upload))


def _pull_directory(
    config: Config,
    remote: Remote,
    source: str,
    run_dir: Path,
    role: str,
    run_id: str,
    members: tuple[str, ...] = (".",),
    approve_quota_override: bool = False,
) -> dict[str, object]:
    archive_name = f"/tmp/tartarus-{run_id}-{role}.tar"
    remote.run(("tar", "-C", source, "-cf", archive_name, *members), sudo=True, timeout=300)
    remote.run(("chown", f"{remote.guest.user}:{remote.guest.user}", archive_name), sudo=True)
    remote_size = int(remote.run(("stat", "-c", "%s", archive_name)).stdout.strip())
    local_archive = run_dir / "transfers" / f"{role}.tar"
    if not approve_quota_override and not local_archive.exists():
        _check_quota(config, run_dir, remote_size * 2)
    try:
        if local_archive.exists():
            if local_archive.stat().st_size != remote_size:
                raise TartarusError(f"existing {role} transfer has a different size")
        else:
            remote.pull(archive_name, local_archive)
            local_archive.chmod(0o600)
    finally:
        remote.run(("rm", "-f", archive_name))
    local_archive.chmod(0o600)
    destination = run_dir / "artifacts" / role
    if destination.exists():
        if not _extraction_matches(local_archive, destination):
            raise TartarusError(f"existing {role} evidence differs from the transfer archive")
    else:
        _safe_extract(local_archive, destination)
    return {
        "relative_path": local_archive.relative_to(run_dir).as_posix(),
        "media_type": "application/x-tar",
        "size": local_archive.stat().st_size,
        "collection_status": "collected",
        "collected_at": utc_now(),
    }


def _pull_capture(
    config: Config,
    remote: Remote,
    run_dir: Path,
    run_id: str,
    *,
    approve_quota_override: bool = False,
) -> dict[str, object]:
    return _pull_directory(
        config,
        remote,
        "/var/spool/tartarus/capture",
        run_dir,
        "remnux",
        run_id,
        (f"{run_id}.pcapng", f"{run_id}-capture.log"),
        approve_quota_override=approve_quota_override,
    )


def _check_quota(config: Config, run_dir: Path, incoming: int) -> None:
    current = sum(path.stat().st_size for path in run_dir.rglob("*") if path.is_file())
    if current + incoming > config.artifact_quota_gib * 1024**3:
        raise TartarusError("collected evidence would exceed the configured run quota")


def _remote_directory_exists(remote: Remote, path: str) -> bool:
    try:
        remote.run(("test", "-d", path), sudo=True)
    except TartarusError:
        return False
    return True


def _safe_extract(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    root = destination.resolve()
    with tarfile.open(archive_path, "r:") as archive:
        for member in archive.getmembers():
            target = (root / member.name).resolve()
            if root not in target.parents and target != root:
                raise TartarusError(f"unsafe evidence archive member: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise TartarusError(f"unsupported evidence archive member: {member.name}")
        archive.extractall(root, filter="data")
    for path in destination.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)


def _extraction_matches(archive_path: Path, destination: Path) -> bool:
    with tarfile.open(archive_path, "r:") as archive:
        expected_files = {
            Path(member.name).as_posix() for member in archive.getmembers() if member.isfile()
        }
        observed_files = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_file()
        }
        if expected_files != observed_files:
            return False
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = destination / member.name
            if not extracted.is_file():
                return False
            if member.size != extracted.stat().st_size:
                return False
    return True


def _visibility_gaps(run_dir: Path) -> list[str]:
    gaps: list[str] = []
    audit = run_dir / "artifacts" / "sandbox" / "audit-status.txt"
    if audit.is_file():
        match = re.search(
            r"(?m)^lost\s+(\d+)$", audit.read_text(encoding="utf-8", errors="replace")
        )
        if match and int(match.group(1)):
            gaps.append(f"audit_lost:{match.group(1)}")
    capture_logs = list((run_dir / "artifacts" / "remnux").glob("*-capture.log"))
    for capture in capture_logs:
        text = capture.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"Packets dropped:\s*(\d+)", text, re.IGNORECASE)
        if match and int(match.group(1)):
            gaps.append(f"packet_drops:{match.group(1)}")
    for stream in ("stdout.log", "stderr.log"):
        path = run_dir / "artifacts" / "sandbox" / stream
        if path.is_file() and path.stat().st_size >= 1024**3:
            gaps.append(f"output_limit:{stream}")
    agent = run_dir / "artifacts" / "sandbox" / "elastic-agent.log"
    if agent.is_file() and re.search(
        r"queue full|backpressure|events? dropped|failed to publish",
        agent.read_text(encoding="utf-8", errors="replace"),
        re.IGNORECASE,
    ):
        gaps.append("elastic_agent_backpressure")
    return gaps
