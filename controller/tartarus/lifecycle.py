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

PAIR_ROLES = ("remnux", "sandbox")


def pair_recovery_state(config: Config, range_id: str) -> dict[str, Any]:
    """Return durable recovery state without accepting legacy sandbox-only proof."""
    path = _pair_recovery_path(config, range_id)
    if path.is_file():
        return load_json(path)
    return {
        "schema_version": "1.0",
        "range_id": range_id,
        "state": "unverified",
        "phase": "unverified",
        "run_id": None,
        "tainted_at": None,
        "verified_at": None,
        "guests": {role: {"status": "unknown"} for role in PAIR_ROLES},
        "failure": "The range has no verified analysis-pair recovery record.",
    }


def assert_analysis_pair_ready(
    config: Config, range_id: str, *, run_id: str | None = None
) -> dict[str, Any]:
    state = pair_recovery_state(config, range_id)
    if state["state"] == "clean" and state["phase"] == "verified":
        return state
    if run_id and state["state"] == "tainted" and state.get("run_id") == run_id:
        return state
    raise TartarusError(
        f"analysis pair for {range_id} is {state['state']}; recover and verify both guests before starting a run"
    )


def mark_analysis_pair_clean(
    config: Config,
    range_id: str,
    verification: dict[str, Any],
    *,
    guests: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not verification.get("passed"):
        raise TartarusError("cannot mark an analysis pair clean without passing verification")
    inventory = guests or range_guests(config, range_id)
    state = {
        "schema_version": "1.0",
        "range_id": range_id,
        "state": "clean",
        "phase": "verified",
        "run_id": None,
        "tainted_at": None,
        "verified_at": utc_now(),
        "guests": {
            role: {"status": "verified", "current": _guest_identity(inventory[role])}
            for role in PAIR_ROLES
        },
        "failure": None,
    }
    _save_pair_recovery(config, state)
    return state


def mark_analysis_pair_tainted(
    config: Config, range_id: str, run_file: Path
) -> dict[str, Any]:
    run = load_json(run_file)
    current = assert_analysis_pair_ready(config, range_id, run_id=run["run_id"])
    if current["state"] == "tainted":
        _set_run_pair_recovery(run_file, current)
        return current
    guests = range_guests(config, range_id)
    now = utc_now()
    state = {
        "schema_version": "1.0",
        "range_id": range_id,
        "state": "tainted",
        "phase": "tainted",
        "run_id": run["run_id"],
        "tainted_at": now,
        "verified_at": None,
        "guests": {
            role: {"status": "tainted", "before": _guest_identity(guests[role])}
            for role in PAIR_ROLES
        },
        "failure": None,
    }
    _save_pair_recovery(config, state)
    run["range_id"] = range_id
    _set_run_pair_recovery(run_file, state, run=run)
    return state


def quarantine_analysis_pair(
    config: Config,
    range_id: str,
    failure: Exception | str,
    *,
    run_file: Path | None = None,
) -> dict[str, Any]:
    state = pair_recovery_state(config, range_id)
    _quarantine_pair(config, state, failure, run_file)
    return state


def _pair_recovery_path(config: Config, range_id: str) -> Path:
    safe_id(range_id, "range ID")
    return config.cache_root / "state" / "ranges" / f"{range_id}-analysis-pair.json"


def _guest_identity(guest: Any) -> dict[str, Any]:
    return {"name": guest.name, "vmid": guest.vmid, "address": guest.address}


def _save_pair_recovery(config: Config, state: dict[str, Any]) -> None:
    atomic_json(_pair_recovery_path(config, state["range_id"]), state)


def _set_run_pair_recovery(
    run_file: Path, state: dict[str, Any], *, run: dict[str, Any] | None = None
) -> None:
    document = run or load_json(run_file)
    document["analysis_pair_recovery"] = state
    validate("run-manifest", document)
    atomic_json(run_file, document)


def _quarantine_pair(
    config: Config,
    state: dict[str, Any],
    failure: Exception | str,
    run_file: Path | None = None,
) -> None:
    state.update(
        state="quarantined", phase="failed", failure=str(failure), verified_at=None
    )
    for guest_state in state["guests"].values():
        if guest_state["status"] not in {"destroyed", "redeployed", "verified"}:
            guest_state["status"] = "failed"
    _save_pair_recovery(config, state)
    if run_file:
        _set_run_pair_recovery(run_file, state)


def start_remote_run(
    config: Config,
    range_id: str,
    run_file: Path,
    duration: int,
    debug: bool = False,
    sample_override: Path | None = None,
) -> dict[str, object]:
    from .verify import verify_range

    pending = load_json(run_file)
    assert_analysis_pair_ready(config, range_id, run_id=pending["run_id"])
    readiness = verify_range(config, range_id)
    if not readiness["passed"]:
        quarantine_analysis_pair(
            config, range_id, "range readiness verification failed", run_file=run_file
        )
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
    mark_analysis_pair_tainted(config, range_id, run_file)
    run = load_json(run_file)
    try:
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
    except (TartarusError, KeyboardInterrupt):
        _recover_failed_start(config, range_id, run_file, sandbox, remnux, debug)
        raise
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
        _recover_failed_start(config, range_id, run_file, sandbox, remnux, debug)
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


def _recover_failed_start(
    config: Config,
    range_id: str,
    run_file: Path,
    sandbox: Remote,
    remnux: Remote,
    debug: bool,
) -> None:
    run = load_json(run_file)
    for remote, command in (
        (sandbox, ("/usr/local/sbin/tartarus-run", "stop", run["run_id"])),
        (remnux, ("/usr/local/sbin/tartarus-capture", "stop", run["run_id"])),
    ):
        try:
            remote.run(command, sudo=True)
        except TartarusError:
            pass
    run.update(status="failed", range_id=range_id, debug_session=debug)
    if "run_start_failed" not in run["visibility_gaps"]:
        run["visibility_gaps"].append("run_start_failed")
    atomic_json(run_file, run)
    try:
        verification = recover_analysis_pair(config, range_id, run_file=run_file)
        run = load_json(run_file)
        run["sandbox_rebuilt_at"] = utc_now()
        run["recovery_verified"] = verification["passed"]
    except TartarusError:
        run = load_json(run_file)
        run["sandbox_rebuilt_at"] = utc_now()
        run["recovery_verified"] = False
        if "analysis_pair_recovery_failed" not in run["visibility_gaps"]:
            run["visibility_gaps"].append("analysis_pair_recovery_failed")
    validate("run-manifest", run)
    atomic_json(run_file, run)


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
        quarantine_analysis_pair(
            config, range_id, "range readiness verification failed", run_file=run_file
        )
        raise TartarusError("range readiness verification failed; sample was not staged")
    if not 1 <= duration <= 3600:
        raise TartarusError("duration must be between 1 and 3600 seconds")
    if not sample.is_file():
        raise TartarusError("controller sample is missing")
    run = load_json(run_file)
    assert_analysis_pair_ready(config, range_id, run_id=run["run_id"])
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
    mark_analysis_pair_tainted(config, range_id, run_file)
    run = load_json(run_file)
    try:
        _stage(
            remnux,
            sample,
            run["run_id"],
            "/var/spool/tartarus/static",
            owner=remnux.guest.user,
            sample_mode="0400",
        )
        _static_analysis(remnux, run_file, run)
    except (TartarusError, KeyboardInterrupt):
        failed = load_json(run_file)
        failed.update(status="failed", execution_mode="static_only")
        if "static_start_failed" not in failed["visibility_gaps"]:
            failed["visibility_gaps"].append("static_start_failed")
        atomic_json(run_file, failed)
        recover_analysis_pair(config, range_id, run_file=run_file)
        raise
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
    """Recover both guests after an agent cancels before execution."""
    run = load_json(run_file)
    if not run.get("range_id"):
        raise TartarusError("run has no range context for cancellation cleanup")
    run["status"] = "failed"
    if "agent_cancelled_before_execution" not in run["visibility_gaps"]:
        run["visibility_gaps"].append("agent_cancelled_before_execution")
    validate("run-manifest", run)
    atomic_json(run_file, run)
    recover_analysis_pair(config, run["range_id"], run_file=run_file)
    return load_json(run_file)


def stop_static_analysis_run(config: Config, run_file: Path) -> dict[str, object]:
    """Collect evidence and recover both guests after a static-only run."""
    run = load_json(run_file)
    if run.get("status") != "running" or run.get("execution_mode") != "static_only":
        raise TartarusError("run is not an active static-only analysis")
    run["status"] = "stopping"
    atomic_json(run_file, run)
    verification = recover_analysis_pair(config, run["range_id"], run_file=run_file)
    run = load_json(run_file)
    run["recovery_verified"] = verification["passed"]
    run["visibility_gaps"] = list(
        dict.fromkeys([*run["visibility_gaps"], *_visibility_gaps(run_file.parent)])
    )
    run["status"] = "collected_with_gaps"
    validate("run-manifest", run)
    atomic_json(run_file, run)
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
    try:
        verification = recover_analysis_pair(
            config,
            run["range_id"],
            run_file=run_file,
            approve_quota_override=approve_quota_override,
        )
    except TartarusError:
        run = load_json(run_file)
        run["stopped_at"] = run.get("stopped_at") or utc_now()
        run["recovery_verified"] = False
        if "analysis_pair_recovery_failed" not in run["visibility_gaps"]:
            run["visibility_gaps"].append("analysis_pair_recovery_failed")
        validate("run-manifest", run)
        atomic_json(run_file, run)
        raise
    run = load_json(run_file)
    run["stopped_at"] = run.get("stopped_at") or utc_now()
    run["sandbox_rebuilt_at"] = utc_now()
    run["recovery_verified"] = verification["passed"]
    run["visibility_gaps"] = [*run["visibility_gaps"], *_visibility_gaps(run_file.parent)]
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
            "event": "run_collected_and_pair_recovered",
            "case_id": run["case_id"],
            "run_id": run["run_id"],
            "sample_id": run["sample"]["sample_id"],
            "artifacts": run["artifacts"],
            "status": run["status"],
            "recovery_verified": run["recovery_verified"],
            "visibility_gaps": run["visibility_gaps"],
        },
    )
    if run["analysis_pair_recovery"]["state"] != "clean":
        raise TartarusError("analysis-pair recovery did not complete")
    return run


def recover_analysis_pair(
    config: Config,
    range_id: str,
    *,
    run_file: Path | None = None,
    wait_seconds: int = 1800,
    approve_quota_override: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Destroy, redeploy, and verify the disposable REMnux/sandbox pair."""
    state = pair_recovery_state(config, range_id)
    if state["state"] == "clean" and state["phase"] == "verified" and not force:
        from .verify import verify_range

        try:
            verification = verify_range(config, range_id)
            if not verification["passed"]:
                raise TartarusError("verified analysis pair no longer passes range verification")
            return verification
        except Exception as exc:
            _quarantine_pair(config, state, exc, run_file)
            if isinstance(exc, TartarusError):
                raise
            raise TartarusError("analysis-pair verification failed; the range is quarantined") from exc
    if state["state"] in {"unverified", "clean"}:
        try:
            guests = range_guests(config, range_id)
        except Exception as exc:
            _quarantine_pair(config, state, exc, run_file)
            if isinstance(exc, TartarusError):
                raise
            raise TartarusError("analysis-pair inventory failed; the range is quarantined") from exc
        state.update(
            state="tainted",
            phase="tainted",
            run_id=load_json(run_file)["run_id"] if run_file else None,
            tainted_at=state.get("tainted_at") or utc_now(),
            verified_at=None,
            guests={
                role: {"status": "tainted", "before": _guest_identity(guests[role])}
                for role in PAIR_ROLES
            },
            failure=None,
        )
        _save_pair_recovery(config, state)
    elif state["state"] == "quarantined":
        if force:
            for guest in state["guests"].values():
                if "before" not in guest and "current" in guest:
                    guest["before"] = guest["current"]
                guest["status"] = "tainted"
        if any("before" not in guest for guest in state["guests"].values()):
            try:
                guests = range_guests(config, range_id)
                for role in PAIR_ROLES:
                    state["guests"][role]["before"] = _guest_identity(guests[role])
            except Exception as exc:
                _quarantine_pair(config, state, exc, run_file)
                if isinstance(exc, TartarusError):
                    raise
                raise TartarusError(
                    "analysis-pair inventory failed; the range remains quarantined"
                ) from exc
        statuses = {guest["status"] for guest in state["guests"].values()}
        if force:
            retry_phase = "destroying"
        elif statuses <= {"redeployed", "verified"}:
            retry_phase = "verifying"
        elif statuses == {"destroyed"}:
            retry_phase = "redeploying"
        elif "destroyed" in statuses:
            retry_phase = "destroying"
        else:
            retry_phase = "collecting" if run_file else "destroying"
        state.update(state="recovering", phase=retry_phase, failure=None)
        _save_pair_recovery(config, state)
    if run_file:
        _set_run_pair_recovery(run_file, state)
    try:
        initial_status = json.loads(
            run_ludus(
                ("--range", range_id, "testing", "status", "--json"),
                config=config.ludus_config,
            ).stdout
        )
    except json.JSONDecodeError as exc:
        failure = TartarusError("could not parse Ludus status before analysis-pair recovery")
        _quarantine_pair(config, state, failure, run_file)
        raise failure from exc
    testing_was_enabled = initial_status.get("testingEnabled") is True
    testing_stopped = False
    try:
        if state["phase"] in {"tainted", "freezing", "collecting"}:
            state.update(state="recovering", phase="freezing", failure=None)
            _save_pair_recovery(config, state)
            if run_file:
                _set_run_pair_recovery(run_file, state)
                gaps = _freeze_analysis_pair(config, run_file)
                for role in PAIR_ROLES:
                    state["guests"][role]["status"] = "stopped"
                state["phase"] = "collecting"
                _save_pair_recovery(config, state)
                _set_run_pair_recovery(run_file, state)
                records, collection_gaps = _collect_analysis_pair_evidence(
                    config, run_file, approve_quota_override=approve_quota_override
                )
                run = load_json(run_file)
                known = {item["relative_path"] for item in run["artifacts"]}
                run["artifacts"].extend(
                    item for item in records if item["relative_path"] not in known
                )
                run["visibility_gaps"] = list(
                    dict.fromkeys([*run["visibility_gaps"], *gaps, *collection_gaps])
                )
                run["stopped_at"] = utc_now()
                validate("run-manifest", run)
                atomic_json(run_file, run)
                for role in PAIR_ROLES:
                    state["guests"][role]["status"] = "collected"
            state["phase"] = "destroying"
            _save_pair_recovery(config, state)
            if run_file:
                _set_run_pair_recovery(run_file, state)

        if state["phase"] == "destroying":
            for role in PAIR_ROLES:
                guest_state = state["guests"][role]
                if guest_state["status"] == "destroyed":
                    continue
                vmid = guest_state["before"]["vmid"]
                try:
                    run_ludus(
                        ("--range", range_id, "vm", "destroy", str(vmid), "--no-prompt"),
                        config=config.ludus_config,
                        timeout=300,
                    )
                except TartarusError:
                    inventory = run_ludus(
                        ("--range", range_id, "range", "inventory"),
                        config=config.ludus_config,
                    ).stdout
                    if guest_state["before"]["name"] in inventory:
                        raise
                guest_state["status"] = "destroyed"
                _save_pair_recovery(config, state)
                if run_file:
                    _set_run_pair_recovery(run_file, state)
            # Testing mode may revert snapshot-enabled guests. It is stopped only
            # after both tainted guests are confirmed destroyed.
            if testing_was_enabled:
                run_ludus(
                    ("--range", range_id, "testing", "stop"),
                    config=config.ludus_config,
                    timeout=300,
                )
                testing_stopped = True
            state["phase"] = "redeploying"
            _save_pair_recovery(config, state)
            if run_file:
                _set_run_pair_recovery(run_file, state)

        if state["phase"] == "redeploying":
            if not testing_stopped:
                current_status = json.loads(
                    run_ludus(
                        ("--range", range_id, "testing", "status", "--json"),
                        config=config.ludus_config,
                    ).stdout
                )
                if current_status.get("testingEnabled") is True:
                    run_ludus(
                        ("--range", range_id, "testing", "stop"),
                        config=config.ludus_config,
                        timeout=300,
                    )
            run_ludus(
                ("--range", range_id, "range", "deploy", "--force"),
                config=config.ludus_config,
                timeout=180,
            )
            _wait_for_pair_deployment(config, range_id, wait_seconds)
            status = json.loads(
                run_ludus(
                    ("--range", range_id, "testing", "status", "--json"),
                    config=config.ludus_config,
                ).stdout
            )
            if status.get("testingEnabled") is not True:
                run_ludus(
                    ("--range", range_id, "testing", "start"),
                    config=config.ludus_config,
                    timeout=300,
                )
            rebuilt = range_guests(config, range_id)
            for role in PAIR_ROLES:
                state["guests"][role].update(
                    status="redeployed", current=_guest_identity(rebuilt[role])
                )
            state["phase"] = "verifying"
            _save_pair_recovery(config, state)
            if run_file:
                _set_run_pair_recovery(run_file, state)

        from .verify import verify_range

        verification = verify_range(config, range_id)
        if not verification["passed"]:
            raise TartarusError("analysis-pair verification failed after redeployment")
        clean = mark_analysis_pair_clean(config, range_id, verification)
        if run_file:
            completed = {
                **clean,
                "run_id": state.get("run_id"),
                "tainted_at": state.get("tainted_at"),
                "guests": {
                    role: {
                        "status": "verified",
                        "before": state["guests"][role].get("before"),
                        "current": clean["guests"][role]["current"],
                    }
                    for role in PAIR_ROLES
                },
            }
            _set_run_pair_recovery(run_file, completed)
        return verification
    except Exception as exc:
        _quarantine_pair(config, state, exc, run_file)
        if isinstance(exc, TartarusError):
            raise
        raise TartarusError("analysis-pair recovery failed; the range is quarantined") from exc


def rebuild_sandbox(
    config: Config, range_id: str, *, wait_seconds: int = 1800
) -> dict[str, object]:
    """Compatibility wrapper for the former sandbox-only recovery command."""
    return recover_analysis_pair(config, range_id, wait_seconds=wait_seconds, force=True)


def _wait_for_pair_deployment(config: Config, range_id: str, wait_seconds: int) -> None:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            status = json.loads(
                run_ludus(
                    ("--range", range_id, "testing", "status", "--json"),
                    config=config.ludus_config,
                ).stdout
            )
        except json.JSONDecodeError:
            time.sleep(15)
            continue
        deployment = str(status.get("rangeState", "")).upper()
        if deployment == "SUCCESS":
            return
        if deployment in {"ERROR", "FAILED", "FAILURE"}:
            raise TartarusError(f"analysis-pair redeployment failed with state {deployment}")
        time.sleep(15)
    raise TartarusError("analysis-pair redeployment did not become ready before the deadline")


def _freeze_analysis_pair(config: Config, run_file: Path) -> list[str]:
    run = load_json(run_file)
    guests = range_guests(config, run["range_id"])
    gaps: list[str] = []
    commands = {
        "sandbox": ("/usr/local/sbin/tartarus-run", "stop", run["run_id"]),
        "remnux": ("/usr/local/sbin/tartarus-capture", "stop", run["run_id"]),
    }
    for role in PAIR_ROLES:
        if role == "sandbox" and run.get("execution_mode") == "static_only":
            continue
        try:
            Remote(config, guests[role]).run(commands[role], sudo=True)
        except TartarusError:
            gaps.append(f"{role}_stop_failed")
    return gaps


def _collect_analysis_pair_evidence(
    config: Config, run_file: Path, *, approve_quota_override: bool
) -> tuple[list[dict[str, object]], list[str]]:
    run = load_json(run_file)
    run_id = run["run_id"]
    guests = range_guests(config, run["range_id"])
    sandbox = Remote(config, guests["sandbox"])
    remnux = Remote(config, guests["remnux"])
    records: list[dict[str, object]] = []
    gaps: list[str] = []

    state_dir = f"/var/spool/tartarus/recovery/{run_id}"
    try:
        remnux.run(("install", "-d", "-m", "0700", state_dir), sudo=True)
        snapshots = {
            "processes.txt": "ps auxww",
            "sockets.txt": "ss -plant",
            "services.txt": "systemctl list-units --type=service --all --no-pager",
            "audit-status.txt": "auditctl -s",
            "journal.txt": "journalctl --no-pager",
            "filesystem.txt": "find /var/spool/tartarus -xdev -printf '%y %s %p\\n'",
            "elastic-agent.txt": "systemctl status elastic-agent --no-pager",
        }
        for name, command in snapshots.items():
            remnux.run(
                (
                    "/bin/sh",
                    "-c",
                    f"{command} > {state_dir}/{name} 2>&1 || true",
                ),
                sudo=True,
                timeout=300,
            )
    except TartarusError:
        gaps.append("remnux_state_snapshot_failed")

    sources = [
        ("remnux-static", remnux, f"/var/spool/tartarus/static/{run_id}"),
        ("ghidra", remnux, f"/var/spool/tartarus/ghidra/{run_id}"),
        ("remnux-state", remnux, state_dir),
        ("remnux-inetsim", remnux, "/var/log/inetsim"),
    ]
    if run.get("execution_mode") != "static_only":
        sources.insert(0, ("sandbox", sandbox, f"/var/spool/tartarus/runs/{run_id}"))
    for role, remote, source in sources:
        if not _remote_directory_exists(remote, source):
            if role in {"sandbox", "remnux-static", "remnux-state"}:
                gaps.append(f"{role}_collection_missing")
            continue
        try:
            records.append(
                _pull_directory(
                    config,
                    remote,
                    source,
                    run_file.parent,
                    role,
                    run_id,
                    approve_quota_override=approve_quota_override,
                )
            )
        except TartarusError:
            gaps.append(f"{role}_collection_failed")

    capture_members = tuple(
        name
        for name in (f"{run_id}.pcapng", f"{run_id}-capture.log")
        if _remote_file_exists(remnux, f"/var/spool/tartarus/capture/{name}")
    )
    if capture_members:
        try:
            records.append(
                _pull_directory(
                    config,
                    remnux,
                    "/var/spool/tartarus/capture",
                    run_file.parent,
                    "remnux-capture",
                    run_id,
                    capture_members,
                    approve_quota_override=approve_quota_override,
                )
            )
        except TartarusError:
            gaps.append("remnux_capture_collection_failed")
    elif run.get("execution_mode") != "static_only":
        gaps.append("remnux_capture_collection_missing")
    return records, gaps


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


def _remote_file_exists(remote: Remote, path: str) -> bool:
    try:
        remote.run(("test", "-f", path), sudo=True)
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
