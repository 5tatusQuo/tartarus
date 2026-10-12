from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import yaml

from . import __version__
from .access import operator_access
from .artifacts import acquire_artifacts, locked_artifacts
from .bundle import create_bundle, verify_bundle
from .config import Config, default_config_path, load_config, save_config
from .doctor import inspect_environment
from .errors import ApprovalRequired, TartarusError
from .keys import ensure_controller_ssh_key
from .lifecycle import rebuild_sandbox, start_remote_run, stop_remote_run
from .ludus import authenticated_user, run_ludus
from .manifest import (
    collect_artifact,
    create_case,
    create_run,
    project_root,
    stage_sample,
    validate,
)
from .release import (
    finalize_deployment_manifest,
    source_inventory,
    source_revision,
    write_prepare_manifest,
)
from .remote import Remote, range_guests
from .reporting import generate_agent_report
from .telemetry import record_lifecycle, telemetry_health, telemetry_search
from .util import atomic_json, load_json, safe_id, utc_now
from .verify import verify_range


def emit(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def find_string(value: object, keys: set[str]) -> str | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys and isinstance(item, str) and item:
                return item
        for item in value.values():
            found = find_string(item, keys)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_string(item, keys)
            if found:
                return found
    return None


def collect_strings(value: object, keys: set[str]) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        found.update(item for key, item in value.items() if key in keys and isinstance(item, str))
        for item in value.values():
            found.update(collect_strings(item, keys))
    elif isinstance(value, list):
        for item in value:
            found.update(collect_strings(item, keys))
    return found


def approve(
    args: argparse.Namespace, summary: dict[str, object], destructive: bool = False
) -> None:
    request = {
        "schema_version": "1.0",
        "operation": str(summary.get("operation", "mutating operation")),
        "reason": "explicit operator approval is required before Tartarus changes state",
        "scope": summary,
    }
    validate("approval-request", request)
    emit(request)
    if destructive and not getattr(args, "confirm", False):
        raise ApprovalRequired("destructive action requires --confirm")
    if not destructive and not getattr(args, "yes", False):
        raise ApprovalRequired("mutating action requires --yes")


def operation_context(config: Config, range_id: str | None = None) -> dict[str, object]:
    manifest_path = config.cache_root / "state" / "prepare-manifest.json"
    release = "not-prepared"
    if manifest_path.is_file():
        release = str(load_json(manifest_path).get("tartarus_release", "unknown"))
    resources = {
        "compact": {"guest_ram_gib": 12, "guest_vcpus": 10},
        "standard": {"guest_ram_gib": 20, "guest_vcpus": 16},
        "large": {"guest_ram_gib": 46, "guest_vcpus": 20},
    }[config.profile]
    return {
        "server_config": str(config.ludus_config) if config.ludus_config else "ludus default",
        "authenticated_user": authenticated_user(config.ludus_config),
        "range_id": range_id,
        "release": release,
        "profile": config.profile,
        "resources": resources,
    }


def announce_local_change(config: Config, operation: str, scope: dict[str, object]) -> None:
    try:
        user = authenticated_user(config.ludus_config)
    except TartarusError:
        user = "unavailable (local operation continues)"
    emit(
        {
            "planned_change": {
                "server_config": str(config.ludus_config)
                if config.ludus_config
                else "ludus default",
                "authenticated_user": user,
                "range_id": scope.pop("range_id", None),
                "release": operation_context_release(config),
                "profile": config.profile,
                "resources": operation_context_resources(config),
                "operation": operation,
                **scope,
            }
        }
    )


def operation_context_release(config: Config) -> str:
    path = config.cache_root / "state" / "prepare-manifest.json"
    return (
        str(load_json(path).get("tartarus_release", "unknown"))
        if path.is_file()
        else "not-prepared"
    )


def operation_context_resources(config: Config) -> dict[str, int]:
    return {
        "compact": {"guest_ram_gib": 12, "guest_vcpus": 10},
        "standard": {"guest_ram_gib": 20, "guest_vcpus": 16},
        "large": {"guest_ram_gib": 46, "guest_vcpus": 20},
    }[config.profile]


def assert_managed_range(config: Config, range_id: str) -> None:
    result = run_ludus(("--range", range_id, "range", "config", "get"), config=config.ludus_config)
    try:
        document = yaml.safe_load(result.stdout)
        marker = document["ludus_extensions"]["tartarus"]["schema_version"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise TartarusError(f"range {range_id} is not Tartarus-managed") from exc
    if marker != 1:
        raise TartarusError(f"range {range_id} has an unsupported Tartarus marker")


def cmd_init(args: argparse.Namespace) -> None:
    config = Config(
        profile=args.profile,
        evidence_root=Path(args.evidence_root).expanduser(),
        cache_root=Path(args.cache_root).expanduser(),
        ludus_config=Path(args.ludus_config).expanduser() if args.ludus_config else None,
        proxmox_url=args.proxmox_url,
        proxmox_ca_file=Path(args.proxmox_ca_file).expanduser() if args.proxmox_ca_file else None,
        management_sources=tuple(args.management_source),
        always_blocked_networks=tuple(args.always_blocked_network),
        host_memory_gib=args.host_memory_gib,
        telemetry_retention_days=args.telemetry_retention_days,
        manifest_retention_days=args.manifest_retention_days,
    )
    target = Path(args.config).expanduser() if args.config else default_config_path()
    if target.exists() and not args.force:
        raise TartarusError(f"refusing to overwrite {target}; use --force")
    announce_local_change(
        config,
        "initialize controller configuration",
        {"config": str(target), "overwrite": bool(args.force and target.exists())},
    )
    saved = save_config(config, target)
    config.evidence_root.mkdir(parents=True, exist_ok=True)
    config.cache_root.mkdir(parents=True, exist_ok=True)
    config.evidence_root.chmod(0o700)
    config.cache_root.chmod(0o700)
    print(f"initialized {saved}")


def cmd_doctor(args: argparse.Namespace) -> None:
    config = load_config()
    report = inspect_environment(config, args.host_memory_gib)
    emit(report)
    if not report["ready"]:
        raise SystemExit(2)


def cmd_credentials(args: argparse.Namespace) -> None:
    emit(operator_access(load_config(), args.range_id))


def cmd_prepare(args: argparse.Namespace) -> None:
    config = load_config()
    root = project_root()
    existing_prepare_state = (config.cache_root / "state" / "prepare-manifest.json").is_file()
    revision = source_revision(args.development)
    offline = Path(args.offline).resolve() if args.offline else None
    if offline:
        verify_bundle(offline)
    required_templates = {"tartarus-debian-12-template"}
    template_inventory = _template_inventory(config)
    missing_templates = sorted(
        required_templates
        - {item.get("name") for item in template_inventory if item.get("built") is True}
    )
    existing_tartarus_templates = sorted(required_templates - set(missing_templates))
    if (
        existing_tartarus_templates
        and not existing_prepare_state
        and not args.adopt_existing_resources
    ):
        raise TartarusError(
            "Tartarus-named templates already exist but are not owned by this controller state; "
            "inspect them and retry with --adopt-existing-resources"
        )
    summary = {
        "server_config": str(config.ludus_config) if config.ludus_config else "ludus default",
        "source": str(root),
        "source_id": "tartarus",
        "profile": config.profile,
        "offline_bundle": str(offline) if offline else None,
        "release": revision,
        "authenticated_user": authenticated_user(config.ludus_config),
        "locked_artifacts": [item["filename"] for item in locked_artifacts()],
        "templates_to_build": missing_templates,
        "adopt_existing_resources": args.adopt_existing_resources,
        "management_sources": list(config.management_sources),
        "always_blocked_networks": list(config.always_blocked_networks),
        "resources": {
            "compact": {"guest_ram_gib": 12, "guest_vcpus": 10},
            "standard": {"guest_ram_gib": 20, "guest_vcpus": 16},
            "large": {"guest_ram_gib": 46, "guest_vcpus": 20},
        }[config.profile],
    }
    approve(args, summary)
    acquire_artifacts(config.cache_root, offline)
    _, controller_public_key = ensure_controller_ssh_key(config)
    with tempfile.TemporaryDirectory(prefix="tartarus-source-") as temporary:
        rendered = Path(temporary) / "tartarus"
        rendered.mkdir()
        for name in ("ansible", "blueprints", "templates"):
            shutil.copytree(root / name, rendered / name)
        shutil.copytree(root / "docs", rendered / "docs")
        for name in (
            "source.yml",
            "versions.lock.yml",
            "requirements.lock",
            "README.md",
            "SECURITY.md",
            "COMPACT-REFERENCE-PLAN.md",
            "PORTABLE-PUBLIC-PLAN.md",
        ):
            shutil.copy2(root / name, rendered / name)
        base_source_files = source_inventory(rendered)
        for range_config in (rendered / "blueprints").glob("*/range-config.yml"):
            document = yaml.safe_load(range_config.read_text(encoding="utf-8"))
            document["network"]["always_blocked_networks"] = list(config.always_blocked_networks)
            document["ludus_extensions"]["tartarus"]["management_sources"] = list(
                config.management_sources
            )
            document.setdefault("router", {})["iptables_commands"] = [
                "iptables -I LUDUS_DEFAULTS -s "
                + source
                + " -p tcp -m multiport --dports 22,5601 -j ACCEPT"
                for source in config.management_sources
            ]
            document.setdefault("global_role_vars", {})[
                "tartarus_common_controller_ssh_public_key"
            ] = controller_public_key
            document["global_role_vars"]["tartarus_elk_telemetry_retention_days"] = (
                config.telemetry_retention_days
            )
            document["global_role_vars"]["tartarus_elk_manifest_retention_days"] = (
                config.manifest_retention_days
            )
            range_config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        sources = run_ludus(("--json", "source", "list"), config=config.ludus_config)
        try:
            registered = json.loads(sources.stdout)
        except json.JSONDecodeError as exc:
            raise TartarusError("could not parse the Ludus source inventory") from exc
        registered_source_ids = collect_strings(registered, {"id", "sourceID", "source_id"})
        if "tartarus" in registered_source_ids:
            if not existing_prepare_state and not args.adopt_existing_resources:
                raise TartarusError(
                    "a Tartarus source already exists but is not owned by this controller state; "
                    "inspect it and retry with --adopt-existing-resources"
                )
            source_command = ("source", "update", "tartarus", "-d", str(rendered), "--force")
        else:
            source_command = (
                "source",
                "add",
                "-d",
                str(rendered),
                "--id",
                "tartarus",
                "--all",
            )
        result = run_ludus(source_command, config=config.ludus_config, timeout=900)
        print(result.stdout, end="")
        write_prepare_manifest(
            config.cache_root, config.profile, revision, rendered, base_source_files
        )
        if missing_templates:
            builds_before = _latest_template_builds(config)
            builds = run_ludus(
                ("templates", "build", "--names", ",".join(missing_templates)),
                config=config.ludus_config,
                timeout=180,
            )
            print(builds.stdout, end="")
            deadline = time.monotonic() + args.wait_seconds
            while time.monotonic() < deadline:
                inventory = _template_inventory(config)
                states = {item.get("name"): item for item in inventory}
                latest_builds = _latest_template_builds(config)
                failed = [
                    name
                    for name in missing_templates
                    if (
                        str(states.get(name, {}).get("status", "")).lower()
                        in {"aborted", "cancelled", "error", "failed", "failure"}
                        or (
                            _is_new_template_build(builds_before.get(name), latest_builds.get(name))
                            and str(latest_builds.get(name, {}).get("status", "")).lower()
                            in {"aborted", "cancelled", "error", "failed", "failure"}
                        )
                    )
                ]
                if failed:
                    raise TartarusError("template build failed: " + ", ".join(failed))
                if all(
                    states.get(name, {}).get("built") is True
                    and _is_new_template_build(builds_before.get(name), latest_builds.get(name))
                    and str(latest_builds.get(name, {}).get("status", "")).lower() == "success"
                    for name in missing_templates
                ):
                    break
                time.sleep(15)
            else:
                raise TartarusError("template builds did not finish before the deadline")


def _template_inventory(config: Config) -> list[dict[str, object]]:
    try:
        value = json.loads(
            run_ludus(("templates", "list", "--json"), config=config.ludus_config).stdout
        )
    except json.JSONDecodeError as exc:
        raise TartarusError("could not parse the Ludus template inventory") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TartarusError("could not parse the Ludus template inventory")
    return value


def _is_new_template_build(
    previous: dict[str, object] | None, latest: dict[str, object] | None
) -> bool:
    if not latest or latest.get("id") is None:
        return False
    return latest.get("id") != (previous or {}).get("id")


def _latest_template_builds(config: Config) -> dict[str, dict[str, object]]:
    try:
        value = json.loads(
            run_ludus(
                ("templates", "logs", "--history", "--json"),
                config=config.ludus_config,
            ).stdout
        )
    except json.JSONDecodeError as exc:
        raise TartarusError("could not parse the Ludus template build history") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TartarusError("could not parse the Ludus template build history")
    latest: dict[str, dict[str, object]] = {}
    for item in value:
        name = item.get("template")
        if not isinstance(name, str):
            continue
        if str(item.get("created", "")) > str(latest.get(name, {}).get("created", "")):
            latest[name] = item
    return latest


def cmd_deploy(args: argparse.Namespace) -> None:
    config = load_config()
    preflight = inspect_environment(config)
    failed = [check["name"] for check in preflight["checks"] if check["status"] != "pass"]
    if failed:
        raise TartarusError("deployment preflight did not pass: " + ", ".join(failed))
    blueprint = f"tartarus/tartarus-{config.profile}"
    summary = {
        **operation_context(config, args.resume_range_id),
        "range_name": args.name,
        "blueprint": blueprint,
        "operation": "resume Tartarus deployment"
        if args.resume_range_id
        else "create and deploy range",
    }
    approve(args, summary)
    if args.resume_range_id:
        range_id = safe_id(args.resume_range_id, "range ID")
        assert_managed_range(config, range_id)
    else:
        requested_range_id = "TARTARUS-" + time.strftime("%Y%m%d%H%M%S", time.gmtime())
        created = run_ludus(
            (
                "--json",
                "--range",
                requested_range_id,
                "range",
                "create",
                "-n",
                args.name,
                "-o",
                "Contained Linux ELF analysis",
            ),
            config=config.ludus_config,
            timeout=180,
        )
        try:
            response = json.loads(created.stdout)
        except json.JSONDecodeError:
            response = {}
        range_id = find_string(response, {"rangeID", "range_id"}) or requested_range_id
        accessible = json.loads(
            run_ludus(("range", "accessible", "--json"), config=config.ludus_config).stdout
        )
        if range_id not in collect_strings(accessible, {"rangeID", "range_id"}):
            raise TartarusError(
                "range creation did not yield an accessible range; inspect 'ludus range accessible'"
            )
        run_ludus(
            ("blueprint", "apply", blueprint, "--target-range", range_id),
            config=config.ludus_config,
            timeout=180,
        )
    atomic_json(
        config.cache_root / "state" / "deployment.json",
        {
            "range_id": range_id,
            "profile": config.profile,
            "blueprint": blueprint,
            "created_at": utc_now(),
            "status": "created",
        },
    )
    try:
        current_status = json.loads(
            run_ludus(
                ("--range", range_id, "testing", "status", "--json"),
                config=config.ludus_config,
            ).stdout
        )
    except json.JSONDecodeError as exc:
        raise TartarusError("could not parse Ludus deployment status") from exc
    current = current_status.get("rangeState")
    should_start_deployment = (args.resume_range_id and current == "SUCCESS") or (
        current != "SUCCESS" and str(current).upper() not in {"RUNNING", "DEPLOYING"}
    )
    if should_start_deployment and current_status.get("testingEnabled") is True:
        run_ludus(
            ("--range", range_id, "testing", "stop"),
            config=config.ludus_config,
            timeout=300,
        )
    deployment_started = False
    if should_start_deployment:
        print(f"starting deployment for range {range_id}")
        deploy_command = ["--range", range_id, "range", "deploy"]
        if args.resume_range_id:
            deploy_command.append("--force")
        result = run_ludus(deploy_command, config=config.ludus_config, timeout=180)
        print(result.stdout, end="")
        deployment_started = True
    deadline = time.monotonic() + args.wait_seconds
    observed_active_deployment = not deployment_started
    while time.monotonic() < deadline:
        status_result = run_ludus(
            ("--range", range_id, "testing", "status", "--json"),
            config=config.ludus_config,
        )
        try:
            status = json.loads(status_result.stdout)
        except json.JSONDecodeError as exc:
            raise TartarusError("could not parse Ludus deployment status") from exc
        state = status.get("rangeState")
        if state == "SUCCESS" and observed_active_deployment:
            break
        if state in {"ERROR", "FAILED", "FAILURE"}:
            raise TartarusError(f"range deployment failed with state {state}")
        if str(state).upper() in {"RUNNING", "DEPLOYING"}:
            observed_active_deployment = True
        time.sleep(15)
    else:
        raise TartarusError("range deployment did not finish before the deadline")
    final_status = json.loads(
        run_ludus(
            ("--range", range_id, "testing", "status", "--json"),
            config=config.ludus_config,
        ).stdout
    )
    if final_status.get("testingEnabled") is not True:
        run_ludus(
            ("--range", range_id, "testing", "start"),
            config=config.ludus_config,
            timeout=300,
        )
    inventory = range_guests(config, range_id)
    deployment_guests: dict[str, dict[str, object]] = {}
    for role, guest in sorted(inventory.items()):
        remote = Remote(config, guest)
        packages = remote.run(
            ("dpkg-query", "-W", "-f", "${Package}\\t${Version}\\n"), timeout=300
        ).stdout.splitlines()
        deployment_guests[role] = {
            "name": guest.name,
            "address": guest.address,
            "vmid": guest.vmid,
            "kernel": remote.run(("uname", "-r")).stdout.strip(),
            "packages": sorted(packages),
        }
    finalize_deployment_manifest(
        config.cache_root,
        range_id=range_id,
        authenticated_user=authenticated_user(config.ludus_config),
        guests=deployment_guests,
    )
    atomic_json(
        config.cache_root / "state" / "deployment.json",
        {
            "range_id": range_id,
            "profile": config.profile,
            "blueprint": blueprint,
            "completed_at": utc_now(),
            "status": "deployed",
        },
    )
    print(f"deployment completed and testing mode enabled for {range_id}")


def cmd_range_passthrough(args: argparse.Namespace) -> None:
    if args.range_action == "prepare":
        cmd_prepare(args)
        return
    if args.range_action == "deploy":
        cmd_deploy(args)
        return
    config = load_config()
    if args.range_action == "status":
        result = run_ludus(
            ("--range", args.range_id, "range", "status"), config=config.ludus_config
        )
    elif args.range_action == "verify":
        assert_managed_range(config, args.range_id)
        report = verify_range(config, args.range_id, args.host_memory_gib)
        emit(report)
        if not report["passed"]:
            raise SystemExit(2)
        return
    elif args.range_action == "destroy":
        assert_managed_range(config, args.range_id)
        approve(
            args,
            {
                **operation_context(config, args.range_id),
                "operation": "permanent range removal",
            },
            destructive=True,
        )
        result = run_ludus(
            ("--range", args.range_id, "range", "rm-range", "--force", "--no-prompt"),
            config=config.ludus_config,
            timeout=300,
        )
    else:
        raise TartarusError(f"unsupported range action: {args.range_action}")
    print(result.stdout, end="")


def cmd_case_create(args: argparse.Namespace) -> None:
    config = load_config()
    announce_local_change(
        config,
        "create evidence case",
        {"case_id": args.case_id or "generated", "evidence_root": str(config.evidence_root)},
    )
    emit(create_case(config.evidence_root, args.case_id))


def cmd_sample_stage(args: argparse.Namespace) -> None:
    config = load_config()
    announce_local_change(
        config,
        "stage ELF sample",
        {"case_id": args.case_id, "sample": str(Path(args.sample).resolve())},
    )
    emit(stage_sample(config.evidence_root, args.case_id, Path(args.sample)))


def cmd_run_start(args: argparse.Namespace) -> None:
    config = load_config()
    assert_managed_range(config, args.range_id)
    if args.telemetry_profile not in {"lightweight", "standard", "deep"}:
        raise TartarusError("unsupported telemetry profile")
    deployment_manifest = config.cache_root / "state" / "prepare-manifest.json"
    deployment = load_json(deployment_manifest)
    if deployment.get("deployment", {}).get("range_id") != args.range_id:
        raise TartarusError(
            "deployment manifest does not identify this range; deploy or prepare the selected range first"
        )
    approve(
        args,
        {
            **operation_context(config, args.range_id),
            "operation": "execute ELF in disposable sandbox",
            "case_id": args.case_id,
            "run_id": args.run_id or "generated",
            "sample_id": args.sample_id,
            "telemetry_profile": args.telemetry_profile,
            "duration_seconds": args.duration,
            "debug_session": args.debug,
            "post_run_action": "collect evidence, destroy sandbox, redeploy and verify",
        },
    )
    run = create_run(
        config.evidence_root,
        args.case_id,
        args.sample_id,
        args.telemetry_profile,
        deployment["tartarus_release"],
        args.run_id,
    )
    run_file = _run_file(config, args.case_id, run["run_id"])
    emit(start_remote_run(config, args.range_id, run_file, args.duration, args.debug))


def _run_file(config: Config, case_id: str, run_id: str) -> Path:
    safe_id(case_id, "case ID")
    safe_id(run_id, "run ID")
    return config.evidence_root / case_id / run_id / "run.json"


def cmd_run_collect(args: argparse.Namespace) -> None:
    config = load_config()
    run_file = _run_file(config, args.case_id, args.run_id)
    quota = config.artifact_quota_gib * 1024**3
    existing = sum(path.stat().st_size for path in run_file.parent.rglob("*") if path.is_file())
    source = Path(args.artifact).resolve(strict=True)
    if existing + source.stat().st_size > quota and not args.approve_quota_override:
        raise ApprovalRequired(
            "artifact would exceed the per-run quota; use --approve-quota-override"
        )
    announce_local_change(
        config,
        "collect controller-local artifact",
        {
            "range_id": load_json(run_file).get("range_id"),
            "case_id": args.case_id,
            "run_id": args.run_id,
            "artifact": str(source),
            "quota_override": args.approve_quota_override,
        },
    )
    emit(collect_artifact(run_file, source, args.media_type))


def cmd_run_stop(args: argparse.Namespace) -> None:
    config = load_config()
    run_file = _run_file(config, args.case_id, args.run_id)
    run_manifest = load_json(run_file)
    if run_manifest.get("range_id"):
        assert_managed_range(config, run_manifest["range_id"])
    approve(
        args,
        {
            **operation_context(config, run_manifest.get("range_id")),
            "operation": "stop run, collect evidence, generate report, destroy and rebuild sandbox",
            "case_id": args.case_id,
            "run_id": args.run_id,
            "quota_override": args.approve_quota_override,
        },
    )
    stop_remote_run(
        config,
        run_file,
        approve_quota_override=args.approve_quota_override,
    )
    generate_agent_report(run_file, run_file.parent / "report.md")
    completed = load_json(run_file)
    record_lifecycle(
        config,
        completed["range_id"],
        {
            "timestamp": utc_now(),
            "event": "run_report_generated",
            "case_id": completed["case_id"],
            "run_id": completed["run_id"],
            "sample_id": completed["sample"]["sample_id"],
            "artifacts": completed["artifacts"],
            "visibility_gaps": completed["visibility_gaps"],
        },
    )
    emit(completed)


def cmd_bundle(args: argparse.Namespace) -> None:
    config = load_config()
    if args.bundle_action == "create":
        announce_local_change(
            config, "create offline bundle", {"output": str(Path(args.output))}
        )
        print(create_bundle(Path(args.output), config.cache_root))
    else:
        emit(verify_bundle(Path(args.bundle)))


def cmd_telemetry(args: argparse.Namespace) -> None:
    config = load_config()
    if args.telemetry_action == "health":
        result = telemetry_health(config, args.range_id)
        emit(result)
        if not result["healthy"]:
            raise SystemExit(2)
    else:
        emit(telemetry_search(config, args.range_id, args.query, args.size))


def cmd_sandbox_rebuild(args: argparse.Namespace) -> None:
    config = load_config()
    assert_managed_range(config, args.range_id)
    guest = range_guests(config, args.range_id)["sandbox"]
    approve(
        args,
        {
            **operation_context(config, args.range_id),
            "vm": guest.name,
            "vmid": guest.vmid,
            "operation": "destroy and redeploy disposable sandbox",
        },
        destructive=True,
    )
    report = rebuild_sandbox(config, args.range_id, wait_seconds=args.wait_seconds)
    emit(report)
    if not report["passed"]:
        raise SystemExit(2)


def cmd_wireguard_export(args: argparse.Namespace) -> None:
    config = load_config()
    target = Path(args.output).expanduser()
    if target.exists():
        raise TartarusError(f"refusing to overwrite {target}")
    announce_local_change(
        config, "export WireGuard configuration", {"output": str(target), "mode": "0600"}
    )
    result = run_ludus(("users", "wireguard"), config=config.ludus_config, sensitive=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(result.stdout)
    os.chmod(target, 0o600)
    print(f"WireGuard configuration written to {target} (mode 0600)")


def cmd_report(args: argparse.Namespace) -> None:
    config = load_config()
    run_file = _run_file(config, args.case_id, args.run_id)
    output = (
        Path(args.output)
        if args.output
        else _run_file(config, args.case_id, args.run_id).parent / "report.md"
    )
    announce_local_change(
        config,
        "generate run report",
        {
            "range_id": load_json(run_file).get("range_id"),
            "case_id": args.case_id,
            "run_id": args.run_id,
            "output": str(output),
            "agent": "codex",
            "model": args.model or "configured Codex default",
            "reasoning_effort": args.reasoning_effort,
            "local_provider": args.local_provider or "configured Codex provider",
        },
    )
    emit(
        generate_agent_report(
            run_file,
            output,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            local_provider=args.local_provider,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="tartarus")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--profile", choices=("compact", "standard", "large"), default="compact")
    init.add_argument("--config")
    init.add_argument("--evidence-root", required=True)
    init.add_argument("--cache-root", required=True)
    init.add_argument("--ludus-config")
    init.add_argument("--proxmox-url")
    init.add_argument("--proxmox-ca-file")
    init.add_argument("--management-source", action="append", required=True)
    init.add_argument("--always-blocked-network", action="append", required=True)
    init.add_argument("--host-memory-gib", type=float)
    init.add_argument("--telemetry-retention-days", type=int, default=14)
    init.add_argument("--manifest-retention-days", type=int, default=30)
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--host-memory-gib", type=float)
    doctor.set_defaults(func=cmd_doctor)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--offline")
    prepare.add_argument("--yes", action="store_true")
    prepare.add_argument("--development", action="store_true")
    prepare.add_argument("--adopt-existing-resources", action="store_true")
    prepare.add_argument("--wait-seconds", type=int, default=7200)
    prepare.set_defaults(func=cmd_prepare)
    deploy = commands.add_parser("deploy")
    deploy.add_argument("--name", default="Tartarus")
    deploy.add_argument("--yes", action="store_true")
    deploy.add_argument("--wait-seconds", type=int, default=3600)
    deploy.add_argument("--resume-range-id")
    deploy.set_defaults(func=cmd_deploy)
    range_cmd = commands.add_parser("range")
    range_actions = range_cmd.add_subparsers(dest="range_action", required=True)
    for action in ("prepare", "deploy", "status", "verify", "destroy"):
        child = range_actions.add_parser(action)
        if action not in {"prepare", "deploy"}:
            child.add_argument("--range-id", required=True)
        if action == "prepare":
            child.add_argument("--offline")
            child.add_argument("--yes", action="store_true")
            child.add_argument("--development", action="store_true")
            child.add_argument("--adopt-existing-resources", action="store_true")
            child.add_argument("--wait-seconds", type=int, default=7200)
        if action == "deploy":
            child.add_argument("--name", default="Tartarus")
            child.add_argument("--yes", action="store_true")
            child.add_argument("--wait-seconds", type=int, default=3600)
            child.add_argument("--resume-range-id")
        if action == "verify":
            child.add_argument("--host-memory-gib", type=float)
        if action == "destroy":
            child.add_argument("--confirm", action="store_true")
        child.set_defaults(func=cmd_range_passthrough)
    case = commands.add_parser("case")
    case_actions = case.add_subparsers(dest="case_action", required=True)
    case_create = case_actions.add_parser("create")
    case_create.add_argument("--case-id")
    case_create.set_defaults(func=cmd_case_create)
    sample = commands.add_parser("sample")
    sample_actions = sample.add_subparsers(dest="sample_action", required=True)
    sample_stage = sample_actions.add_parser("stage")
    sample_stage.add_argument("--case-id", required=True)
    sample_stage.add_argument("sample")
    sample_stage.set_defaults(func=cmd_sample_stage)
    run = commands.add_parser("run")
    run_actions = run.add_subparsers(dest="run_action", required=True)
    start = run_actions.add_parser("start")
    start.add_argument("--case-id", required=True)
    start.add_argument("--sample-id", required=True)
    start.add_argument("--run-id")
    start.add_argument("--range-id", required=True)
    start.add_argument("--duration", type=int, default=300)
    start.add_argument("--debug", action="store_true")
    start.add_argument("--yes", action="store_true")
    start.add_argument("--telemetry-profile", default="standard")
    start.set_defaults(func=cmd_run_start)
    collect = run_actions.add_parser("collect")
    collect.add_argument("--case-id", required=True)
    collect.add_argument("--run-id", required=True)
    collect.add_argument("artifact")
    collect.add_argument("--media-type", default="application/octet-stream")
    collect.add_argument("--approve-quota-override", action="store_true")
    collect.set_defaults(func=cmd_run_collect)
    stop = run_actions.add_parser("stop")
    stop.add_argument("--case-id", required=True)
    stop.add_argument("--run-id", required=True)
    stop.add_argument("--approve-quota-override", action="store_true")
    stop.add_argument("--yes", action="store_true")
    stop.set_defaults(func=cmd_run_stop)
    bundle = commands.add_parser("bundle")
    bundle_actions = bundle.add_subparsers(dest="bundle_action", required=True)
    bundle_create = bundle_actions.add_parser("create")
    bundle_create.add_argument("--output", required=True)
    bundle_create.set_defaults(func=cmd_bundle)
    bundle_verify = bundle_actions.add_parser("verify")
    bundle_verify.add_argument("bundle")
    bundle_verify.set_defaults(func=cmd_bundle)
    telemetry = commands.add_parser("telemetry")
    telemetry_actions = telemetry.add_subparsers(dest="telemetry_action", required=True)
    health = telemetry_actions.add_parser("health")
    health.add_argument("--range-id", required=True)
    health.set_defaults(func=cmd_telemetry)
    search = telemetry_actions.add_parser("search")
    search.add_argument("--range-id", required=True)
    search.add_argument("query")
    search.add_argument("--size", type=int, default=50)
    search.set_defaults(func=cmd_telemetry)
    credentials = commands.add_parser("credentials")
    credential_actions = credentials.add_subparsers(
        dest="credentials_action", required=True
    )
    credentials_show = credential_actions.add_parser("show")
    credentials_show.add_argument("--range-id", required=True)
    credentials_show.set_defaults(func=cmd_credentials)
    sandbox = commands.add_parser("sandbox")
    sandbox_actions = sandbox.add_subparsers(dest="sandbox_action", required=True)
    rebuild = sandbox_actions.add_parser("rebuild")
    rebuild.add_argument("--range-id", required=True)
    rebuild.add_argument("--confirm", action="store_true")
    rebuild.add_argument("--wait-seconds", type=int, default=1800)
    rebuild.add_argument("--host-memory-gib", type=float)
    rebuild.set_defaults(func=cmd_sandbox_rebuild)
    report = commands.add_parser("report")
    report_actions = report.add_subparsers(dest="report_action", required=True)
    generate = report_actions.add_parser("generate")
    generate.add_argument("--case-id", required=True)
    generate.add_argument("--run-id", required=True)
    generate.add_argument("--output")
    generate.add_argument("--model")
    generate.add_argument("--local-provider", choices=("ollama", "lmstudio"))
    generate.add_argument(
        "--reasoning-effort", choices=("low", "medium", "high", "xhigh"), default="high"
    )
    generate.set_defaults(func=cmd_report)
    wireguard = commands.add_parser("wireguard")
    wg_actions = wireguard.add_subparsers(dest="wireguard_action", required=True)
    export = wg_actions.add_parser("export")
    export.add_argument("--output", required=True)
    export.set_defaults(func=cmd_wireguard_export)
    verify = commands.add_parser("verify")
    verify.add_argument("--range-id", required=True)
    verify.add_argument("--host-memory-gib", type=float)
    verify.set_defaults(
        func=lambda args: cmd_range_passthrough(
            argparse.Namespace(
                range_action="verify", range_id=args.range_id, host_memory_gib=args.host_memory_gib
            )
        )
    )
    destroy = commands.add_parser("destroy")
    destroy.add_argument("--range-id", required=True)
    destroy.add_argument("--confirm", action="store_true")
    destroy.set_defaults(
        func=lambda args: cmd_range_passthrough(
            argparse.Namespace(range_action="destroy", range_id=args.range_id, confirm=args.confirm)
        )
    )
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        args.func(args)
        return 0
    except ApprovalRequired as exc:
        print(f"approval required: {exc}", file=sys.stderr)
        return 3
    except TartarusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
