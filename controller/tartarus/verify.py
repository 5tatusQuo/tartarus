from __future__ import annotations

import ipaddress
import json
import secrets
import time
from collections.abc import Callable
from typing import Any

from .config import Config
from .doctor import inspect_environment
from .ludus import run_ludus
from .manifest import validate
from .remote import Remote, range_guests
from .telemetry import elastic_request, telemetry_health, telemetry_search
from .util import atomic_json, utc_now


def verify_range(
    config: Config, range_id: str, host_memory_gib: float | None = None
) -> dict[str, Any]:
    guests = range_guests(config, range_id)
    remnux = Remote(config, guests["remnux"])
    sandbox = Remote(config, guests["sandbox"])
    elk = Remote(config, guests["elk"])
    checks: list[dict[str, Any]] = []

    environment = inspect_environment(config, host_memory_gib)
    checks.extend(environment["checks"])
    _check(checks, "ludus_testing_mode", lambda: _testing_enabled(config, range_id))
    _check(checks, "sandbox_clean", lambda: _sandbox_clean(sandbox))
    for role, remote in (("elk", elk), ("remnux", remnux), ("sandbox", sandbox)):
        _check(checks, f"{role}_clock_synchronized", lambda remote=remote: _clock_ok(remote))
        _check(
            checks,
            f"{role}_public_ipv4_blocked",
            lambda remote=remote: _expect_failure(
                remote,
                (
                    "curl",
                    "-fsS",
                    "--connect-timeout",
                    "3",
                    "--max-time",
                    "5",
                    "http://1.1.1.1/",
                ),
            ),
        )
    _check(
        checks,
        "sandbox_public_ipv4_blocked",
        lambda: _expect_failure(
            sandbox,
            ("curl", "-fsS", "--connect-timeout", "3", "--max-time", "5", "http://1.1.1.1/"),
        ),
    )
    _check(
        checks,
        "sandbox_public_dns_blocked",
        lambda: _expect_failure(sandbox, ("getent", "ahosts", "example.com")),
    )
    for index, network in enumerate(config.always_blocked_networks):
        target = _probe_address(network)
        _check(
            checks,
            f"infrastructure_network_{index}_blocked",
            lambda target=target: _expect_failure(sandbox, ("ping", "-c", "1", "-W", "2", target)),
        )
    for index, network in enumerate(config.management_sources):
        target = _probe_address(network)
        _check(
            checks,
            f"management_network_{index}_blocked_from_sandbox",
            lambda target=target: _expect_failure(sandbox, ("ping", "-c", "1", "-W", "2", target)),
        )
    _check(
        checks,
        "sandbox_ipv6_disabled",
        lambda: (
            sandbox.run(("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")).stdout.strip() == "1"
        ),
    )
    _check(checks, "router_is_enforcement_boundary", lambda: _output_policy_accepts(sandbox))
    _check(
        checks,
        "sandbox_to_elastic_allowed",
        lambda: (
            sandbox.run(
                (
                    "curl",
                    "-k",
                    "-sS",
                    "--connect-timeout",
                    "3",
                    "-o",
                    "/dev/null",
                    "https://" + guests["elk"].address + ":9200",
                )
            ).returncode
            == 0
        ),
    )
    _check(
        checks,
        "sandbox_to_kibana_rejected",
        lambda: _expect_failure(
            sandbox,
            (
                "curl",
                "-fsS",
                "--connect-timeout",
                "3",
                "http://" + guests["elk"].address + ":5601",
            ),
        ),
    )
    _check(
        checks,
        "inetsim_http_and_capture",
        lambda: _verify_capture(remnux, sandbox, guests["remnux"].address),
    )
    _check(checks, "bounded_strace", lambda: _verify_bounded_runner(sandbox))
    _check(
        checks,
        "gdbserver_restricted_lifecycle",
        lambda: _verify_gdb(remnux, sandbox, guests["sandbox"].address),
    )
    _check(
        checks, "elastic_telemetry_health", lambda: telemetry_health(config, range_id)["healthy"]
    )
    _check(
        checks,
        "pinned_elastic_version",
        lambda: elastic_request(config, range_id, "").get("version", {}).get("number") == "9.5.5",
    )
    _check(
        checks,
        "pinned_elastic_agent_versions",
        lambda: all(
            "9.5.5" in remote.run(("elastic-agent", "version")).stdout
            for remote in (remnux, sandbox)
        ),
    )
    _check(
        checks,
        "pinned_reverse_engineering_versions",
        lambda: _reverse_engineering_versions_ok(remnux),
    )
    _check(checks, "static_analysis_fixture", lambda: _verify_static_analysis(remnux))
    _check(checks, "telemetry_search_latency", lambda: _verify_search(config, range_id, sandbox))
    for role, remote in (("elk", elk), ("remnux", remnux), ("sandbox", sandbox)):
        _check(checks, f"{role}_audit_no_loss", lambda remote=remote: _audit_ok(remote))

    passed = all(check["status"] == "pass" for check in checks)
    report = {
        "schema_version": "1.0",
        "range_id": range_id,
        "generated_at": utc_now(),
        "passed": passed,
        "checks": checks,
    }
    validate("verification-report", report)
    output = config.evidence_root / "verification" / f"{range_id}.json"
    atomic_json(output, report)
    return report


def _check(checks: list[dict[str, Any]], name: str, operation: Callable[[], bool]) -> None:
    try:
        passed = bool(operation())
        checks.append({"name": name, "status": "pass" if passed else "fail"})
    except Exception as exc:  # noqa: BLE001 - preserve all independent probe results
        checks.append({"name": name, "status": "fail", "detail": str(exc)})


def _expect_failure(remote: Remote, command: tuple[str, ...]) -> bool:
    try:
        remote.run(command, timeout=10)
    except Exception:  # noqa: BLE001 - failure is the expected result of a negative probe
        return True
    return False


def _testing_enabled(config: Config, range_id: str) -> bool:
    result = run_ludus(
        ("--range", range_id, "testing", "status", "--json"),
        config=config.ludus_config,
    )
    return json.loads(result.stdout).get("testingEnabled") is True


def _probe_address(network: str) -> str:
    value = ipaddress.ip_network(network)
    if value.num_addresses <= 2:
        return str(value.network_address)
    return str(value.network_address + 1)


def _output_policy_accepts(remote: Remote) -> bool:
    try:
        output = remote.run(("iptables", "-S", "OUTPUT"), sudo=True).stdout
        return (
            "-P OUTPUT ACCEPT" in output
            and "-j DROP" not in output
            and "-j REJECT" not in output
        )
    except Exception:  # noqa: BLE001 - Debian may use nftables without iptables compatibility
        ruleset = remote.run(("nft", "list", "ruleset"), sudo=True).stdout
        return "hook output" not in ruleset


def _clock_ok(remote: Remote) -> bool:
    before = time.time()
    remote_epoch = int(remote.run(("date", "+%s")).stdout.strip())
    after = time.time()
    controller_midpoint = (before + after) / 2
    return abs(remote_epoch - controller_midpoint) <= 5


def _sandbox_clean(remote: Remote) -> bool:
    samples = remote.run(
        (
            "find",
            "/var/spool/tartarus/runs",
            "-mindepth",
            "2",
            "-maxdepth",
            "2",
            "-name",
            "sample",
            "-print",
            "-quit",
        ),
        sudo=True,
    ).stdout
    return not samples.strip() and _expect_failure(remote, ("pgrep", "-u", "tartarus-runner"))


def _verify_capture(remnux: Remote, sandbox: Remote, remnux_ip: str) -> bool:
    fixture = "verify-capture"
    interface = __import__("json").loads(
        remnux.run(("ip", "-j", "route", "show", "default")).stdout
    )[0]["dev"]
    remnux.run(("/usr/local/sbin/tartarus-capture", "start", fixture, interface), sudo=True)
    try:
        sandbox.run(("curl", "-fsS", "--max-time", "5", f"http://{remnux_ip}/"))
    finally:
        remnux.run(("/usr/local/sbin/tartarus-capture", "stop", fixture), sudo=True)
    result = remnux.run(("test", "-s", f"/var/spool/tartarus/capture/{fixture}.pcapng"), sudo=True)
    remnux.run(
        (
            "rm",
            "-f",
            f"/var/spool/tartarus/capture/{fixture}.pcapng",
            f"/var/spool/tartarus/capture/{fixture}-capture.log",
        ),
        sudo=True,
    )
    return result.returncode == 0


def _verify_bounded_runner(sandbox: Remote) -> bool:
    run_id = "verify-runner"
    run_dir = f"/var/spool/tartarus/runs/{run_id}"
    sandbox.run(("install", "-d", "-m", "0700", run_dir), sudo=True)
    sandbox.run(("cp", "/bin/true", f"{run_dir}/sample"), sudo=True)
    digest = sandbox.run(("sha256sum", f"{run_dir}/sample"), sudo=True).stdout.split()[0]
    sandbox.run(
        ("/usr/local/sbin/tartarus-run", "start", run_id, digest, "standard", "30"), sudo=True
    )
    time.sleep(1)
    sandbox.run(("/usr/local/sbin/tartarus-run", "stop", run_id), sudo=True)
    traces = sandbox.run(
        ("find", run_dir, "-maxdepth", "1", "-name", "strace.*", "-size", "+0c", "-print", "-quit"),
        sudo=True,
    ).stdout
    sandbox.run(("rm", "-rf", run_dir), sudo=True)
    return bool(traces.strip())


def _verify_gdb(remnux: Remote, sandbox: Remote, sandbox_ip: str) -> bool:
    sandbox.run(
        (
            "systemd-run",
            "--unit",
            "tartarus-gdb-verify",
            "--collect",
            "gdbserver",
            ":2345",
            "/bin/sleep",
            "10",
        ),
        sudo=True,
    )
    time.sleep(1)
    try:
        result = remnux.run(
            (
                "gdb",
                "-q",
                "-batch",
                "-ex",
                f"target remote {sandbox_ip}:2345",
                "-ex",
                "info registers",
                "-ex",
                "detach",
            )
        )
        observed = "rax" in result.stdout or "rip" in result.stdout
    finally:
        sandbox.run(("systemctl", "stop", "tartarus-gdb-verify.service"), sudo=True)
    return observed and _expect_failure(remnux, ("nc", "-z", "-w", "2", sandbox_ip, "2345"))


def _verify_search(config: Config, range_id: str, sandbox: Remote) -> bool:
    marker = "tartarus-verify-" + secrets.token_hex(8)
    sandbox.run(("logger", marker))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if telemetry_search(config, range_id, f'message:"{marker}"', 5)["count"]:
            return True
        time.sleep(5)
    return False


def _audit_ok(remote: Remote) -> bool:
    output = remote.run(("auditctl", "-s"), sudo=True).stdout
    values = dict(line.split(maxsplit=1) for line in output.splitlines() if " " in line)
    return values.get("lost") == "0" and values.get("backlog") == "0"


def _reverse_engineering_versions_ok(remnux: Remote) -> bool:
    version = remnux.run(
        (
            "grep",
            "^application.version=11.4.2$",
            "/opt/ghidra_11.4.2_PUBLIC/Ghidra/application.properties",
        )
    )
    return (
        "6.0.4" in remnux.run(("r2", "-v")).stdout
        and "15.2" in remnux.run(("gdb", "--version")).stdout.splitlines()[0]
        and "7.2.2" in _command_version(remnux, ("zeek", "--version"))
        and "1.3.2" in _command_version(remnux, ("inetsim", "--version"))
        and bool(version.stdout.strip())
    )


def _command_version(remote: Remote, command: tuple[str, ...]) -> str:
    result = remote.run(command)
    return result.stdout + result.stderr


def _verify_static_analysis(remnux: Remote) -> bool:
    project = "/var/spool/tartarus/ghidra/verify-static"
    analyze = remnux.run(("which", "analyzeHeadless")).stdout.strip()
    remnux.run(("rm", "-rf", project))
    remnux.run(("mkdir", "-p", project))
    try:
        radare = remnux.run(
            (
                "r2",
                "-q",
                "-e",
                "io.cache=true",
                "-c",
                "e cfg.sandbox=true;aaa;aflj",
                "/bin/true",
            ),
            timeout=120,
        ).stdout
        json.loads(radare)
        remnux.run((analyze, project, "tartarus", "-import", "/bin/true"), timeout=600)
        functions = remnux.run(
            (
                analyze,
                project,
                "tartarus",
                "-process",
                "true",
                "-noanalysis",
                "-scriptPath",
                "/opt/tartarus/ghidra-scripts",
                "-postScript",
                "TartarusFunctions.java",
            ),
            timeout=300,
        ).stdout
        return "TARTARUS" in functions
    finally:
        remnux.run(("rm", "-rf", project))
