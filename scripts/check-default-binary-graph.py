#!/usr/bin/env python3
"""Verify that packaged operator binaries cannot select compatibility targets."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
LEGACY_FEATURE = "legacy-v1"
PACKAGE_CONTRACTS = {
    "thunderboltd": {
        "default_bin": "thunderboltd",
        "legacy_bin": "thunderboltd-legacy-v1",
        "default_dependencies": {
            "clap",
            "serde_json",
            "thiserror",
            "thunderbolt-control",
            "thunderbolt-runtime",
            "thunderbolt-runtime-config",
            "tokio",
            "tokio-util",
            "tracing",
            "tracing-subscriber",
        },
        "legacy_dependencies": {
            "getrandom",
            "thunderbolt-config",
            "thunderbolt-node",
            "thunderbolt-storage",
            "toml",
            "zeroize",
        },
        "subcommands": {
            "check": {"config", "help"},
            "start": {"config", "help", "log-format"},
        },
        "additional_forbidden_commands": {"init"},
        "additional_forbidden_options": set(),
        "required_config": False,
    },
    "thunderbolt-cli": {
        "default_bin": "thunderbolt-cli",
        "legacy_bin": "thunderbolt-cli-legacy-v1",
        "default_dependencies": {
            "clap",
            "hex",
            "serde_json",
            "thiserror",
            "thunderbolt-control",
            "thunderbolt-runtime",
            "thunderbolt-runtime-config",
            "tokio",
        },
        "legacy_dependencies": {
            "libc",
            "reqwest",
            "thunderbolt-config",
            "thunderbolt-protocol",
            "zeroize",
        },
        "subcommands": {
            "status": {"config", "help"},
            "blockers": {"config", "help"},
            "redacted-config": {"config", "help"},
            "drain": {"config", "help"},
            "stop": {"config", "help"},
        },
        "additional_forbidden_commands": {"init", "start"},
        "additional_forbidden_options": set(),
        "required_config": False,
    },
    "thunderbolt-floor-node": {
        "default_bin": "thunderbolt-floor-node",
        "legacy_bin": None,
        "default_dependencies": {
            "clap",
            "hex",
            "rustix",
            "serde",
            "serde_json",
            "sha2",
            "tendermint",
            "tendermint-proto",
            "thiserror",
            "thunderbolt-abci-server",
            "thunderbolt-floor",
            "thunderbolt-floor-abci",
            "thunderbolt-floor-app",
            "thunderbolt-keystore",
            "tokio",
            "toml",
        },
        "legacy_dependencies": set(),
        "subcommands": {
            "check": {"help"},
            "genesis": {"help"},
            "start": {"help"},
        },
        "additional_forbidden_commands": {"init", "profile", "serve", "status"},
        "additional_forbidden_options": {
            "comet-genesis",
            "crash-before-commit-height",
            "crash-before-commit-marker",
            "db",
            "listen",
        },
        "required_config": True,
    },
}
EXPECTED_OPTIONS = {"config", "help", "version"}
EXPECTED_SHORT_OPTIONS = {"h", "V"}
FORBIDDEN_TRANSITIVE_PACKAGES = {
    "thunderbolt-config",
    "thunderbolt-node",
    "thunderbolt-storage",
}
FORBIDDEN_TRANSITIVE_FEATURES = {"insecure-live-test"}
FORBIDDEN_HELP_TERMS = {
    "legacy",
    "v1",
    "v2",
    "version 1",
    "version 2",
    "demo",
    "http",
    "submit",
    "database",
    "channel",
    "endpoint",
    "token",
    "payload",
    "timeout",
}


class GateError(RuntimeError):
    """One default-binary invariant failed."""


def run(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        details = []
        for label, value in [("stderr", completed.stderr), ("stdout", completed.stdout)]:
            value = value.strip()
            if not value:
                continue
            if len(value) > 12_000:
                value = f"[... truncated ...]\n{value[-12_000:]}"
            details.append(f"{label}:\n{value}")
        detail = "\n".join(details)
        raise GateError(f"command failed ({' '.join(command)}):\n{detail}")
    return completed


def metadata_for(package_name: str) -> dict[str, Any]:
    manifest = REPO_ROOT / "crates" / package_name / "Cargo.toml"
    completed = run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--no-default-features",
            "--manifest-path",
            str(manifest),
        ]
    )
    return json.loads(completed.stdout)


def package_from(metadata: dict[str, Any], package_name: str) -> dict[str, Any]:
    matches = [package for package in metadata["packages"] if package["name"] == package_name]
    if len(matches) != 1:
        raise GateError(f"expected exactly one metadata package named {package_name}, found {len(matches)}")
    return matches[0]


def resolve_node(metadata: dict[str, Any], package: dict[str, Any]) -> dict[str, Any]:
    resolve = metadata.get("resolve")
    if resolve is None:
        raise GateError("cargo metadata omitted the dependency resolution graph")
    matches = [node for node in resolve["nodes"] if node["id"] == package["id"]]
    if len(matches) != 1:
        raise GateError(f"expected exactly one resolution node for {package['name']}")
    return matches[0]


def resolved_normal_closure_ids(metadata: dict[str, Any], root_id: str) -> set[str]:
    nodes_by_id = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    closure = set()
    pending = [root_id]
    while pending:
        current_id = pending.pop()
        if current_id in closure:
            continue
        closure.add(current_id)
        current = nodes_by_id[current_id]
        pending.extend(
            dependency["pkg"]
            for dependency in current["deps"]
            if any(kind.get("kind") is None for kind in dependency["dep_kinds"])
        )
    return closure


def resolved_normal_closure_names(metadata: dict[str, Any], root_id: str) -> set[str]:
    package_names_by_id = {package["id"]: package["name"] for package in metadata["packages"]}
    return {
        package_names_by_id[package_id]
        for package_id in resolved_normal_closure_ids(metadata, root_id)
    }


def forbidden_normal_features(metadata: dict[str, Any], root_id: str) -> set[str]:
    nodes_by_id = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    return {
        feature
        for package_id in resolved_normal_closure_ids(metadata, root_id)
        for feature in nodes_by_id[package_id].get("features", [])
        if feature in FORBIDDEN_TRANSITIVE_FEATURES
    }


def verify_metadata(package_name: str, contract: dict[str, Any]) -> None:
    metadata = metadata_for(package_name)
    package = package_from(metadata, package_name)
    node = resolve_node(metadata, package)

    if package.get("default_run") != contract["default_bin"]:
        raise GateError(f"{package_name} default-run must be {contract['default_bin']}")
    expected_features = {"default", LEGACY_FEATURE} if contract["legacy_bin"] is not None else set()
    if set(package["features"]) != expected_features:
        raise GateError(f"{package_name} public feature set changed: {sorted(package['features'])}")
    if contract["legacy_bin"] is not None and package["features"].get("default") != []:
        raise GateError(f"{package_name} default features must remain empty")
    if node.get("features") != []:
        raise GateError(f"{package_name} resolved unexpected default features: {node.get('features')}")

    if contract["legacy_bin"] is not None:
        expected_feature = {f"dep:{dependency}" for dependency in contract["legacy_dependencies"]}
        actual_feature = set(package["features"].get(LEGACY_FEATURE, []))
        if actual_feature != expected_feature:
            raise GateError(
                f"{package_name} {LEGACY_FEATURE} edges changed: "
                f"expected {sorted(expected_feature)}, found {sorted(actual_feature)}"
            )

    binary_targets = [target for target in package["targets"] if "bin" in target["kind"]]
    actual_targets = {
        target["name"]: set(target.get("required-features", [])) for target in binary_targets
    }
    expected_targets = {contract["default_bin"]: set()}
    if contract["legacy_bin"] is not None:
        expected_targets[contract["legacy_bin"]] = {LEGACY_FEATURE}
    if actual_targets != expected_targets:
        raise GateError(f"{package_name} binary target contract changed: {actual_targets}")

    normal_dependencies = {
        dependency["name"]: dependency
        for dependency in package["dependencies"]
        if dependency.get("kind") is None
    }
    for dependency_name in contract["legacy_dependencies"]:
        dependency = normal_dependencies.get(dependency_name)
        if dependency is None or not dependency.get("optional", False):
            raise GateError(f"{package_name} legacy dependency {dependency_name} must be optional and normal")

    package_names_by_id = {candidate["id"]: candidate["name"] for candidate in metadata["packages"]}
    resolved_normal_dependencies = {
        package_names_by_id[dependency["pkg"]]
        for dependency in node["deps"]
        if any(kind.get("kind") is None for kind in dependency["dep_kinds"])
    }
    activated_legacy = resolved_normal_dependencies & contract["legacy_dependencies"]
    if activated_legacy:
        raise GateError(
            f"{package_name} default graph activated legacy-only direct dependencies: {sorted(activated_legacy)}"
        )
    if resolved_normal_dependencies != contract["default_dependencies"]:
        raise GateError(
            f"{package_name} activated normal direct dependencies changed: "
            f"expected {sorted(contract['default_dependencies'])}, found {sorted(resolved_normal_dependencies)}"
        )

    closure_ids = resolved_normal_closure_ids(metadata, package["id"])
    closure_names = {package_names_by_id[package_id] for package_id in closure_ids}
    forbidden_transitive = closure_names & FORBIDDEN_TRANSITIVE_PACKAGES
    if forbidden_transitive:
        raise GateError(
            f"{package_name} default recursive normal graph reached legacy application crates: "
            f"{sorted(forbidden_transitive)}"
        )
    forbidden_features = forbidden_normal_features(metadata, package["id"])
    if forbidden_features:
        raise GateError(
            f"{package_name} default recursive normal graph enabled forbidden features: "
            f"{sorted(forbidden_features)}"
        )


def build_default_binaries(target_directory: Path) -> dict[str, Path]:
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target_directory)
    environment.setdefault("CARGO_BUILD_JOBS", "4")
    build_command = ["cargo", "build", "--locked", "--no-default-features", "--bins"]
    for package_name in PACKAGE_CONTRACTS:
        build_command.extend(["--package", package_name])
    build_command.append("--message-format=json-render-diagnostics")
    completed = run(build_command, env=environment)

    metadata_by_package = {package_name: metadata_for(package_name) for package_name in PACKAGE_CONTRACTS}
    package_names_by_id = {}
    for metadata in metadata_by_package.values():
        package_names_by_id.update({package["id"]: package["name"] for package in metadata["packages"]})

    root_package_ids = {
        package_from(metadata, package_name)["id"]: package_name
        for package_name, metadata in metadata_by_package.items()
    }

    artifacts: dict[str, Path] = {}
    built_packages = set()
    for line in completed.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise GateError(f"cargo emitted non-JSON build output: {line!r}") from error
        if message.get("reason") != "compiler-artifact":
            continue
        package_id = message.get("package_id")
        if package_id not in package_names_by_id:
            raise GateError(f"compiler artifact referenced an unknown package id: {package_id}")
        built_packages.add(package_names_by_id[package_id])
        target_name = message["target"]["name"]
        if "live-test" in target_name or FORBIDDEN_TRANSITIVE_FEATURES & set(message.get("features", [])):
            raise GateError(f"default build selected a forbidden target or feature: {target_name}")
        if message.get("executable") is None:
            continue
        if package_id not in root_package_ids or "bin" not in message["target"]["kind"]:
            continue
        name = message["target"]["name"]
        if name in artifacts:
            raise GateError(f"cargo emitted duplicate executable artifacts for {name}")
        artifacts[name] = Path(message["executable"])

    expected = {contract["default_bin"] for contract in PACKAGE_CONTRACTS.values()}
    if set(artifacts) != expected:
        raise GateError(f"default build artifacts changed: expected {sorted(expected)}, found {sorted(artifacts)}")
    for name, executable in artifacts.items():
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise GateError(f"default artifact is not executable: {name} at {executable}")
    forbidden_built = built_packages & FORBIDDEN_TRANSITIVE_PACKAGES
    if forbidden_built:
        raise GateError(f"default build compiled legacy application crates: {sorted(forbidden_built)}")
    return artifacts


def verify_legacy_targets_require_feature(target_directory: Path) -> None:
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target_directory)
    environment.setdefault("CARGO_BUILD_JOBS", "4")
    for package_name, contract in PACKAGE_CONTRACTS.items():
        if contract["legacy_bin"] is None:
            continue
        command = [
            "cargo",
            "build",
            "--locked",
            "--no-default-features",
            "--package",
            package_name,
            "--bin",
            contract["legacy_bin"],
        ]
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = f"{completed.stdout}\n{completed.stderr}".lower()
        if completed.returncode == 0:
            raise GateError(f"{contract['legacy_bin']} built without {LEGACY_FEATURE}")
        if "requires the features" not in output or LEGACY_FEATURE not in output:
            raise GateError(
                f"{contract['legacy_bin']} failed for an unexpected reason instead of its required feature:\n"
                f"{output.strip()}"
            )


def verify_compiled_cli_schemas(target_directory: Path) -> None:
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target_directory)
    environment.setdefault("CARGO_BUILD_JOBS", "4")
    test_name = "tests::default_operator_schema_is_exact_and_visible"
    for package_name, contract in PACKAGE_CONTRACTS.items():
        base_command = [
            "cargo",
            "test",
            "--locked",
            "--no-default-features",
            "--package",
            package_name,
            "--bin",
            contract["default_bin"],
            test_name,
        ]
        listing = run([*base_command, "--", "--exact", "--list", "--format", "terse"], env=environment)
        listed_tests = [line for line in listing.stdout.splitlines() if line]
        expected_listing = [f"{test_name}: test"]
        if listed_tests != expected_listing:
            raise GateError(
                f"{package_name} schema-test discovery changed: "
                f"expected {expected_listing}, found {listed_tests}"
            )
        completed = run([*base_command, "--", "--exact"], env=environment)
        passed_line = f"test {test_name} ... ok"
        if passed_line not in completed.stdout.splitlines():
            raise GateError(f"{package_name} schema test did not execute and pass exactly once")
        summary = re.search(
            r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;",
            completed.stdout,
        )
        if summary is None:
            raise GateError(f"{package_name} schema-test result was not exactly one passed and zero ignored")


def help_section_lines(help_text: str, heading: str) -> list[str]:
    lines = help_text.splitlines()
    try:
        start = lines.index(f"{heading}:") + 1
    except ValueError as error:
        raise GateError(f"help output omitted {heading}: section") from error
    section = []
    for line in lines[start:]:
        if not line.strip():
            break
        section.append(line.strip())
    return section


def verify_help_text(
    invocation: str,
    help_text: str,
    expected_usage: str,
    expected_options: set[str],
    expected_short_options: set[str],
    expected_commands: set[str] | None,
) -> None:
    if expected_usage not in help_text.splitlines():
        raise GateError(f"{invocation} help usage changed; expected {expected_usage!r}")
    if expected_commands is not None:
        commands = {line.split(maxsplit=1)[0] for line in help_section_lines(help_text, "Commands")}
        if commands != expected_commands:
            raise GateError(
                f"{invocation} help commands changed: expected {sorted(expected_commands)}, found {sorted(commands)}"
            )
    elif "Commands:" in help_text.splitlines():
        raise GateError(f"{invocation} unexpectedly exposes nested commands")

    option_lines = help_section_lines(help_text, "Options")
    options = {match for line in option_lines for match in re.findall(r"--([a-z0-9-]+)", line)}
    short_options = {
        match
        for line in option_lines
        for match in re.findall(r"(?:^|\s)-([A-Za-z])(?:,|\s|$)", line)
    }
    if options != expected_options:
        raise GateError(
            f"{invocation} help options changed: expected {sorted(expected_options)}, found {sorted(options)}"
        )
    if short_options != expected_short_options:
        raise GateError(
            f"{invocation} short help options changed: "
            f"expected {sorted(expected_short_options)}, found {sorted(short_options)}"
        )
    lowered = help_text.lower()
    leaked = sorted(term for term in FORBIDDEN_HELP_TERMS if term in lowered)
    if leaked:
        raise GateError(f"{invocation} help leaked forbidden terms: {leaked}")


def read_help(executable: Path, arguments: list[str]) -> str:
    completed = run([str(executable), *arguments, "--help"])
    invocation = " ".join([executable.name, *arguments])
    if completed.stderr:
        raise GateError(f"{invocation} --help emitted unexpected stderr: {completed.stderr.strip()}")
    return completed.stdout


def verify_help(artifacts: dict[str, Path]) -> None:
    for contract in PACKAGE_CONTRACTS.values():
        binary_name = contract["default_bin"]
        executable = artifacts[binary_name]
        expected_commands = set(contract["subcommands"]) | {"help"}
        root_usage = (
            f"Usage: {binary_name} --config <CONFIG> <COMMAND>"
            if contract["required_config"]
            else f"Usage: {binary_name} [OPTIONS] <COMMAND>"
        )
        verify_help_text(
            binary_name,
            read_help(executable, []),
            root_usage,
            EXPECTED_OPTIONS,
            EXPECTED_SHORT_OPTIONS,
            expected_commands,
        )
        for subcommand, expected_options in contract["subcommands"].items():
            invocation = f"{binary_name} {subcommand}"
            subcommand_usage = (
                f"Usage: {binary_name} --config <CONFIG> {subcommand}"
                if contract["required_config"]
                else f"Usage: {invocation} [OPTIONS]"
            )
            verify_help_text(
                invocation,
                read_help(executable, [subcommand]),
                subcommand_usage,
                expected_options,
                {"h"},
                None,
            )


def verify_forbidden_invocations(artifacts: dict[str, Path]) -> None:
    forbidden_tokens = {term.replace(" ", "-") for term in FORBIDDEN_HELP_TERMS}
    for contract in PACKAGE_CONTRACTS.values():
        executable = artifacts[contract["default_bin"]]
        forbidden_commands = forbidden_tokens | contract["additional_forbidden_commands"]
        for command in forbidden_commands:
            assert_invocation_rejected(executable, [command, "--help"])
        prefixes = [[]] + [[subcommand] for subcommand in contract["subcommands"]]
        forbidden_options = forbidden_tokens | contract["additional_forbidden_options"]
        for prefix in prefixes:
            for option in forbidden_options:
                assert_invocation_rejected(executable, [*prefix, f"--{option}", "--help"])


def assert_invocation_rejected(executable: Path, arguments: list[str]) -> None:
    completed = subprocess.run(
        [str(executable), *arguments],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode == 0:
        raise GateError(f"forbidden invocation was accepted: {' '.join([executable.name, *arguments])}")


def run_self_tests() -> None:
    synthetic_metadata = {
        "packages": [
            {"id": "root", "name": "thunderboltd"},
            {"id": "runtime", "name": "thunderbolt-runtime"},
            {"id": "legacy", "name": "thunderbolt-node"},
        ],
        "resolve": {
            "nodes": [
                {
                    "id": "root",
                    "deps": [{"pkg": "runtime", "dep_kinds": [{"kind": None}]}],
                },
                {
                    "id": "runtime",
                    "features": ["insecure-live-test"],
                    "deps": [{"pkg": "legacy", "dep_kinds": [{"kind": None}]}],
                },
                {"id": "legacy", "deps": []},
            ]
        },
    }
    closure = resolved_normal_closure_names(synthetic_metadata, "root")
    if not closure & FORBIDDEN_TRANSITIVE_PACKAGES:
        raise GateError("self-test failed to detect a transitive legacy application crate")
    if forbidden_normal_features(synthetic_metadata, "root") != {"insecure-live-test"}:
        raise GateError("self-test failed to detect a forbidden transitive feature")

    safe_help = """Start service\n\nUsage: thunderboltd start [OPTIONS]\n\nOptions:\n      --config <CONFIG>\n  -h, --help\n"""
    verify_help_text(
        "thunderboltd start",
        safe_help,
        "Usage: thunderboltd start [OPTIONS]",
        {"config", "help"},
        {"h"},
        None,
    )
    unsafe_help = safe_help.replace("  -h, --help", "      --http\n  -h, --help")
    try:
        verify_help_text(
            "thunderboltd start",
            unsafe_help,
            "Usage: thunderboltd start [OPTIONS]",
            {"config", "help"},
            {"h"},
            None,
        )
    except GateError:
        pass
    else:
        raise GateError("self-test failed to reject a forbidden subcommand option")


def main() -> int:
    try:
        run_self_tests()
        for package_name, contract in PACKAGE_CONTRACTS.items():
            verify_metadata(package_name, contract)
        with tempfile.TemporaryDirectory(prefix="thunderbolt-default-binaries-") as directory:
            target_directory = Path(directory)
            artifacts = build_default_binaries(target_directory)
            verify_legacy_targets_require_feature(target_directory)
            verify_compiled_cli_schemas(target_directory)
            verify_help(artifacts)
            verify_forbidden_invocations(artifacts)
    except (GateError, json.JSONDecodeError) as error:
        print(f"default binary graph gate failed: {error}", file=sys.stderr)
        return 1
    print("default binary graph gate passed: release binaries are isolated and schema-locked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
