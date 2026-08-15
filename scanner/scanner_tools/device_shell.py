"""Immutable plans for explicitly confirmed remote-device SSH shell execution."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


MAX_SHELL_COMMANDS = 8
MAX_SHELL_COMMAND_CHARS = 4096
MAX_SHELL_COMMAND_TOTAL_CHARS = 16_384
MIN_SHELL_TIMEOUT_SECONDS = 5
MAX_SHELL_TIMEOUT_SECONDS = 60


_RISK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("privilege-change", re.compile(r"(^|[;&|]\s*)(sudo|su)(\s|$)|\b(chown|chmod|setcap)\b", re.I)),
    ("service-or-process-change", re.compile(r"\b(systemctl|service|kill|pkill|killall)\b", re.I)),
    ("package-or-firmware-change", re.compile(r"\b(apt|apt-get|apk|dnf|yum|rpm|opkg|fwupdmgr|rauc|swupdate)\b", re.I)),
    ("filesystem-write-or-delete", re.compile(r"(^|\s)(rm|mv|cp|dd|mkfs|mount|umount|tee)(\s|$)|(^|[^<])>{1,2}[^>]", re.I)),
    ("device-restart-or-power", re.compile(r"\b(reboot|shutdown|poweroff|halt)\b", re.I)),
    ("network-egress-or-pivot", re.compile(r"\b(curl|wget|nc|ncat|netcat|ssh|scp|sftp|telnet)\b", re.I)),
    ("background-or-detached-process", re.compile(r"(^|[^&])&\s*$|\b(nohup|setsid)\b", re.I)),
)


def normalize_shell_commands(values: Any) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("SSH shell commands must be a list")
    if not 1 <= len(values) <= MAX_SHELL_COMMANDS:
        raise ValueError(f"SSH shell plans require 1-{MAX_SHELL_COMMANDS} commands")
    commands: list[str] = []
    total = 0
    for raw in values:
        command = str(raw or "")
        if not command.strip():
            raise ValueError("SSH shell commands cannot be empty")
        if "\x00" in command or "\r" in command:
            raise ValueError("SSH shell commands cannot contain NUL or carriage return")
        if any(ord(character) < 32 and character not in {"\n", "\t"} for character in command):
            raise ValueError("SSH shell commands contain unsupported control characters")
        if len(command) > MAX_SHELL_COMMAND_CHARS:
            raise ValueError(f"Each SSH shell command is limited to {MAX_SHELL_COMMAND_CHARS} characters")
        total += len(command)
        if total > MAX_SHELL_COMMAND_TOTAL_CHARS:
            raise ValueError(f"SSH shell plan commands are limited to {MAX_SHELL_COMMAND_TOTAL_CHARS} characters")
        commands.append(command)
    return commands


def detected_shell_risks(commands: list[str]) -> list[str]:
    joined = "\n".join(commands)
    return [name for name, pattern in _RISK_PATTERNS if pattern.search(joined)]


def shell_plan_digest(plan: dict[str, Any]) -> str:
    canonical = {
        key: plan.get(key)
        for key in (
            "schema_version", "plan_id", "run_id", "device_target_id", "target_locator",
            "locator_generation", "credential_profile_id", "ssh_port",
            "expected_host_key_fingerprint", "commands", "timeout_seconds", "purpose",
            "risk_summary", "detected_risks", "created_at", "expires_at",
        )
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def build_shell_plan(
    *,
    plan_id: str,
    run_id: str,
    device_target_id: str,
    target_locator: str,
    locator_generation: int,
    credential_profile_id: str,
    ssh_port: int,
    expected_host_key_fingerprint: str,
    commands: list[str],
    timeout_seconds: int,
    purpose: str,
    risk_summary: str,
    created_at: str,
    expires_at: str,
) -> dict[str, Any]:
    normalized_commands = normalize_shell_commands(commands)
    port = int(ssh_port)
    if not 1 <= port <= 65535:
        raise ValueError("SSH shell plan port is invalid")
    timeout = int(timeout_seconds)
    if not MIN_SHELL_TIMEOUT_SECONDS <= timeout <= MAX_SHELL_TIMEOUT_SECONDS:
        raise ValueError(
            f"SSH shell command timeout must be {MIN_SHELL_TIMEOUT_SECONDS}-{MAX_SHELL_TIMEOUT_SECONDS} seconds"
        )
    fingerprint = str(expected_host_key_fingerprint or "")
    if not fingerprint.startswith("SHA256:"):
        raise ValueError("SSH shell plan requires a pinned SHA256 host key")
    plan = {
        "schema_version": "device-agent-ssh-shell-plan/v1",
        "plan_id": str(plan_id),
        "run_id": str(run_id),
        "device_target_id": str(device_target_id),
        "target_locator": str(target_locator),
        "locator_generation": int(locator_generation),
        "credential_profile_id": str(credential_profile_id),
        "ssh_port": port,
        "expected_host_key_fingerprint": fingerprint,
        "commands": normalized_commands,
        "timeout_seconds": timeout,
        "purpose": str(purpose or "")[:1000],
        "risk_summary": str(risk_summary or "")[:1000],
        "detected_risks": detected_shell_risks(normalized_commands),
        "created_at": str(created_at),
        "expires_at": str(expires_at),
    }
    plan["plan_digest"] = shell_plan_digest(plan)
    plan["confirmation_phrase"] = f"RUN {plan['plan_digest'][:12]}"
    plan["status"] = "proposed"
    return plan


def validate_shell_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schema_version") != "device-agent-ssh-shell-plan/v1":
        raise ValueError("invalid SSH shell plan schema")
    normalized = dict(plan)
    normalized["commands"] = normalize_shell_commands(plan.get("commands"))
    if not 1 <= int(plan.get("ssh_port") or 0) <= 65535:
        raise ValueError("SSH shell plan port is invalid")
    if not MIN_SHELL_TIMEOUT_SECONDS <= int(plan.get("timeout_seconds") or 0) <= MAX_SHELL_TIMEOUT_SECONDS:
        raise ValueError("SSH shell plan timeout is invalid")
    if not str(plan.get("expected_host_key_fingerprint") or "").startswith("SHA256:"):
        raise ValueError("SSH shell plan host key is invalid")
    actual = shell_plan_digest(normalized)
    if not str(plan.get("plan_digest") or "") or actual != str(plan.get("plan_digest")):
        raise ValueError("SSH shell plan digest mismatch")
    return normalized
