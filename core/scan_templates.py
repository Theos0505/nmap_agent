"""
scan_templates.py
------------------
Defines the only nmap scan types this tool is permitted to run, and the
exact, hardcoded flags associated with each one.

The LLM never generates raw nmap flags. It only selects a `scan_type`
name (from structured JSON intent), and this module maps that name to a
safe flag list. This is the core control that prevents
prompt injection or LLM mistakes from ever producing a dangerous command.

Explicitly excluded, on purpose, for safety:
  -A            aggressive scan (bundles OS detection, scripts, traceroute)
  --script      NSE scripts (includes vuln scanners, brute-force, exploits)
  -O            OS fingerprinting (noisy, not needed for this tool's purpose)
  -D, -S        decoy / spoofed source address (used to evade detection)
  --spoof-mac   MAC spoofing
  -T0/-T1/-T5   extreme timing templates (either too slow to be useful or
                aggressive enough to risk DoS-like behavior on some targets)
"""

import re
import shutil
import ctypes
import platform


class ScanTemplateError(Exception):
    """Raised for invalid scan type or port specification requests."""
    pass


# Each template maps a safe, descriptive name to it's nmap flag
# requires_privilege, scan type that require admin privilege
SCAN_TEMPLATES = {
    "ping_scan": {
        "description": "Check which hosts are online (no port scan)",
        "flags": ["-sn"],
        "requires_privileges": False,
    },
    "quick_scan": {
        "description": "Fast scan for most common 100 ports",
        "flags": ["-sT", "-F"],
        "requires_privileges": False,
    },
    "connect_scan": {
        "description": "Standard TCP connect scan",
        "flags": ["-sT"],
        "requires_privileges": False,
    },
    "syn_scan": {
        "description": "TCP SYN Scan (stealthier, faster)",
        "flags": ["-sS"],
        "requires_privileges": True
    },
    "version_scan": {
        "description": "Detect service/version running on open port",
        "flags": ["-sV"],
        "requires_privileges": False
    },
    "full_port_scan": {
        "description": "Scan all 65535 TCP ports.",
        "flags": ["-sT", "-p-"],
        "requires_privileges": False,
    }
}

# Only safe timing templates, skipping extreme (-T0, -T5)
ALLOWED_TIMING = {"T2", "T3", "T4"}


def list_templates() -> dict:
    """Return the available scan types and their descriptions (for LLM prompt + CLI help)."""
    return {name: cfg["description"] for name, cfg in SCAN_TEMPLATES.items()}


def _has_admin_privileges() -> bool:
    """Check for admin/root, used to decide if SYN scan is viable"""
    system = platform.system()
    try:
        if system == "Windows":
            return ctypes.windll.shell32.IsUserAdmin() != 0
        else:
            import os
            return os.geteuid() == 0
    except Exception:
        return False


def validate_port_spec(port_spec: str) -> str:
    """
        Validate a user/LLM-provided port specification string.
        Only allows digits, commas, and hyphens (e.g. "80", "1-1000", "22,80,443").
        Rejects anything else to prevent flag/argument injection via the port field.
    """

    if port_spec is None:
        return None

    port_spec = port_spec.strip()

    if not re.fullmatch((r"[0-9,\-])+", port_spec)):
        raise ScanTemplateError(
            f"Invalid Port Specification: '{port_spec}'."
            f"Only digits, commas, and hyphens are allowed (e.g. '80', '1-1000', '22,80,443')."
        )

    # Sankty-check for each individual port/range is in valid bounds
    for part in port_spec.split(","):
        if '-' in part:
            bounds = part.split('-')
            if len(bounds) != 2:
                raise ScanTemplateError(f"Invalid port range '{part}'")
            low, high = bounds
            if not (low.isdigit() and high.isdigit()):
                raise ScanTemplateError(f"Invalid port range'{part}'")
            if not (1 <= int(low) <= 65535 and 1 <= int(high) <= 65535 and int(low) <= int(high)):
                raise ScanTemplateError(f"Port range out of bounds '{part}'")
        else:
            if not part.isdigit() or not (1 <= int(part) <= 65535):
                raise ScanTemplateError(f"Port out of bounds '{part}'")
    return port_spec


def build_command(scan_type: str, target: str, port_spec: str = None, timing: str = "T3"):
    """
    Build nmap commands as a safe list of arguments (never a raw string, as this will prevent shell injection since
    we'll run it via subprocess with Shell=Disabled

    Returns the full argument list, e.g.:
    ["nmap", "-sT", "-p", "1-1000", "-T3", "192.168.1.10"]
    :param scan_type:
    :param target:
    :param port_spec:
    :param timing:
    :return:
    """

    if scan_type not in SCAN_TEMPLATES:
        raise ScanTemplateError(
            f"Unknown scan type '{scan_type}'. Available types: "
            f"{', '.join(SCAN_TEMPLATES.keys())}"
        )

    template = SCAN_TEMPLATES[scan_type]
    flags = list(template["flags"])

    if template["requires_privileges"] and not _has_admin_privileges():
        flags = SCAN_TEMPLATES["connect_scan"]["flags"]
        downgraded = True
    else:
        downgraded = False

    if timing not in ALLOWED_TIMING:
        timing = "T3"  # safe default

    command = ["nmap"] + flags

    if port_spec:
        validated_port = validate_port_spec(port_spec)
        command += ["-p", validated_port]

    command += [f"-{timing}", target]

    return {
        "command": command,
        "downgraded": downgraded
    }


def nmap_available() -> bool:
    """Check that nmap is actually installed and on PATH before we try to run anything."""
    return shutil.which("nmap") is not None
