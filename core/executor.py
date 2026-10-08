"""
executor.py
------------
Runs a pre-built, pre-validated nmap command as a subprocess.

This module NEVER constructs commands itself and NEVER accepts raw
strings from the user or LLM. It only accepts the command list produced
by scan_templates.build_command(), which is already restricted to
approved flags. subprocess.run() is called with shell=False (the
default) and a list of arguments, so there is no shell interpretation
of any input, closing off shell injection entirely.
"""

import subprocess
import time

DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes, overidable via settings.yaml


class ExecutionError(Exception):
    """Raised when the scan cannot be run or fails in a way the caller must handle"""
    pass


def run_scan(command: list, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """
    Execute the given nmap command (a list of arguments, eg.
    {"nmap", "-sT", "-F", "-T3", "192.168.1.1"}).
    Returns a dict:
    {
        "success": bool,
        "stdout": str,
        "stderr": str,
        "returncode": int,
        "duration_seconds": float,
        "command": list, # echoing back for display/logging
    }
    Raises Execution error for conditions that cannot be corrected by the caller
    (nmap missing, timeout, permission denied) with a clear human-readable message.
    Non-zero exit codes itself are not raised as exceptions they are returned to
    the result dict so the caller/parser can decide how to handle partial or failed
    scans.
    :param command:
    :param timeout:
    :return:
    """
    if not command or command[0] != "nmap":
        # Defensive check: this should never happen if callers only ever
        # pass output from scan_templates.build_command(), but we don't
        # trust that blindly here either
        raise ExecutionError(
            "Refusing to execute: command does not start with 'nmap'"
            "This should not happen, check the calling code"
        )
    start_time = time.time()

    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except FileNotFoundError:
        raise Exception(
            "nmap is not installed or not found in the path"
            " Install it from https://nmap.org/download.html and try again"
        )
    except subprocess.TimeoutExpired:
        raise ExecutionError(
            f"Scan timed out after {timeout} seconds. Try a narrower target"
            f"fewer ports, or a faster scan_type (eg. quick_scan instead of"
            f"full_port_scan)"
        )
    except PermissionError:
        raise ExecutionError(
            "Permission denied trying to run nmap. Some scan types (like "
            "syn scan) require admin root privileges. Try running as "
            "administrator, or use a scan type that doesn't require elevated "
            "privileges."
        )
    duration = time.time() - start_time

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "duration_seconds": round(duration, 2),
        "command": command,  # echoing back for display/logging
    }
