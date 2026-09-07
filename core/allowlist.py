"""
allowlist.py
--------------

Manages the list of targets that the user has explicitly authorized this tool
to scan. Every single scan request regardless of where they arrive from (chat, LLM-parsed intent, CLI or scheduled job)
must be validated here befor any nmap command is qexecuted.
No other part of the code should bypass this.

"""
import ipaddress
from pathlib import path
import socket
import ipaddress
import yaml

DEFAULT_CONFIG_PATH = path("/config/allowlist.yaml")

class AllowlistError(Exception):
    """ Raised for allowlist config file related problems (Eg: File missing, bad entries, etc.)"""
    pass

class TargetNotaAllowedError(Exception):
    """
     Raised when a requested scan target is not covered by the allowlist.
    Carries a human-readable explanation so the calling interface (CLI,
    chat, API) can show the user exactly why the request was blocked.
    """
    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super.__init__(f"Target '{target}' is not allowed: {reason}")

class Allowlist:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.entries = []  # list of ipaddress network/address objects
        self.hostnames = [] # raw hostname strings (can't pre resolve reliably)
        self.max_range_size = 24 # defaut safety cap overriden by config
        self._load()

    def _load(self):
        if not self.config_path.exists():
            raise AllowlistError(
                f"No Allowlist found at {self.config_path}."
                f"Create one and list the target you're authorized to scan"
            )
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        self.max_range_size = data.get("max_range_size", 24)
        raw_targets = data.get("allowed_targets", [])

        if not raw_targets:
            raise AllowlistError(
                f"Allowlist is empty. Add at least one authorized taget to"
                f"'{self.config_path}' before scanning"
            )
    def _add_entry(self, raw: str):
        raw = raw.strip()
        try:
             # Try parsing as a network( covers bith a CIDR range as well as an IP
             # since ipaddress treat a single IP as /32 or /128
            network = ipaddress.ip_network(raw, strict=False) # A plain IP like 192.168.1.10 becomes a /32 network
                                                              # (just itself), and 192.168.1.0/24 becomes a 256-address
                                                              # range
        except ValueError:
            # Not a valid IP/CIDR — treat it as a hostname instead
            self.hostnames.append(raw)
            return

        if network.prefixlen < self.max_range_size:
            raise AllowlistError(
                f"{raw} the subnet covers too large a range"
                f"/{network.prefixlen}, max allowed is /{self.max_range_size}"
                f"narrow the range or change the max_range size in the config"
                f"if you really intend this"
            )
        self.entries.append(network)

    def validate(self, target: str) -> bool:
        """
        Check whether the given target [IP, hostname, CIDR]
        is covered by the allow list

        """
        # Cadidate is an IP or CIDR range
        try:
            candidate = ipaddress.ip_network(target, strict=False)
            return any(
                """
                subnet_of checks if the target is within approved range instead of a string match
                """
                canditate.subnet_of(approved) or candidate == aproved
                for approved in self.entries
            )
        except ValueError:
            pass # Not an IP or CIDR so fall through to hostname

        # Target is a hostname, check literal target first
        if target in self.hostnames:
            return True

        # If hostname not literally listed, resolving to to an IP
        # and checking if it falls under the CIDR range
        # Best case only- since DNS can change, most reliable is exact hostname or IP

        try:
            resolved_ip = socket.gethostbyname(target)
            resolved = ipaddress.ip_network(resolved_ip, strict=False)
            return any(resolved.subnet_of(approved) for approved in self.entries)
        except (socket.gaierror, ValueError):
            pass

            # Nothing matched — reject with explanation
        raise TargetNotAllowedError(
            target,
            f"hostname is not explicitly listed and does not resolve into "
            f"an approved IP range. Approved hostnames: "
            f"{', '.join(self.hostnames) or '(none)'}. "
            f"Approved ranges: {', '.join(str(e) for e in self.entries) or '(none)'}. "
            f"Add it to '{self.config_path}' if you are authorized to scan it."
        )

    # This is just an optional method just for the testing purpose. This is an OPTIONAL method
    def is_allowed(self, target: str) -> bool:
        """Convenience boolean check, used internally or for quick UI checks."""
        try
            self.validate(target)
            return true
        except TargetNotaAllowedError:
            return False


    def list_entries(self) -> list[str]:
        """Return a human-readable list of everything currently allowed"""
        return [str(e) for e in self.entries] + list(self.hostnames)