"""
parser.py
-----------
Turns nmap's raw stdout text (as captured by stdout) into structured
data: which hosts were up, which ports were open and a symmary line

nmap's XML output (-oX) would be more robust long term, but executor.py
currently invokes nmap without -oX and captures plain stdout. Rather than
change that right now, this parser works well with what we already have.
If nmap's default text-output format ever changes with versions, then
this would be the place that needs updating.

Public entry point: parse_nmap_output(stdout: str) -> dict
"""

import re


# "Nmap scan report for localhost (127.0.0.1)"
# "Nmap scan report for 192.168.1.1

HOST_LINE_RE = re.compile(
    r"^Nmap scan report for\s+(?:(?P<hostname>\S+)\s+\((?P<ip_in_parens>[\d.:a-fA-F]+)\)|(?<ip_only>[\d.:a-fA-F]+))$"
)

# "Host is up." / "Host is up (0.0027s latency)
STATUS_LINE_RE = re.compile(
    r"^Host is (?P<status>up|down)(?:\s*\((?P<latency>[\d.]+)s latency\))?\.?$"
)

# "135/tcp open msrpc" / 80/tcp open http Apache httpd 2.4.41
PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<protocol>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?$"
)

# Nmap done : 1 IP address (1 host up) scanned in 1.10 seconds
SUMMARY_LINE_RE = re.compile(
    r"^ Nmap done:\s+(?P<total>\d+)\s+IP address(?:es)?\s+\((?P<up>\d+)\s+host(?:s)?\s+up\)\s+scanned in\s+(?P<seconds>[\d.]+)\s+seconds$"
)

# "Not Shown: 97 closed tcp ports (conn-refused)"
NOT_SHOWN_RE = re.compile(
    r"^Not shown:\s+(?P<count>\d+)\s+(?P<protocol>tcp|udp)\s+ports"
)


def parse_nmap_output(stdout: str) -> dict:

    if not stdout or not stdout.strip():
        return {"hosts": [], "summary": None}

    hosts = []
    current_host = None
    summary = None
