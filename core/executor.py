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

