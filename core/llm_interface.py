"""
llm_interface.py
-----------------

Handles all communication with LLM. It has two responsibilities

1. parse_intent()         ->  turns natural language into a structured (JSON) format which the called must still
                              independantly validate with allowlist.py and scan_templates.py. The LLMs output is never
                              trusted or executed directly
2. summarize_results()    ->  turns structured nmap results in to a plain English summary

Provider-agnostic by design: OllamaProvider is the only implementation
today, but LLMProvider is an abstract base so cloud providers could be
added later without changing the rest of the app.
"""

import json
import requests
from abc import ABC, abstractmethod

from core.scan_templates import list_templates


class LLMError(Exception):
    """Raised when LLM fails to produce any result after retrying"""
    pass


# ---------------------------------------------------------------------
# Abstract base — defines the interface any provider must implement
# ---------------------------------------------------------------------


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> bool:
        """Send a prompt to LLM and return a text response"""
        raise NotImplementedError


# ---------------------------------------------------------------------
# Ollama implementation
# ---------------------------------------------------------------------
class OllamaProvider(LLMProvider):
    def __init__(self, model: str = 'llama3.1', host: str = 'http://localhost:11434'):
        self.model = model
        self.host = host

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False
        }

        if json_mode:
            payload["format"] = "json"

        try:
            response = requests.post(f"{self.host}/api/generate", json=payload,
                                     timeout=60)  # Change timeout if necessary
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise LLMError(
                f"Could not reach Ollama at {self.host}. Is it running? "
                f"(Run 'ollama serve' if not.) Original error: {e}"
            )

        return response.json().get("response", "")


# ---------------------------------------------------------------------
# Intent parsing
# ---------------------------------------------------------------------
REQUIRED_FIELDS = ["scan_type", "target", "port_spec"]


def _build_intent_system_prompt() -> str:
    templates = list_templates()
    template_list = "\n".join(f"{name}: {description}" for name, description in templates.items())
    return f"""You are a network scan intent parser. Your ONLY job is to read the
user's request and output a single JSON object describing their intent.
You must respond with only valid JSON, no extra text ,matching exactly this schema:
{{
    "scan_type": one of [{", ".join(f'"{k}"' for k in templates.keys())}],
    "target": string (an IP adress , CIDR range, or hostname),
    "port_spec": string or null (e.g. "80", "1-1000", "22,80,443", or null if not specified)
}}

Available scan types and what they do
{template_list}

Rules:
- Extract the target EXACTLY as the user describes it. Do NOT substitute,
  guess, or "correct" it to a different address. If they say "my router"
  and don't give an IP, use their literal words as the target string.
- Do NOT invent a scan_type that isn't in the list above.
- If the user's request is ambiguous about scan type, default to "quick_scan".
- Output ONLY the JSON object. No explanation, no markdown formatting, no extra text.
"""


def _has_required_key_fields(parsed: dict) -> bool:
    """
       Defensive helper: checks all required keys are present, regardless
       of whether REQUIRED_FIELDS happens to be a set, list, or tuple.
       Avoids relying on .issubset() existing on the container's type.
    """
    if not isinstance(parsed, dict):
        return False
    return all(field in parsed for field in REQUIRED_FIELDS)


def parse_intent(user_request: str, provider: LLMProvider) -> dict:
    """
      Convert a natural language scan request into structured intent.
      Retries once with a stricter reminder if the first response is
      malformed or missing fields. Raises LLMError if it still fails.

      NOTE: The returned dict is NOT validated for safety. The caller
      must still pass target/scan_type/port_spec through allowlist.py and
      scan_templates.py before building or running any command.
    """

    system_prompt = _build_intent_system_prompt()

    for attempt in range(2):  # One try + One retry
        prompt = user_request
        if attempt == 1:
            prompt = (
                f"{user_request}\n\n"
                f"REMINDER: Respond with ONLY a valid JSON object containing "
                f"exactly these keys: scan_type, target, port_spec. No other text."
            )

        raw_response = provider.generate(prompt, system=system_prompt, json_mode=True)

        try:
            parsed = json.loads(raw_response)
        except json.JSONDecodeError:
            continue  # malformed JSON, try the retry loop

        if _has_required_key_fields(parsed):
            return {
                "scan_type": parsed.get("scan_type"),
                "target": parsed.get("target"),
                "port_spec": parsed.get("port_spec")
            }
        # else: Goes to retry

    raise LLMError(
        "Could not understand the scan request after two attempts. "
        "Try rephrasing it more explicitly, e.g. "
        "\"run a quick scan on 192.168.1.10\"."
    )


# ---------------------------------------------------------------------
# Result summarization
# ---------------------------------------------------------------------

def summarize_results(scan_results: dict, provider: LLMProvider) -> str:
    """
       This Converts structured nmap results (produced by parser.py) into a
       plain-English summary for the user. No JSON constraint needed here
       free text is fine since this is just for display, nothing downstream
       parses it.
       """
    system_prompt = (
        "You are a security scan assistant. Summarize the following nmap "
        "scan results in plain, clear English for a technical but "
        "non-expert user. Mention: what host(s) were scanned, which ports "
        "were open and what services/versions were detected (if known), "
        "and flag anything unusual or worth attention. Be concise — a few "
        "sentences to a short paragraph, not a huge report."
    )
    prompt = json.dumps(scan_results, indent=2)
    return provider.generate(prompt, system=system_prompt, json_mode=False)
