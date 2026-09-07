"""
test_llm_interface.py
-----------------------
Quick standalone script to sanity-check parse_intent() against a real
running Ollama instance before wiring it into the full CLI.

Run with: python test_llm_interface.py
"""

from core.llm_interface import OllamaProvider, parse_intent, LLMError

def main():
    provider = OllamaProvider(model="llama3.1")

    test_requests = [
        "scan 192.168.1.10 for open web ports",
        "do a quick scan on my home network",
        "check if 127.0.0.1 is up",
        "run a full port scan on 192.168.1.0/24",
    ]

    for req in test_requests:
        print(f"\n--- User request: \"{req}\" ---")
        try:
            intent = parse_intent(req, provider)
            print("Parsed intent:", intent)
        except LLMError as e:
            print("Failed to parse:", e)

if __name__ == "__main__":
    main()