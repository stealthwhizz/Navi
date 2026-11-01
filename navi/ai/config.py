"""Provider defaults; credentials are resolved only at request time."""
import re

HARD_REQUEST_LIMIT = 5
DEFAULT_MODEL = "openai/gpt-oss-20b"
PROVIDERS = {"groq": {"model": DEFAULT_MODEL, "api_key_env": "GROQ_API_KEY"},
             "openai": {"model": "gpt-4.1-mini", "api_key_env": "OPENAI_API_KEY"}}
DEFAULTS = {"enabled": False, "provider": "groq", "model": DEFAULT_MODEL,
            "api_key_env": "GROQ_API_KEY", "workflow": "correlation", "max_requests": HARD_REQUEST_LIMIT, "auto_test": True, "max_seconds": 120,
            "request_timeout": 30, "max_completion_tokens": 2000, "max_prompt_tokens": 4000,
            "max_context_chars": 20000, "max_source_windows": 16, "max_tests": 8}


def options(value=None):
    if value is None: value = {}
    if not isinstance(value, dict) or value.keys() - DEFAULTS.keys():
        raise ValueError("ai accepts only documented options; put the provider key in an environment variable, never in configuration.")
    provider = value.get('provider', 'groq')
    if not isinstance(provider, str) or provider not in PROVIDERS: raise ValueError('Supported AI providers are groq and openai.')
    result = {**DEFAULTS, **PROVIDERS[provider], **value}
    for name in ("enabled", "auto_test"):
        if type(result[name]) is not bool: raise ValueError(f"ai.{name} must be a boolean.")
    if not isinstance(result["workflow"], str) or result["workflow"] not in {"correlation", "full"}: raise ValueError("ai.workflow must be correlation or full.")
    if not isinstance(result["model"], str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,120}", result["model"]):
        raise ValueError("ai.model must be a model identifier.")
    if not isinstance(result["api_key_env"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", result["api_key_env"]):
        raise ValueError("ai.api_key_env must name an environment variable.")
    for name, low, high in [("max_requests", 1, HARD_REQUEST_LIMIT), ("max_seconds", 5, 300), ("request_timeout", 1, 60),
                            ("max_prompt_tokens", 1500, 16000), ("max_completion_tokens", 512, 8000), ("max_context_chars", 4000, 60000),
                            ("max_source_windows", 1, 40), ("max_tests", 0, 20)]:
        if type(result[name]) is not int or not low <= result[name] <= high:
            raise ValueError(f"ai.{name} must be an integer between {low} and {high}.")
    return result
