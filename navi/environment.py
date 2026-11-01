"""Load operator settings and diagnose credential selection without exposing values."""
import hashlib
import os
from pathlib import Path

from dotenv import load_dotenv, dotenv_values

# Internal provenance only. Neither credential values nor fingerprints are returned.
_loaded = {}


def load_environment():
    path = Path.cwd() / '.env'
    before = set(os.environ)
    load_dotenv(dotenv_path=path, override=False, interpolate=False)
    for name in os.environ.keys() - before:
        _loaded[name] = (str(path), hashlib.sha256(os.environ[name].encode()).digest())


def key_problem(key, provider='openai'):
    label = 'Groq' if provider == 'groq' else 'OpenAI'
    if not key: return 'The selected API key is empty or missing.'
    if not key.isascii() or any(c.isspace() for c in key): return 'The selected API key contains whitespace or non-ASCII characters.'
    if key.lower() in {'your_key', 'your_key_here', 'your_openai_api_key', 'your_groq_api_key', 'sk-your-key-here', 'replace_me'}:
        return f'The selected API key is a placeholder. Replace it with a {label} API key.'
    if (provider == 'openai' and key.startswith(('gsk_', 'sk-or-', 'sk-ant-'))) or (provider == 'groq' and key.startswith('sk-')):
        return f'The selected key belongs to another provider. Navi needs a {label} API key.'
    return None


def credential_status(name='OPENAI_API_KEY', provider='openai'):
    path = Path.cwd() / '.env'
    values = {}
    readable = False
    try:
        if path.is_file():
            with path.open() as stream: values = dotenv_values(stream=stream, interpolate=False)
            readable = True
    except (OSError, ValueError): pass
    key = os.environ.get(name, '')
    stamp = (str(path), hashlib.sha256(key.encode()).digest())
    from_file = _loaded.get(name) == stamp and name in os.environ
    source = '.env loaded at startup' if from_file else 'process environment' if name in os.environ else 'missing'
    differs = name in os.environ and name in values and key != (values[name] or '')
    issues = []
    problem = key_problem(key, provider)
    if problem: issues.append(problem)
    if differs: issues.append('The process value differs from .env. Unset the exported variable and restart Navi to load the file value.')
    return {'key_variable': name, 'key_configured': bool(key), 'key_source': source, 'dotenv_path': str(path),
            'dotenv_readable': readable, 'dotenv_key_present': name in values,
            'process_differs_from_dotenv': differs, 'configuration_issues': issues,
            'local_configuration_ok': problem is None,
            'note': f'Local configuration only; this does not validate the key with {provider}.'}


def authentication_error(name='OPENAI_API_KEY', provider='openai'):
    label = 'Groq' if provider == 'groq' else 'OpenAI'
    status = credential_status(name, provider)
    message = f"{label} authentication failed (HTTP 401). The key selected from {status['key_source']} via {name} was rejected."
    if status['process_differs_from_dotenv']:
        message += f' Unset the exported {name} and restart Navi to load .env.'
    else:
        message += f' Replace {name} in .env with a valid {label} API key and restart Navi.'
    return message + ' Run navi ai-check --offline to inspect key selection, then navi ai-check for one provider check. Native results are retained.'
