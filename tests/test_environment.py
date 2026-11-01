"""Local dotenv loading never needs a real credential or provider request."""
import os

import pytest

from navi.environment import load_environment


@pytest.fixture
def local_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv('PYTHON_DOTENV_DISABLED', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    # Environment changes made by dotenv must also be restored after each test.
    monkeypatch.setenv('OPENAI_API_KEY', '')
    monkeypatch.delenv('OPENAI_API_KEY')
    return tmp_path


def test_dotenv_loads_quoted_key_without_expanding_values(local_env):
    (local_env / '.env').write_text('OPENAI_API_KEY="sk-test_synthetic_${UNCHANGED}" # comment\n')
    load_environment()
    assert os.environ['OPENAI_API_KEY'] == 'sk-test_synthetic_${UNCHANGED}'


@pytest.mark.parametrize('existing', ['sk-test_shell_value', ''])
def test_existing_environment_takes_precedence(local_env, monkeypatch, existing):
    (local_env / '.env').write_text('OPENAI_API_KEY=sk-test_file_value\n')
    monkeypatch.setenv('OPENAI_API_KEY', existing)
    load_environment()
    assert os.environ['OPENAI_API_KEY'] == existing


def test_loader_does_not_search_parent_directories(local_env, monkeypatch):
    (local_env / '.env').write_text('OPENAI_API_KEY=sk-test_parent_value\n')
    child=local_env / 'child'; child.mkdir(); monkeypatch.chdir(child)
    load_environment()
    assert 'OPENAI_API_KEY' not in os.environ


def test_cli_ai_check_uses_dotenv_and_does_not_print_key(local_env, monkeypatch, capsys):
    from navi.cli import main
    key='sk-test_synthetic_cli_key'
    (local_env / '.env').write_text(f'OPENAI_API_KEY={key}\n')
    def complete(self, messages, control):
        assert os.environ['OPENAI_API_KEY'] == key
        return {'ready': True}, {}
    monkeypatch.setattr('navi.ai.client.OpenAIClient.complete', complete)
    assert main(['ai-check', '--provider', 'openai']) == 0
    output=capsys.readouterr()
    assert key not in output.out + output.err
    assert '"ready": true' in output.out


def test_fastapi_factory_loads_dotenv(local_env, monkeypatch):
    from navi.api import create_app, Settings
    from conftest import ROOT
    key='sk-test_synthetic_server_key'
    (local_env / '.env').write_text(f'OPENAI_API_KEY={key}\n')
    create_app(Settings(source=str(ROOT / 'examples/shop'), output=str(local_env / 'reports')))
    assert os.environ['OPENAI_API_KEY'] == key


def test_offline_ai_check_never_contacts_provider_and_shows_no_key(local_env, monkeypatch, capsys):
    from navi.cli import main
    import json
    key = 'sk-proj-synthetic-offline-key'
    (local_env/'.env').write_text(f'OPENAI_API_KEY={key}\n')
    monkeypatch.setattr('navi.ai.client.OpenAIClient.complete', lambda *a: pytest.fail('Offline means zero requests'))
    assert main(['ai-check','--provider', 'openai', '--offline']) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert key not in output
    assert result['requests'] == 0 and result['provider_checked'] is False
    assert result['key_source'] == '.env loaded at startup' and result['local_configuration_ok']


def test_key_diagnostic_explains_a_stale_shell_override(local_env, monkeypatch):
    from navi.environment import credential_status, authentication_error
    key = 'sk-proj-synthetic-new-key'
    (local_env/'.env').write_text(f'OPENAI_API_KEY={key}\n')
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-proj-synthetic-old-key')
    load_environment()
    result = credential_status()
    assert result['key_source'] == 'process environment' and result['process_differs_from_dotenv']
    message = authentication_error()
    assert 'HTTP 401' in message and 'Unset the exported' in message
    assert key not in message and 'sk-proj-synthetic-old-key' not in message


@pytest.mark.parametrize('value', ['your_key_here','gsk_synthetic_groq_key','sk-or-synthetic_key', 'sk-ant-synthetic_key'])
def test_known_placeholder_or_other_provider_is_blocked_without_request(local_env, monkeypatch, value):
    from navi.ai.client import OpenAIClient, AIUnavailable
    from navi.control import ScanControl
    monkeypatch.setenv('OPENAI_API_KEY', value)
    monkeypatch.setattr('navi.ai.client.Transport', lambda *a, **k: pytest.fail('Invalid local key must not be sent'))
    client = OpenAIClient({})
    with pytest.raises(AIUnavailable) as caught: client.complete([], ScanControl())
    assert value not in str(caught.value) and client.requests == 0
