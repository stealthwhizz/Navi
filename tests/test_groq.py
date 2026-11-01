"""Groq contracts, using synthetic credentials and responses exclusively."""
import json

import pytest

from navi.ai.client import create_client, GroqClient, AIUnavailable
from navi.ai.config import options
from navi.control import ScanControl
from navi.transport import Response


def test_groq_default_endpoint_model_and_key(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'gsk_synthetic_test_only')
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-unrelated-test-only')
    sent = []
    class Transport:
        def __init__(self, target, **kwargs):
            assert target == 'https://api.groq.com/openai/v1'
            assert kwargs['allowed_origins'] == ['https://api.groq.com']
            assert kwargs['max_requests'] == 1
        def request(self, path, method, **kwargs):
            assert path == '/chat/completions' and method == 'POST'
            assert kwargs['headers']['Authorization'] == 'Bearer gsk_synthetic_test_only'
            assert kwargs['json_body']['model'] == 'openai/gpt-oss-20b'
            sent.append(kwargs)
            return Response(200, {}, json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': '{"ready": true}'}}]}).encode(), '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    client = create_client({})
    assert isinstance(client, GroqClient) and options(None)['api_key_env'] == 'GROQ_API_KEY'
    assert client.complete([], ScanControl())[0] == {'ready': True}
    assert client.requests == len(sent) == 1


@pytest.mark.parametrize('status', [401, 413, 429])
def test_groq_fatal_errors_stop_followups_without_exposing_response(monkeypatch, status):
    key = 'gsk_synthetic_test_only'; monkeypatch.setenv('GROQ_API_KEY', key)
    class Transport:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): return Response(status, {}, key.encode(), '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    client = create_client({})
    for _ in range(3):
        with pytest.raises(AIUnavailable) as error: client.complete([], ScanControl())
        assert 'Groq' in str(error.value) and key not in str(error.value)
    assert client.requests == 1


def test_groq_max_five_attempts_including_failed_transport(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'gsk_synthetic_test_only')
    attempted = []
    def broken(*a, **k):
        attempted.append(1)
        raise OSError('synthetic failure')
    monkeypatch.setattr('navi.ai.client.Transport', broken)
    client = create_client({})
    for _ in range(8):
        with pytest.raises(AIUnavailable): client.complete([], ScanControl())
    assert len(attempted) == client.requests == 5
    with pytest.raises(ValueError): options({'max_requests': 6})


def test_missing_groq_key_does_not_fall_back_to_openai(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-synthetic-test-only')
    monkeypatch.setattr('navi.ai.client.Transport', lambda *a, **k: pytest.fail('No Groq key; no request'))
    client = create_client({})
    with pytest.raises(AIUnavailable, match='GROQ_API_KEY'): client.complete([], ScanControl())
    assert client.requests == 0


def test_groq_dotenv_offline_check(tmp_path, monkeypatch, capsys):
    from navi.cli import main
    monkeypatch.chdir(tmp_path); monkeypatch.delenv('PYTHON_DOTENV_DISABLED')
    key = 'gsk_synthetic_dotenv_only'
    (tmp_path / '.env').write_text('GROQ_API_KEY=' + key + '\n')
    monkeypatch.setattr('navi.ai.client.Transport', lambda *a, **k: pytest.fail('Offline check must not contact Groq'))
    assert main(['ai-check', '--offline']) == 0
    output = capsys.readouterr().out
    assert key not in output
    result = json.loads(output)
    assert result['provider'] == 'groq' and result['model'] == 'openai/gpt-oss-20b'
    assert result['key_source'] == '.env loaded at startup' and result['requests'] == 0
