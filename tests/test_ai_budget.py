"""Provider size/quota behavior uses synthetic headers; never a live key or sleep."""
import json
from types import SimpleNamespace

import pytest

from navi.ai.budget import compact_schema, estimate_tokens, seconds
from navi.ai.client import AIUnavailable, OpenAIClient
from navi.ai.review import AISession, valid_patch
from navi.ai.schemas import SourceReview
from navi.control import ScanControl
from navi.transport import Response


def test_full_prompt_including_schema_and_instructions_is_bounded():
    captured = []
    class Model:
        def complete(self, messages, control):
            captured.append(messages)
            return {'summary': 'Synthetic coverage', 'priorities': []}, {}
    session = AISession({'ai': {'enabled': True}}, ScanControl(), client=Model())
    session.call('coverage', {'gaps': [{'id': str(i), 'reason': 'long gap text '*100} for i in range(80)]})
    assert estimate_tokens(captured[0]) <= 4000
    assert session.report['stages']['coverage']['omitted']['gaps'] > 0
    schema = compact_schema(SourceReview.model_json_schema())
    assert schema['title'] == 'SourceReview' and 'title' in schema['$defs']['Hypothesis']['properties']


def test_oversized_prompt_is_rejected_before_network(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-test_test_only')
    monkeypatch.setattr('navi.ai.client.Transport', lambda *a, **k: pytest.fail('Prompt exceeded local limit'))
    client = OpenAIClient({})
    with pytest.raises(AIUnavailable, match='prompt budget'):
        client.complete([{'role': 'user', 'content': 'x'*20000}], ScanControl())
    assert client.requests == 0


def test_http_413_stops_followup_requests_and_redacts_provider_text(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-test_test_only')
    calls = []
    class Transport:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k):
            calls.append(1)
            return Response(413, {}, b'sk-test_test_only private account details', '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    client = OpenAIClient({})
    for _ in range(3):
        with pytest.raises(AIUnavailable, match='HTTP 413') as caught: client.complete([], ScanControl())
        assert 'sk-test_test_only' not in str(caught.value) and caught.value.fatal
    assert len(calls) == client.requests == 1


@pytest.mark.parametrize('available', [120, 10])
def test_token_quota_is_respected_before_next_request_without_real_wait(monkeypatch, available):
    now = [0.]; waits = []; requests = []
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-test_test_only')
    monkeypatch.setattr('navi.ai.client.time', SimpleNamespace(monotonic=lambda: now[0]))
    class Transport:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k):
            requests.append(now[0])
            return Response(200, {'x-ratelimit-limit-tokens': '8000', 'x-ratelimit-remaining-tokens': '0', 'x-ratelimit-reset-tokens': '1m'},
                json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': '{}'}}]}).encode(), '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    control = ScanControl(available, clock=lambda: now[0])
    def wait(delay): now[0] += delay; control.check()
    monkeypatch.setattr(control, 'wait', wait)
    client = OpenAIClient({}); client.on_wait = waits.append
    client.complete([], control)
    if available == 120:
        client.complete([], control)
        assert len(requests) == 2 and requests[1] >= 60 and len(waits) == 1
    else:
        with pytest.raises(AIUnavailable, match='remaining AI time budget'): client.complete([], control)
        assert len(requests) == 1 and not waits


def test_duration_headers_and_trimmed_source_citations():
    assert seconds('1m2.5s') == 62.5 and seconds('500ms') == .5
    assert seconds('unexpected secret text') is None and seconds('999999h') is None
    window = {'file': 'app.py', 'start': 1, 'end': 10, 'lines': [{'number': n, 'text': 'line'} for n in [1,2,9,10]]}
    assert not valid_patch('--- a/app.py\n+++ b/app.py\n@@ -5 +5 @@\n-old\n+new\n', window)
