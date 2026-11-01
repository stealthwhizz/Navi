"""Project recorded HTTP evidence into the shared finding contract without guessing."""
import json
from urllib.parse import parse_qs, urlsplit


def runtime_observations(evidence, bindings):
    observations = []
    for index, item in enumerate(evidence):
        request = item.get('request')
        if not request:
            continue
        tested = request.get('tested_input') or {}
        # New reports record a tested_input at the request boundary. For older
        # reports infer only values actually retained in request metadata.
        binding = next((b for b in bindings if b.get('parameter') == tested.get('parameter')
                        and b.get('location') == tested.get('location')), None)
        if binding is None:
            path = urlsplit(request.get('url', '')).path
            binding = next((b for b in bindings if b.get('method') == request.get('method')
                            and b.get('route') == path), {})
        parameter = tested.get('parameter', binding.get('parameter'))
        location = tested.get('location', binding.get('location'))
        payload = tested.get('value')
        if not tested and parameter:
            values = request.get({'query': 'query', 'form': 'form', 'json': 'json'}.get(location, ''))
            if isinstance(values, dict):
                payload = values.get(parameter)
            if payload is None and location == 'query':
                payload = parse_qs(urlsplit(request.get('url', '')).query).get(parameter, [None])[0]
        if payload is not None and not isinstance(payload, str):
            payload = json.dumps(payload, ensure_ascii=True)
        observations.append({'evidence_index': index, 'label': item.get('label', 'Observation'),
            'url': request.get('url', ''), 'method': request.get('method', binding.get('method', 'GET')),
            'route': tested.get('route', binding.get('route')), 'parameter': parameter, 'location': location,
            'payload': payload, 'request': request,
            'response': {'status': item.get('status'), 'headers': item.get('response_headers', {}),
                         'excerpt': item.get('body_excerpt', ''), 'body_sha256': item.get('body_sha256'),
                         'truncated': item.get('truncated', False) or item.get('body_bytes', 0) > len(item.get('body_excerpt', '').encode())},
            'browser': item.get('browser'), 'execution_proof': item.get('execution_proof'),
            'policy': item.get('policy'), 'variant': item.get('variant'), 'trace': item.get('trace')})
    return observations


def primary_observation(observations):
    # Prefer a request with an actual injected value; all controls and separate
    # read observations remain attached, including stored-XSS execution proof.
    return next((o for o in reversed(observations) if o['payload'] is not None),
                observations[-1] if observations else None)
