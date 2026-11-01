"""Small provider chat client; fixed HTTPS destination, bounded requests, no tool calls."""
import json
import os
import threading
import time
from .config import options
from ..control import ScanControl, ScanStopped
from .budget import estimate_tokens, seconds, integer
from ..transport import Transport
from ..environment import key_problem, authentication_error

ENDPOINT = 'https://api.openai.com/v1'
ENDPOINTS = {'openai': (ENDPOINT, 'https://api.openai.com'), 'groq': ('https://api.groq.com/openai/v1', 'https://api.groq.com')}


class AIUnavailable(Exception):
    def __init__(self, reason, fatal=False, http_status=None, retry_after=None):
        super().__init__(reason)
        self.fatal = fatal
        self.http_status = http_status
        self.retry_after = retry_after


class OpenAIClient:
    default_provider = "openai"
    def __init__(self, config):
        self.config = options({"provider": self.default_provider, **config})
        self.label = "Groq" if self.config["provider"] == "groq" else "OpenAI"
        self.blocked = None
        self.requests = 0
        self._budget_lock = threading.Lock()
        self.token_limit = self.tokens_remaining = self.token_reset_at = None
        self.on_wait = lambda seconds: None
        self.last_budget = {}

    def pace(self, messages, control):
        prompt = estimate_tokens(messages)
        required = prompt + self.config['max_completion_tokens']
        self.last_budget = {'estimated_prompt_tokens': prompt, 'reserved_output_tokens': self.config['max_completion_tokens'],
                            'estimated_total_tokens': required, 'provider_token_limit': self.token_limit,
                            'provider_tokens_remaining': self.tokens_remaining, 'wait_seconds': 0}
        if prompt > self.config['max_prompt_tokens']:
            raise AIUnavailable('AI prompt exceeds the local prompt budget, including schema and instructions; no request sent.', True)
        if self.token_limit is not None and required > self.token_limit:
            raise AIUnavailable("Estimated AI input plus output exceeds the provider's reported token limit. Lower ai.max_prompt_tokens or ai.max_completion_tokens; no request sent.", True)
        if self.token_reset_at is not None and time.monotonic() >= self.token_reset_at:
            self.tokens_remaining = self.token_limit
        if self.tokens_remaining is not None and required > self.tokens_remaining:
            if self.token_reset_at is None:
                raise AIUnavailable('The AI provider reported insufficient token quota without a reset time. Rerun AI after the quota resets; no request sent.', True)
            delay = max(0, self.token_reset_at - time.monotonic()) + .1
            if delay >= control.remaining() - 1:
                raise AIUnavailable('AI token quota resets after the remaining AI time budget. Native results are saved; rerun AI later.', True)
            self.on_wait(delay)
            self.last_budget['wait_seconds'] = round(delay, 3)
            control.wait(delay)
            self.tokens_remaining = self.token_limit

    def observe_quota(self, headers):
        headers = {str(k).lower(): v for k, v in headers.items()}
        self.token_limit = integer(headers.get('x-ratelimit-limit-tokens'))
        self.tokens_remaining = integer(headers.get('x-ratelimit-remaining-tokens'))
        reset = seconds(headers.get('x-ratelimit-reset-tokens'))
        self.token_reset_at = time.monotonic() + reset if reset is not None else None

    def complete(self, messages, control):
        if self.blocked: raise AIUnavailable(self.blocked, True)
        key = os.environ.get(self.config['api_key_env'], '')
        problem = key_problem(key, self.config['provider'])
        if problem:
            raise AIUnavailable(f"{problem} Set {self.config['api_key_env']} in .env or the process environment; native results are retained.", True)
        control.check()
        with self._budget_lock:
            if self.requests >= self.config['max_requests']:
                raise AIUnavailable('AI request limit reached; no further requests allowed in this scan.', True)
        self.pace(messages, control)
        with self._budget_lock:
            if self.requests >= self.config['max_requests']:
                raise AIUnavailable('AI request limit reached; no further requests allowed in this scan.', True)
            # Reserve before transport setup so network/JSON failures also count.
            self.requests += 1
        try:
            request_control = ScanControl(min(self.config['request_timeout'], control.remaining()), event=control.event)
            endpoint, allowed_origin = ENDPOINTS[self.config['provider']]
            transport = Transport(endpoint, allowed_origins=[allowed_origin],
                                  timeout=min(self.config['request_timeout'], control.remaining()),
                                  max_requests=1, interval=0, control=request_control)
            response = transport.request('/chat/completions', 'POST', headers={'Authorization': 'Bearer ' + key}, json_body={
                'model': self.config['model'], 'messages': messages, 'stream': False, 'temperature': 0.1,
                'max_completion_tokens': self.config['max_completion_tokens'], 'response_format': {'type': 'json_object'}})
            self.observe_quota(response.headers)
            if response.status != 200:
                reasons = {401: authentication_error(self.config['api_key_env'], self.config['provider']), 403: f'{self.label} access was denied.',
                           404: f'The configured {self.label} model or endpoint was not found.',
                           413: f'{self.label} rejected an oversized request (HTTP 413). Lower ai.max_prompt_tokens or ai.max_completion_tokens. Further AI calls stopped; native results retained.',
                           429: f'{self.label} rate limit reached; retry a later scan or reduce AI context/output limits.'}
                reason = reasons.get(response.status, f'{self.label} returned HTTP {response.status}; no AI result accepted.')
                fatal = response.status in {400, 401, 403, 404, 413, 429} or response.status >= 500
                if fatal: self.blocked = reason
                raise AIUnavailable(reason, fatal, http_status=response.status, retry_after=seconds(response.headers.get('retry-after')))
            if response.truncated: raise AIUnavailable(f'{self.label} response exceeded the response-size limit.')
            data = response.json()
            choice = data['choices'][0]
            if choice.get('finish_reason') != 'stop':
                raise AIUnavailable(f'{self.label} did not finish a complete answer; truncated or filtered output was rejected.')
            content = choice['message']['content']
            if not isinstance(content, str): raise AIUnavailable(f'{self.label} returned no JSON text.')
            value = json.loads(content)
            usage = {k: v for k, v in data.get('usage', {}).items()
                     if k in {'prompt_tokens', 'completion_tokens', 'total_tokens'} and type(v) is int and 0 <= v <= 10_000_000}
            return value, usage
        except (AIUnavailable, ScanStopped):
            raise
        except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
            # Never persist provider response text or exceptions containing headers.
            raise AIUnavailable(f'{self.label} request/JSON response failed ({type(error).__name__}); native results are retained.') from None


class GroqClient(OpenAIClient):
    default_provider = "groq"


def create_client(config):
    return (GroqClient if options(config)["provider"] == "groq" else OpenAIClient)(config)
