"""Execute a fetched HTML response in Chromium, with all other network blocked."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

from .transport import Response


class BrowserUnavailable(RuntimeError):
    pass


REPAIR_HINT = "Run python3 scripts/setup_environment.py, then use .venv/bin/python -m navi."


def options(value=None):
    value = {} if value is None else value
    if not isinstance(value, dict) or value.keys() - {'external_scripts', 'max_scripts'}:
        raise ValueError('browser accepts external_scripts and max_scripts.')
    result = {'external_scripts': False, 'max_scripts': 8, **value}
    if type(result['external_scripts']) is not bool or type(result['max_scripts']) is not int or not 1 <= result['max_scripts'] <= 32:
        raise ValueError('browser.external_scripts must be boolean and max_scripts must be 1–32.')
    return result


def script_response(transport, url):
    from .discovery import local_reference
    local = local_reference(transport.target, transport.target + '/', url)
    if not local: return None
    response = transport.request(local[0], 'GET', query=local[1])
    if response.status != 200 or response.truncated or response.headers.get('content-encoding', 'identity') not in {'', 'identity'}:
        return None
    return response


def check_driver():
    """Detect broken distro/wheel installs before Playwright creates async tasks."""
    try:
        from playwright._impl._driver import compute_driver_executable
    except ImportError as error:
        raise BrowserUnavailable(f"Playwright is not installed for this Python. {REPAIR_HINT}") from error
    node, entry = compute_driver_executable()
    node = shutil.which(str(node)) or str(node)
    if not Path(entry).is_file():
        raise BrowserUnavailable(f"Playwright driver is missing: {entry}. {REPAIR_HINT}")
    if not Path(node).is_file() or not os.access(node, os.X_OK):
        raise BrowserUnavailable(f"Playwright's Node executable is unavailable: {node}. {REPAIR_HINT}")
    try:
        check = subprocess.run([node, str(entry), "--version"], capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BrowserUnavailable(f"Playwright driver could not start ({type(error).__name__}). {REPAIR_HINT}") from error
    if check.returncode:
        raise BrowserUnavailable(f"Playwright driver failed its startup check (exit {check.returncode}). {REPAIR_HINT}")
    return {"node": node, "entrypoint": str(entry)}


class BrowserVerifier:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._driver = None
        self._browser = None
        self._failure = None
        self.options = options()
        self.transport = None

    def start(self):
        if not self.enabled:
            raise BrowserUnavailable("Browser verification was disabled; XSS execution has not been checked.")
        if self._failure:
            raise BrowserUnavailable(self._failure)
        if self._browser:
            return
        try:
            check_driver()
            from playwright.sync_api import sync_playwright
            self._driver = sync_playwright().start()
            configured = os.environ.get("NAVI_CHROMIUM")
            executable = configured or shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
            if configured and not Path(configured).is_file():
                raise RuntimeError(f"NAVI_CHROMIUM is not a file: {configured}")
            self._browser = self._driver.chromium.launch(executable_path=executable, headless=True,
                args=["--disable-background-networking", "--disable-component-update", "--disable-sync"], timeout=15000)
        except Exception as error:
            self.close()
            self._failure = f"Chromium verification unavailable: {str(error).splitlines()[0]}"
            raise BrowserUnavailable(self._failure) from error

    def verify(self, response: Response, token: str) -> dict:
        self.start()
        if response.truncated:
            return {"executed": False, "reason": "Response exceeded the body limit; replay would be incomplete."}
        context = self._browser.new_context(service_workers="block", java_script_enabled=True)
        try:
            page = context.new_page()
            served = False
            blocked = 0
            scripts = 0
            def intercept(route):
                nonlocal served, blocked, scripts
                if not served and route.request.is_navigation_request() and route.request.url == response.url:
                    served = True
                    keep = {k: v for k, v in response.headers.items() if k in {
                        "content-type", "content-security-policy", "content-security-policy-report-only",
                        "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy"}}
                    route.fulfill(status=response.status, headers=keep, body=response.body)
                elif self.options['external_scripts'] and self.transport is not None and route.request.resource_type == 'script' and route.request.method == 'GET' and scripts < self.options['max_scripts']:
                    scripts += 1
                    try:
                        script = script_response(self.transport, route.request.url)
                    except (OSError, ValueError): script = None
                    if script is None:
                        blocked += 1
                        route.abort()
                    else:
                        keep = {k: v for k, v in script.headers.items() if k in {'content-type', 'x-content-type-options', 'access-control-allow-origin'}}
                        route.fulfill(status=script.status, headers=keep, body=script.body)
                else:
                    blocked += 1
                    route.abort()
            context.route("**/*", intercept)
            page.goto(response.url, wait_until="domcontentloaded", timeout=6000)
            page.wait_for_timeout(200)
            executed = page.locator("html").get_attribute("data-navi-proof") == token
            return {"executed": executed, "engine": "Chromium", "mode": "isolated response replay",
                    "network_requests_blocked": blocked, "script_fetch_attempts": scripts, "marker": token,
                    "reason": "Injected JavaScript set the document proof marker." if executed else "No execution marker observed; CSP or context may prevent execution."}
        finally:
            context.close()

    def close(self):
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass  # A crashed optional browser must not discard other findings.
            self._browser = None
        if self._driver:
            try:
                self._driver.stop()
            except Exception:
                pass
            self._driver = None
