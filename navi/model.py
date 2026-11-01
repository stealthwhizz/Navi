"""Versioned, shared evidence model. No scanner-specific schema leaks into correlation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any


SCHEMA_VERSION = "1.2"
RULES = {
    "CWE-78": ("OS command injection", "critical", "Avoid a shell and use a fixed executable with an argument array. If shell use is necessary, validate inputs and quote each argument appropriately (escapeshellarg in PHP); never let input choose the executable."),
    "CWE-89": ("SQL injection", "high", "Use a parameterized query; pass values separately from SQL text."),
    "CWE-79": ("Cross-site scripting", "high", "Use automatic HTML escaping and context-appropriate encoding. Avoid rendering untrusted HTML."),
    "CWE-22": ("Path traversal", "high", "Resolve the requested path under an allowed directory and enforce that boundary, or use send_from_directory."),
    "CWE-601": ("Open redirect", "medium", "Accept local relative paths or validate destinations against an explicit allowlist."),
    "CWE-798": ("Hard-coded credential", "high", "Load credentials from a secret store or environment, and rotate any exposed credential."),
    "CWE-639": ("Broken object authorization (IDOR)", "high", "Enforce the configured owner, role, and tenant policy on every object access."),
}


def fingerprint(*parts: Any) -> str:
    data = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode()).hexdigest()[:20]


@dataclass(frozen=True, order=True)
class Input:
    location: str
    name: str


@dataclass
class Binding:
    route: str
    method: str
    parameter: str
    location: str
    handler: str
    flow: list[str] = field(default_factory=list)
    provenance: str = "source"
    scenario: str | None = None


@dataclass
class Route:
    path: str
    methods: list[str]
    file: str
    function: str
    line: int
    end_line: int
    parameters: list[dict] = field(default_factory=list)
    provenance: str = "source"


@dataclass
class Finding:
    id: str
    origin: str
    cwe: str
    title: str
    severity: str
    source: dict | None = None
    bindings: list[Binding] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    verification: str = "unverified"
    confidence: str = "candidate"
    note: str = ""
    scanner: str = "native"
    rule_id: str | None = None
    source_flows: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        from .evidence import runtime_observations
        value = asdict(self)
        value['fingerprint'] = self.id
        value['runtime'] = runtime_observations(value['evidence'], value['bindings']) if self.origin == 'dast' else []
        return value


@dataclass
class Analysis:
    digest: str | None
    routes: list[Route]
    findings: list[Finding]
    gaps: list[dict]
    files: int
    function_map: dict = field(default_factory=dict)
    templates: dict = field(default_factory=dict)


@dataclass
class Check:
    cwe: str
    route: str
    method: str
    parameter: str
    location: str
    outcome: str
    reason: str
    evidence: list[dict] = field(default_factory=list)
    scenario: str | None = None


def gap(component: str, reason: str, **details: Any) -> dict:
    return {"component": component, "reason": reason, **details}



def no_source_analysis():
    return Analysis(digest=None, routes=[], findings=[], files=0,
        gaps=[gap("static", "No source supplied: runtime testing is available, but SAST and source correlation were not performed.")],
        function_map={"nodes": [], "edges": [], "scope": "No source supplied; no function reachability or root-cause claims."})
