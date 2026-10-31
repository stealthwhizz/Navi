from typing import Literal

from pydantic import BaseModel, ConfigDict

ScanState = Literal["queued", "running", "completed", "failed"]
ScanPhase = Literal["routes", "sast", "dast", "correlate"]
IssueStatus = Literal["confirmed", "code_only", "runtime_only"]
Severity = Literal["critical", "high", "medium", "low", "informational"]
CheckResult = Literal["pass", "fail", "unknown"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Progress(StrictModel):
    done: int
    total: int


class CoverageItem(StrictModel):
    kind: str
    location: str
    detail: str


class CoverageError(StrictModel):
    stage: str
    message: str


class DastCoverage(StrictModel):
    requests: int = 0
    routes_tested: int = 0
    params_tested: int = 0
    blocked: int = 0
    timeouts: int = 0


class Coverage(StrictModel):
    frameworks: list[str] = []
    files_parsed: int = 0
    files_skipped: list[dict[str, str]] = []
    routes_total: int = 0
    routes_unmapped: int = 0
    unresolved: list[CoverageItem] = []
    rules_not_run: list[dict[str, str]] = []
    dast: DastCoverage = DastCoverage()
    errors: list[CoverageError] = []


class ScanCounts(StrictModel):
    confirmed: int = 0
    code_only: int = 0
    runtime_only: int = 0
    suppressed: int = 0


class ScanResponse(StrictModel):
    id: str
    state: ScanState
    source_root: str
    target_origin: str
    created_at: str
    started_at: str | None
    finished_at: str | None
    phase: ScanPhase | None
    progress: Progress | None
    error: str | None
    counts: ScanCounts
    coverage: Coverage | None


class StartScanRequest(StrictModel):
    source_root: str
    target_origin: str


class StartScanResponse(StrictModel):
    scan_id: str
    state: Literal["queued"]


class RouteRef(StrictModel):
    method: str
    path: str


class LocationRef(StrictModel):
    file: str
    line: int


class IssueSummary(StrictModel):
    id: str
    fingerprint: str
    status: IssueStatus
    severity: Severity
    risk: int
    cwe: int
    title: str
    route: RouteRef | None
    location: LocationRef | None


class SastSource(StrictModel):
    expr: str
    type: str
    location: str


class SastSink(StrictModel):
    name: str
    type: str
    location: str


class SastPathStep(StrictModel):
    label: str
    location: str
    resolved: bool


class SanitizerEvidence(StrictModel):
    name: str
    location: str
    effective: bool
    reason: str


class SastEvidence(StrictModel):
    rule_id: str
    file: str
    line_start: int
    line_end: int
    snippet: dict[str, str | int]
    highlight_line: int
    source: SastSource
    sink: SastSink
    path: list[SastPathStep]
    sanitizers: list[SanitizerEvidence]


class DastResponse(StrictModel):
    status: int
    excerpt: str
    truncated: bool


class DastEvidence(StrictModel):
    rule_id: str
    method: str
    url: str
    parameter: str | None
    payload: str | None
    request: str
    response: DastResponse
    evidence: str | None
    oracle: str


class CorrelationCheck(StrictModel):
    name: str
    result: CheckResult
    detail: str


class Correlation(StrictModel):
    accepted: bool
    rationale: str
    checks: list[CorrelationCheck]


class IssueDetail(IssueSummary):
    scan_id: str
    first_seen: str
    last_seen: str
    sast: SastEvidence | None
    dast: DastEvidence | None
    correlation: Correlation | None


class RouteHandler(StrictModel):
    name: str
    file: str
    line_start: int
    line_end: int


class RouteResponse(StrictModel):
    method: str
    path: str
    declared_at: str | None
    handler: RouteHandler | None
    params: list[str]
    provenance: Literal["laravel", "filesystem", "front_controller", "fuzzy", "unresolved"]
    confidence: Literal["high", "medium", "low"]
    tested: bool
    issue_count: int


class SuppressedResponse(StrictModel):
    id: str
    source: Literal["sast", "dast"]
    cwe: int
    title: str
    file: str
    line: int
    sanitizer: str
    reason: str
