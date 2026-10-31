from dataclasses import dataclass


@dataclass(frozen=True)
class FindingInput:
    source: str
    cwe: int
    title: str
    severity: str
    risk: int
    fingerprint: str
    route: dict | None
    location: dict | None
    sast: dict | None = None
    dast: dict | None = None
