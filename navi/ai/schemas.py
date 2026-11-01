"""Model output contracts. None grants access to a shell, tool, URL, or status field."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

CWE = Literal['CWE-78', 'CWE-79', 'CWE-89', 'CWE-22', 'CWE-601', 'CWE-798', 'CWE-639']
NativeCWE = Literal['CWE-78', 'CWE-79', 'CWE-89', 'CWE-22', 'CWE-601']


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Hypothesis(Contract):
    source_id: str = Field(max_length=80)
    line: int = Field(ge=1)
    cwe: CWE
    title: str = Field(min_length=1, max_length=160)
    reasoning: str = Field(min_length=1, max_length=1800)
    missing_evidence: str = Field(min_length=1, max_length=1000)


class SourceReview(Contract):
    summary: str = Field(max_length=2000)
    hypotheses: list[Hypothesis] = Field(max_length=20)


class ProposedTest(Contract):
    input_id: str = Field(max_length=80)
    cwe: NativeCWE
    hypothesis_id: str | None
    rationale: str = Field(min_length=1, max_length=1200)


class TestPlan(Contract):
    summary: str = Field(max_length=2000)
    tests: list[ProposedTest] = Field(max_length=20)


class CandidateRank(Contract):
    finding_id: str = Field(max_length=80)
    reason: str = Field(min_length=1, max_length=1000)


class LinkReview(Contract):
    issue_id: str = Field(max_length=80)
    assessment: Literal['supported', 'uncertain', 'needs_more_evidence']
    explanation: str = Field(min_length=1, max_length=1600)
    candidate_ranking: list[CandidateRank] = Field(max_length=10)
    evidence_refs: list[str] = Field(max_length=12)
    next_step: str = Field(max_length=1000)
    noise_assessment: Literal['actionable', 'possible_false_positive', 'needs_context'] = 'needs_context'
    noise_reason: str = Field(default='', max_length=1200)
    priority_hint: Literal['urgent', 'normal', 'later'] = 'normal'
    priority_reason: str = Field(default='', max_length=1000)
    fix_target_id: str | None = Field(default=None, max_length=80)
    fix_line: int | None = Field(default=None, ge=1)
    fix_reason: str = Field(default='', max_length=1200)


class CorrelationReview(Contract):
    summary: str = Field(max_length=2000)
    reviews: list[LinkReview] = Field(max_length=24)


class RegressionCase(Contract):
    name: str = Field(min_length=1, max_length=160)
    scenario: str = Field(min_length=1, max_length=1000)
    expected: str = Field(min_length=1, max_length=1000)


class Fix(Contract):
    issue_id: str = Field(max_length=80)
    source_id: str | None
    explanation: str = Field(min_length=1, max_length=1800)
    patch: str | None = Field(max_length=8000)
    regression_tests: list[RegressionCase] = Field(min_length=1, max_length=6)
    evidence_refs: list[str] = Field(max_length=12)


class RemediationReview(Contract):
    summary: str = Field(max_length=2000)
    fixes: list[Fix] = Field(max_length=20)


class GapPriority(Contract):
    gap_ids: list[str] = Field(min_length=1, max_length=12)
    priority: Literal['high', 'medium', 'low']
    reason: str = Field(min_length=1, max_length=1600)
    action: str = Field(min_length=1, max_length=1200)


class CoverageReview(Contract):
    summary: str = Field(max_length=2000)
    priorities: list[GapPriority] = Field(max_length=20)


STAGES = {'source_review': SourceReview, 'test_planning': TestPlan,
          'correlation': CorrelationReview, 'remediation': RemediationReview, 'coverage': CoverageReview}
