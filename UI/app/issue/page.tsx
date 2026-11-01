'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useEffect } from 'react';
import { useScan } from '@/components/AppShell';
import { CorrelationChain } from '@/components/evidence/CorrelationChain';
import { CodeEvidence, RuntimeEvidence } from '@/components/evidence/Evidence';
import s from '@/components/evidence/evidence.module.css';
import { Icon } from '@/components/Icon';
import { Notice, SeverityMeter, StatusBadge, cx, ui } from '@/components/ui';
import { api } from '@/lib/api';
import { CWE_NAME, loc, when } from '@/lib/format';
import { useApi } from '@/lib/useApi';

export default function IssuePage() {
  const id = useSearchParams().get('id');
  const { scan } = useScan();
  const issueKey = id && scan ? `${scan.id}:${id}` : null;
  const { data: issue, error } = useApi(issueKey, () => api.issue(id!, scan!.id));
  useEffect(() => { if (issue) document.title = `${issue.title} | Navi`; }, [issue]);

  const back = <p><Link href={{ pathname: '/issues/', query: scan ? { scan: scan.id } : undefined }}><Icon name="back" /> Issues</Link></p>;
  if (!id) return <>{back}<Notice kind="error">No issue selected. Open an issue from the issue list.</Notice></>;
  if (error) return <>{back}<Notice kind="error">{error.message}</Notice></>;
  if (!issue) return <>{back}<p className="on-sky" role="status">Loading issue…</p></>;

  return (
    <div className={issue.status === 'confirmed' ? s.confirmedIssue : undefined}>
      {back}
      <div className={s.head}>
        <h1 className="wrap-any">{issue.title}</h1>
        <div className={s.row}>
          <StatusBadge status={issue.status} />
          <SeverityMeter level={issue.severity} />
          <span>CWE-{issue.cwe}{CWE_NAME[issue.cwe] && ` ${CWE_NAME[issue.cwe]}`}</span>
          <span>Risk {issue.risk.toFixed(1)}</span>
        </div>
      </div>
      <div className="stack">
        <section className={ui.panel} aria-labelledby="where">
          <h2 id="where" className={cx('h3', ui.panelHead)}>Where to fix</h2>
          <dl className={s.whereGrid}>
            <div><dt>Endpoint</dt><dd className="mono">{issue.dast ? `${issue.dast.method} ${issue.dast.url}` : issue.route ? `${issue.route.method} ${issue.route.path}` : 'Not mapped to a route'}</dd></div>
            <div><dt>Parameter</dt><dd className="mono">{issue.dast?.parameter ?? (issue.sast ? issue.sast.source.expr : 'None')}</dd></div>
            <div><dt>Test payload</dt><dd className="mono wrap-any">{issue.dast?.payload ?? 'No payload recorded'}</dd></div>
            <div><dt>Code to change</dt><dd className="mono">{issue.sast ? loc(issue.sast.file, issue.sast.highlight_line) : issue.location ? loc(issue.location.file, issue.location.line) : 'No source location found'}</dd></div>
            <div><dt>Fingerprint</dt><dd className="mono">{issue.fingerprint}</dd></div>
            <div><dt>This scan</dt><dd>{when(issue.last_seen)} · {issue.signals_combined} signals · {issue.evidence_count} observations</dd></div>
          </dl>
        </section>
        <section className={ui.panel} aria-labelledby="why">
          <h2 id="why" className={cx('h3', ui.panelHead)}>Reasoning</h2>
          <p className="prose">{issue.reasoning.native}</p>
          <h3 className="h4">AI analysis</h3>
          {issue.reasoning.ai
            ? <><p className="prose">{issue.reasoning.ai}</p><p className="meta">{issue.reasoning.ai_provider} · {issue.reasoning.ai_model} · Evidence-based advice</p></>
            : <p className="meta">{issue.reasoning.ai_reason ?? 'No AI analysis is available for this finding.'}</p>}
          <details open={issue.status === 'confirmed'}><summary>Why these findings were linked</summary><CorrelationChain issue={issue} /></details>
        </section>
        <section className={ui.panel} aria-labelledby="fix">
          <h2 id="fix" className={cx('h3', ui.panelHead)}>Suggested fix</h2>
          <p className="prose">{issue.fix ?? 'Review the recorded evidence and source flow to determine the appropriate fix.'}</p>
          <p className="meta">{issue.risk_basis}</p>
        </section>
        <div className={s.grid}>
          <CodeEvidence issue={issue} />
          <RuntimeEvidence issue={issue} />
        </div>
      </div>
    </div>
  );
}
