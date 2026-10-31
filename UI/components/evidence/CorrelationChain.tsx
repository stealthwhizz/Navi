import { STATUS_LABEL } from '@/lib/format';
import type { CheckResult, Issue } from '@/lib/types';
import { Icon, type IconName } from '../Icon';
import { cx } from '../ui';
import s from './evidence.module.css';

const CHECK: Record<CheckResult, { icon: IconName; word: string }> = {
  pass: { icon: 'check', word: 'Passed' },
  fail: { icon: 'x', word: 'Failed' },
  unknown: { icon: 'help', word: 'Unknown' },
};
const NO_CANDIDATE: Partial<Record<Issue['status'], string>> = {
  code_only: 'No runtime finding was a candidate for this code path, so it stays Code only.',
  runtime_only: 'No source finding was a candidate for this route, so it stays Runtime only.',
};

export function CorrelationChain({ issue }: { issue: Issue }) {
  const c = issue.correlation;
  if (!c) return <p className="prose">{NO_CANDIDATE[issue.status] ?? 'The API returned no correlation record for this issue.'}</p>;
  const firstOpen = c.checks.findIndex((k) => k.result !== 'pass');
  return (
    <>
      <ol className={cx(s.chain, !c.accepted && s.unproven)} aria-label="Correlation checks">
        {c.checks.map((k, i) => (
          <li key={k.name} className={firstOpen !== -1 && i >= firstOpen ? s.open : undefined}>
            <span className={cx(s.node, k.result === 'unknown' && s.unknown)}>
              <span><Icon name={CHECK[k.result].icon} /> {k.name.replaceAll('_', ' ').replace(/^./, (ch) => ch.toUpperCase())}</span>
              <span className="meta">{CHECK[k.result].word}: {k.detail}</span>
            </span>
          </li>
        ))}
        <li className={c.accepted ? undefined : s.open}><span className={cx(s.node, s.status)}>{STATUS_LABEL[issue.status]}</span></li>
      </ol>
      <p className={cx('prose', s.rationale)}>{c.rationale}</p>
    </>
  );
}
