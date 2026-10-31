import type { ReactNode } from 'react';
import { loc } from '@/lib/format';
import type { Issue } from '@/lib/types';
import { Icon, type IconName } from '../Icon';
import { CopyButton, Empty, cx, ui } from '../ui';
import s from './evidence.module.css';

function Panel({ icon, title, rule, children }: { icon: IconName; title: string; rule?: string; children: ReactNode }) {
  return (
    <section className={ui.panel} aria-label={`${title} evidence`}>
      <div className={ui.panelHead}><h2 className="h3"><Icon name={icon} /> {title}</h2>{rule && <span className="meta mono">{rule}</span>}</div>
      {children}
    </section>
  );
}

function Block({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return <div className={s.block}><div className={ui.panelHead}><h3 className="h4">{title}</h3>{action}</div>{children}</div>;
}

// Wraps every occurrence of `needle` in <mark>; React escapes both sides.
function Marked({ text, needle }: { text: string; needle: string | null }) {
  if (!needle) return <>{text}</>;
  return <>{text.split(needle).map((part, i) => <span key={i}>{i > 0 && <mark>{needle}</mark>}{part}</span>)}</>;
}

export function CodeEvidence({ issue }: { issue: Issue }) {
  const x = issue.sast;
  if (!x) return <Panel icon="code" title="Code"><Empty>No source finding matched this runtime behaviour. If the route has no handler, the route map shows why.</Empty></Panel>;
  return (
    <Panel icon="code" title="Code" rule={x.rule_id}>
      <dl className={ui.facts}>
        <dt>File</dt><dd className="mono">{loc(x.file, x.line_start, x.line_end)}</dd>
        <dt>Source</dt><dd><span className="mono">{x.source.expr}</span> <span className="muted">({x.source.type}) at</span> <span className="mono">{x.source.location}</span></dd>
        <dt>Sink</dt><dd><span className="mono">{x.sink.name}</span> <span className="muted">({x.sink.type}) at</span> <span className="mono">{x.sink.location}</span></dd>
      </dl>
      <Block title="Snippet" action={<CopyButton text={x.snippet.code} what="code snippet" />}>
        <pre className={s.code} tabIndex={0} aria-label={`Lines ${x.snippet.start_line} onward of ${x.file}`}>
          {x.snippet.code.split('\n').map((line, i) => {
            const n = x.snippet.start_line + i;
            return <span key={n} className={cx(s.ln, n === x.highlight_line && s.hl)}><span>{n}</span><span>{line}</span></span>;
          })}
        </pre>
      </Block>
      <Block title="Data flow">
        {x.path.length ? (
          <ol className={s.flow}>
            {x.path.map((step, i) => (
              <li key={i} className={step.resolved ? undefined : s.unresolved}>
                <div>
                  <div className="mono wrap-any">{step.label}</div>
                  <div className="meta"><span className="mono">{step.location}</span>{!step.resolved && <>, <span className="warning-text">unresolved step</span></>}</div>
                </div>
              </li>
            ))}
          </ol>
        ) : <Empty>The rule recorded no data-flow steps.</Empty>}
      </Block>
      <Block title="Sanitizers">
        {x.sanitizers.length ? (
          <ul className={ui.plain}>
            {x.sanitizers.map((z) => (
              <li key={`${z.name}@${z.location}`}>
                <span className="mono">{z.name}</span> at <span className="mono">{z.location}</span>: <strong>{z.effective ? 'effective' : 'not effective for this CWE'}</strong>. {z.reason}
              </li>
            ))}
          </ul>
        ) : <p className="muted">No sanitizer on this path.</p>}
      </Block>
    </Panel>
  );
}

export function RuntimeEvidence({ issue }: { issue: Issue }) {
  const d = issue.dast;
  if (!d) {
    return <Panel icon="globe" title="Runtime"><Empty>{issue.cwe === 798 ? 'Hard-coded credentials are found in source only; no runtime test applies.' : 'DAST did not observe this issue on a tested route.'}</Empty></Panel>;
  }
  const evidenceShown = !d.evidence || d.response.excerpt.includes(d.evidence);
  return (
    <Panel icon="globe" title="Runtime" rule={d.rule_id}>
      <dl className={ui.facts}>
        <dt>Request</dt><dd className="mono">{d.method} {d.url}</dd>
        <dt>Parameter</dt><dd className="mono">{d.parameter ?? 'None'}</dd>
        <dt>Payload</dt><dd className="mono">{d.payload ?? 'None'}</dd>
      </dl>
      <Block title="Request sent" action={<CopyButton text={d.request} what="raw request" />}>
        <pre className={cx(s.code, s.raw)} tabIndex={0}><Marked text={d.request} needle={d.payload} /></pre>
      </Block>
      <Block title={`Response, status ${d.response.status}`} action={<CopyButton text={d.response.excerpt} what="response excerpt" />}>
        {d.response.excerpt
          ? <pre className={cx(s.code, s.raw)} tabIndex={0}><Marked text={d.response.excerpt} needle={d.evidence} /></pre>
          : <p className="muted">The response had no body.</p>}
        {d.response.truncated && <p className="meta">Excerpt truncated to the stored limit.</p>}
        {!evidenceShown && <p className="meta">The evidence string is outside the stored excerpt: <span className="mono">{d.evidence}</span></p>}
      </Block>
      <Block title="Why this counts as evidence"><p className="prose">{d.oracle}</p></Block>
    </Panel>
  );
}
