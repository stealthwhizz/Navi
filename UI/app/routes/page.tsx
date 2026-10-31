'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useScan } from '@/components/AppShell';
import { Icon } from '@/components/Icon';
import { Empty, Notice, cx, ui } from '@/components/ui';
import { api } from '@/lib/api';
import { loc } from '@/lib/format';
import type { Route } from '@/lib/types';
import { useApi } from '@/lib/useApi';

const PROVENANCE: Record<Route['provenance'], string> = {
  laravel: 'Laravel route file', filesystem: 'File path', front_controller: 'Front controller dispatch', fuzzy: 'Matched by name', unresolved: 'Unresolved',
};
const FILTERS = { all: 'All', unmapped: 'Without a handler', issues: 'With issues' } as const;
type Filter = keyof typeof FILTERS;
const isUnmapped = (r: Route) => !r.handler || r.provenance === 'unresolved';

export default function RoutesPage() {
  const { scan } = useScan();
  const raw = useSearchParams().get('filter');
  const filter: Filter = raw === 'unmapped' || raw === 'issues' ? raw : 'all';
  const { data: routes, error } = useApi(scan?.id ?? null, () => api.routes(scan!.id));

  if (!scan) return <><h1>Routes</h1><Empty>The route map appears after your first scan. <Link href="/?new=1">Start a scan</Link>.</Empty></>;
  if (error) return <><h1>Routes</h1><Notice kind="error">{error.message}</Notice></>;
  if (!routes) return <><h1>Routes</h1><p className="on-sky" role="status">Loading routes…</p></>;

  const shown = routes.filter((r) => (filter === 'unmapped' ? isUnmapped(r) : filter === 'issues' ? r.issue_count > 0 : true));
  // Native history update keeps focus on the pressed chip (no Next navigation).
  const choose = (next: Filter) => window.history.replaceState(null, '', `${window.location.pathname}?scan=${encodeURIComponent(scan.id)}${next === 'all' ? '' : `&filter=${next}`}`);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Routes</h1>
          <p className="meta">{routes.length} routes, {routes.filter(isUnmapped).length} without a handler. Unresolved routes are shown, never guessed.</p>
        </div>
      </div>
      <section className={ui.panel} aria-label="Route map">
        <div className={ui.filters}>
          <div className={ui.chips} role="group" aria-label="Filter routes">
            {(Object.keys(FILTERS) as Filter[]).map((key) => (
              <button key={key} type="button" className={ui.chip} aria-pressed={filter === key} onClick={() => choose(key)}>{FILTERS[key]}</button>
            ))}
          </div>
        </div>
        {shown.length === 0 ? (
          <Empty>{routes.length ? 'No routes match this filter.' : 'This scan discovered no routes. Check the scan coverage for parser errors and skipped files.'}</Empty>
        ) : (
          <div className={ui.tableWrap}>
            <table className={cx(ui.table, ui.stackable)}>
              <caption className="sr-only">Route map: URL to handler, parameters, and mapping confidence</caption>
              <thead>
                <tr><th scope="col">Route</th><th scope="col">Handler</th><th scope="col">Declared at</th><th scope="col">Parameters</th><th scope="col">Mapping</th><th scope="col">Tested</th><th scope="col">Issues</th></tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={`${r.method} ${r.path}`}>
                    <td data-label="Route" className="mono">{r.method} {r.path}</td>
                    <td data-label="Handler">
                      {r.handler
                        ? <><div className="mono wrap-any">{r.handler.name}</div><div className="meta mono">{loc(r.handler.file, r.handler.line_start, r.handler.line_end)}</div></>
                        : <span className={cx(ui.badge, ui.badgeWarning)}><Icon name="alert" />Handler unresolved</span>}
                    </td>
                    <td data-label="Declared" className="mono">{r.declared_at ?? <span className="muted">Unknown</span>}</td>
                    <td data-label="Params" className="mono">{r.params.length ? r.params.join(', ') : <span className="muted">None read</span>}</td>
                    <td data-label="Mapping">{PROVENANCE[r.provenance]}<div className="meta">{r.confidence} confidence</div></td>
                    <td data-label="Tested">{r.tested ? <><Icon name="check" /> Yes</> : <span className="muted">No</span>}</td>
                    <td data-label="Issues">{r.issue_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
