'use client';

import Link from 'next/link';
import { useScan } from '@/components/AppShell';
import { Icon } from '@/components/Icon';
import { Empty, ScanStateLabel, cx, ui } from '@/components/ui';
import { clock, elapsedMs, when } from '@/lib/format';

export default function ScansPage() {
  const { scans, scan: current } = useScan();
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scan history</h1>
          <p className="meta">Every scan, newest first. Open one to make it the scan you are viewing.</p>
        </div>
        <Link className={ui.btn} href={{ pathname: '/', query: { new: '1' } }}><Icon name="plus" />New scan</Link>
      </div>
      <section className={ui.panel} aria-label="Scans">
        {scans.length === 0 ? <Empty>No scans yet. <Link href="/?new=1">Start a scan</Link>.</Empty> : (
          <div className={ui.tableWrap}>
            <table className={cx(ui.table, ui.stackable)}>
              <caption className="sr-only">Scans with state, duration, and issue counts</caption>
              <thead>
                <tr><th scope="col">Started</th><th scope="col">State</th><th scope="col">Duration</th><th scope="col">Confirmed</th><th scope="col">Code only</th><th scope="col">Runtime only</th><th scope="col">Source</th><th scope="col"><span className="sr-only">Actions</span></th></tr>
              </thead>
              <tbody>
                {scans.map((x) => (
                  <tr key={x.id} className={x.id === current?.id ? ui.rowCurrent : undefined}>
                    <td data-label="Started">{when(x.started_at ?? x.created_at)}</td>
                    <td data-label="State"><ScanStateLabel scan={x} /></td>
                    <td data-label="Duration" className={ui.nowrap}>{x.started_at ? clock(elapsedMs(x)) : <span className="muted">Not started</span>}</td>
                    <td data-label="Confirmed" className={x.counts.confirmed ? ui.countHot : undefined}>{x.counts.confirmed}</td>
                    <td data-label="Code only">{x.counts.code_only}</td>
                    <td data-label="Runtime only">{x.counts.runtime_only}</td>
                    <td data-label="Source" className="mono">{x.source_root}</td>
                    <td data-label="">
                      {x.id === current?.id
                        ? <span className="meta">Viewing</span>
                        : <Link href={{ pathname: '/', query: { scan: x.id } }}>Open<span className="sr-only"> scan from {when(x.created_at)}</span></Link>}
                    </td>
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
