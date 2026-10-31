'use client';

import Link from 'next/link';
import { useScan } from '@/components/AppShell';
import { Icon } from '@/components/Icon';
import { Empty, Notice, cx, ui } from '@/components/ui';
import { api } from '@/lib/api';
import { CWE_NAME, loc } from '@/lib/format';
import { useApi } from '@/lib/useApi';

export default function SuppressedPage() {
  const { scan } = useScan();
  const { data: rows, error } = useApi(scan?.id ?? null, () => api.suppressed(scan!.id));
  const head = (
    <div className="page-head">
      <div>
        <h1>Suppressed</h1>
        <p className="meta">Findings judged safe because a sanitizer covers them. They are kept here and left out of the issue list.</p>
      </div>
    </div>
  );

  if (!scan) return <>{head}<Empty>Suppressed findings appear after your first scan. <Link href="/?new=1">Start a scan</Link>.</Empty></>;
  if (error) return <>{head}<Notice kind="error">{error.message}</Notice></>;
  if (!rows) return <>{head}<p className="on-sky" role="status">Loading suppressed findings…</p></>;

  return (
    <>
      {head}
      <section className={ui.panel} aria-label="Suppressed findings">
        {rows.length === 0 ? <Empty>Nothing was suppressed in this scan.</Empty> : (
          <div className={ui.tableWrap}>
            <table className={cx(ui.table, ui.stackable)}>
              <caption className="sr-only">Suppressed findings with the sanitizer and reason</caption>
              <thead>
                <tr><th scope="col">CWE</th><th scope="col">Finding</th><th scope="col">Location</th><th scope="col">Sanitizer</th><th scope="col">Reason</th><th scope="col">Found by</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td data-label="CWE">CWE-{r.cwe}{CWE_NAME[r.cwe] && ` ${CWE_NAME[r.cwe]}`}</td>
                    <td data-label="Finding"><Icon name="shield" /> {r.title}</td>
                    <td data-label="Location" className="mono">{loc(r.file, r.line)}</td>
                    <td data-label="Sanitizer" className="mono">{r.sanitizer}</td>
                    <td data-label="Reason">{r.reason}</td>
                    <td data-label="Found by">{r.source === 'sast' ? 'Code analysis' : 'Runtime test'}</td>
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
