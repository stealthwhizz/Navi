'use client';

import Link from 'next/link';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { createContext, useContext, useState, type ReactNode } from 'react';
import { api, setAccessToken } from '@/lib/api';
import { when } from '@/lib/format';
import type { Scan } from '@/lib/types';
import { useApi } from '@/lib/useApi';
import { Icon, type IconName } from './Icon';
import { Notice, cx, ui } from './ui';
import s from './AppShell.module.css';

interface ScanContextValue {
  scans: Scan[]; // newest first, with live updates applied
  scan: Scan | null; // ?scan= or the newest scan; null when no scans exist
  updateScan: (next: Scan) => void; // live polling pushes fresh state here so the sidebar stays in sync
}
const ScanContext = createContext<ScanContextValue | null>(null);

export function useScan(): ScanContextValue {
  const value = useContext(ScanContext);
  if (!value) throw new Error('useScan must be used inside <AppShell>');
  return value;
}

const NAV: { href: string; label: string; icon: IconName; match: (p: string) => boolean }[] = [
  { href: '/', label: 'Dashboard', icon: 'dashboard', match: (p) => p === '/' },
  { href: '/issues/', label: 'Issues', icon: 'list', match: (p) => p.startsWith('/issue') },
  { href: '/routes/', label: 'Route map', icon: 'route', match: (p) => p.startsWith('/routes') },
  { href: '/scans/', label: 'Scan history', icon: 'history', match: (p) => p.startsWith('/scans') },
];

// Two overlapping scanners: code analysis (blue) and runtime testing (cantaloupe). Issues live where they overlap.
function Mark() {
  return (
    <svg viewBox="0 0 26 18" aria-hidden="true">
      <circle cx="9" cy="9" r="7.5" fill="none" stroke="var(--accent-hover)" strokeWidth="1.75" />
      <circle cx="17" cy="9" r="7.5" fill="none" stroke="var(--confirmed)" strokeWidth="1.75" />
    </svg>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const params = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const wanted = params.get('scan');
  const [authVersion, setAuthVersion] = useState(0);
  const [key, setKey] = useState('');
  const loaded = useApi(`scans:${wanted ?? ''}:${authVersion}`, api.scans);
  const [fresh, setFresh] = useState<Record<string, Scan>>({});

  const scans = (loaded.data ?? []).map((x) => fresh[x.id] ?? x);
  const scan = (wanted ? scans.find((x) => x.id === wanted) : scans[0]) ?? null;
  const missing = !!wanted && !!loaded.data && !scan;
  const query = scan ? { scan: scan.id } : undefined;

  let content: ReactNode;
  if (loaded.error) {
    content = <Notice kind="error" action={<p><button type="button" className={cx(ui.btn, ui.quiet, ui.small)} onClick={() => window.location.reload()}>Reload</button></p>}>{loaded.error.message}</Notice>;
  } else if (missing) {
    content = <Notice kind="error" action={<p><Link href="/">Open the newest scan</Link></p>}>Scan {wanted} doesn&apos;t exist.</Notice>;
  } else if (!loaded.data) {
    content = <p className="on-sky" role="status">Loading…</p>;
  } else {
    content = <ScanContext.Provider value={{ scans, scan, updateScan: (next) => setFresh((f) => ({ ...f, [next.id]: next })) }}>{children}</ScanContext.Provider>;
  }

  return (
    <div className={s.layout}>
      <aside className={s.sidebar}>
        <Link className={s.brand} href={{ pathname: '/', query }}><Mark />Navi</Link>
        {loaded.data && scans.length > 0 && (
          <div className={s.scanBox}>
            <label htmlFor="scan-pick">Viewing scan</label>
            <select
              id="scan-pick"
              className={cx(ui.control, s.picker)}
              value={scan?.id ?? ''}
              // Issue pages belong to one scan; switching scans returns to that scan's issue list.
              onChange={(e) => router.push(`${pathname.startsWith('/issue/') ? '/issues/' : pathname}?scan=${encodeURIComponent(e.target.value)}`)}
            >
              {scans.map((x) => <option key={x.id} value={x.id}>{when(x.created_at)} ({x.state})</option>)}
            </select>
            {scan && (
              <span className={s.target}>
                <Icon name="target" /><span>{scan.state === 'running' ? 'Testing' : 'Target'}</span> <span className="mono">{scan.target_origin}</span>
              </span>
            )}
          </div>
        )}
        {loaded.data && (
          <nav className={s.nav} aria-label="Main">
            {NAV.map((item) => (
              <Link key={item.href} href={{ pathname: item.href, query }} aria-current={item.match(pathname) ? 'page' : undefined}>
                <Icon name={item.icon} />{item.label}
                {item.href === '/issues/' && scan && (
                  <span className={scan.counts.confirmed ? s.countConfirmed : s.count}>
                    {scan.counts.confirmed + scan.counts.code_only + scan.counts.runtime_only}
                  </span>
                )}
              </Link>
            ))}
          </nav>
        )}
        <div className={s.foot}>
          <details className={ui.disclosure}><summary>Workspace access key</summary><form onSubmit={(event) => {event.preventDefault(); setAccessToken(key); setAuthVersion(v => v + 1); setKey('');}}><label className="sr-only" htmlFor="workspace-key">Access key</label><input id="workspace-key" className={ui.control} type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} /><button className={ui.btn}>Unlock</button></form></details>
          <Link className={ui.btn} href={{ pathname: '/', query: { ...query, new: '1' } }}><Icon name="plus" />New scan</Link>
        </div>
      </aside>
      <main id="main" tabIndex={-1} className={s.main}>{content}</main>
    </div>
  );
}
