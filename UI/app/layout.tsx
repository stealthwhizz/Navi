import type { Metadata } from 'next';
import { Suspense, type ReactNode } from 'react';
import { AppShell } from '@/components/AppShell';
import './globals.css';

// Chosen so payloads and paths read exactly: 0/O, 1/l/I, rn/m stay distinct (design system §3).

export const metadata: Metadata = {
  title: { default: 'Navi', template: '%s | Navi' },
  description: 'SAST and DAST correlation with evidence-based reasoning',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" >
      <body>
        <a className="skip" href="#main">Skip to content</a>
        {/* useSearchParams in the shell needs a Suspense boundary for static export. */}
        <Suspense fallback={<main id="main"><p className="muted" role="status">Loading…</p></main>}>
          <AppShell>{children}</AppShell>
        </Suspense>
      </body>
    </html>
  );
}
