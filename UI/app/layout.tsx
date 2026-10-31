import type { Metadata } from 'next';
import { Atkinson_Hyperlegible_Mono, Atkinson_Hyperlegible_Next, Instrument_Serif } from 'next/font/google';
import { Suspense, type ReactNode } from 'react';
import { AppShell } from '@/components/AppShell';
import './globals.css';

// Chosen so payloads and paths read exactly: 0/O, 1/l/I, rn/m stay distinct (design system §3).
const ui = Atkinson_Hyperlegible_Next({ subsets: ['latin'], weight: ['400', '600'], variable: '--face-ui', display: 'swap' });
const code = Atkinson_Hyperlegible_Mono({ subsets: ['latin'], weight: ['400', '600'], variable: '--face-code', display: 'swap' });
const display = Instrument_Serif({ subsets: ['latin'], weight: '400', variable: '--face-display', display: 'swap' });

export const metadata: Metadata = {
  title: { default: 'Navi', template: '%s | Navi' },
  description: 'SAST and DAST correlation for PHP applications',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${ui.variable} ${code.variable} ${display.variable}`}>
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
