import type { NextConfig } from 'next';

// API paths the UI calls (docs/03-Architecture.md §4). Pages live under /ui so they never collide with them.
const API_PATHS = ['/scans', '/scans/:path*', '/issues', '/issues/:path*', '/routes', '/suppressed', '/reports/:path*'];
const devApi = process.env.CYBERFORGE_API ?? 'http://127.0.0.1:8000';

const config: NextConfig = {
  output: 'export', // FastAPI serves the built `out/` directory; no Node at demo time
  basePath: '/ui',
  trailingSlash: true, // emits route/index.html, which Starlette StaticFiles(html=True) resolves
  // `next dev` only: proxy API calls so the browser stays same-origin, as it is behind FastAPI.
  // The slash redirect is skipped so `/scans` is proxied as-is instead of becoming `/scans/`.
  ...(process.env.NODE_ENV === 'development' && {
    skipTrailingSlashRedirect: true,
    rewrites: async () => API_PATHS.map((source) => ({ source, destination: `${devApi}${source}`, basePath: false as const })),
  }),
};

export default config;
