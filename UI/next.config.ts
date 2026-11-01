import type { NextConfig } from 'next';

// The supplied UI uses the native FastAPI namespace; exported pages live under /ui.
const API_PATHS = ['/api/:path*'];
const devApi = process.env.NAVI_API ?? 'http://127.0.0.1:8080';

const config: NextConfig = {
  output: 'export', // FastAPI serves the built `out/` directory; no Node while serving
  basePath: '/ui',
  trailingSlash: true, // emits route/index.html, which Starlette StaticFiles(html=True) resolves
  // `next dev` only: proxy API calls so the browser stays same-origin, as it is behind FastAPI.
  // The slash redirect is skipped so `/api` requests retain their original paths.
  ...(process.env.NODE_ENV === 'development' && {
    skipTrailingSlashRedirect: true,
    rewrites: async () => API_PATHS.map((source) => ({ source, destination: `${devApi}${source}`, basePath: false as const })),
  }),
};

export default config;
