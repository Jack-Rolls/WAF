// WAF Dashboard Worker
// Serves dashboard UI and analytics API routes
// See PRD.md for full spec

interface Env {
  DB: D1Database;
}

/**
 * WAF Dashboard Worker
 * 
 * Handles two API routes (/api/summary, /api/recent) and serves dashboard UI.
 * run_worker_first for /api/* routes ensures APIs are handled before static assets.
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Handle API routes
    if (url.pathname === '/api/summary') {
      // TODO: Phase 3 - Query D1 for summary stats
      // For now, return empty summary structure
      return new Response(
        JSON.stringify({
          total_requests: 0,
          total_blocked: 0,
          total_challenged: 0,
          verdict_breakdown: { allowed: 0, challenged: 0, blocked: 0 },
          category_breakdown: {},
          top_countries: [],
          top_asns: [],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    if (url.pathname === '/api/recent') {
      // TODO: Phase 3 - Query D1 for recent requests
      // For now, return empty recent requests array
      return new Response(
        JSON.stringify({
          requests: [],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // All other requests: try to serve static assets
    // If no static asset matches, return 404
    return new Response('Not Found', { status: 404 });
  },
};
