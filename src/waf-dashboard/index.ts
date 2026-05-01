// WAF Dashboard Worker
// Serves dashboard UI and analytics API routes
// See PRD.md for full spec

interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // TODO: Implement API routes (/api/summary, /api/recent) in Phase 7
    return new Response('WAF Dashboard Worker - Phase 1 scaffolding', { status: 200 });
  },
};
