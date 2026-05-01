// Vulnshop Worker
// Vulnerable demo app + WAF logic
// See PRD.md for full spec

interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // TODO: Implement WAF inspector and routing logic in Phase 4-5
    return new Response('VulnShop Worker - Phase 1 scaffolding', { status: 200 });
  },
};
