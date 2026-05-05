import { inspectRequest } from './waf';
import { logRequestToD1 } from './db';

interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
}

/**
 * VulnShop Worker
 * 
 * Runs the WAF via run_worker_first before any request is processed.
 * Logs all requests to D1, handles API stubs, and serves static assets.
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';

    // Extract geolocation from request.cf object (populated by Cloudflare edge)
    const cf = request.cf as Record<string, unknown> | undefined;
    const asn = cf?.asn ? Number(cf.asn) : undefined;
    const asnOrg = cf?.asOrganization as string | undefined;
    const country = cf?.country as string | undefined;
    const city = cf?.city as string | undefined;

    // Read request body (for POST/PUT inspection)
    let bodyText = '';
    if (['POST', 'PUT'].includes(request.method)) {
      try {
        bodyText = await request.clone().text();
      } catch {
        // If body is not text, skip it
      }
    }

    // Run WAF inspection
    const inspection = inspectRequest(
      request.method,
      url.pathname,
      url.search.substring(1), // query string without the leading ?
      bodyText,
      request.headers.get('user-agent') || undefined,
      request.headers.get('referer') || undefined
    );

    // Prepare log entry (async logging happens later)
    const logEntry = {
      timestamp: Date.now(),
      method: request.method,
      path: url.pathname,
      query: url.search.substring(1) || undefined,
      bodyPreview: bodyText.substring(0, 256) || undefined,
      userAgent: request.headers.get('user-agent') || undefined,
      clientIp,
      asn,
      asnOrg,
      country,
      city,
      verdict: inspection.verdict,
      matchedRules: inspection.matchedRules,
      matchedCategories: inspection.matchedCategories,
    };

    // Handle WAF verdicts
    if (inspection.verdict === 'blocked') {
      // Log and return 403 with matched rule details
      ctx.waitUntil(logRequestToD1(env.DB, ctx, logEntry));
      return new Response(
        JSON.stringify({
          status: 'blocked',
          message: 'Request blocked by WAF',
          matched_rules: inspection.matchedRules.map((r) => ({
            id: r.id,
            description: r.description,
            category: r.category,
            severity: r.severity,
          })),
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    if (inspection.verdict === 'challenged') {
      // Log and return 429 with stub challenge page
      ctx.waitUntil(logRequestToD1(env.DB, ctx, logEntry));
      return new Response(
        `<html>
          <head><title>Rate Limited</title></head>
          <body>
            <h1>Challenge Required</h1>
            <p>Your request has been flagged as potentially suspicious.</p>
            <p>In production, this would present a CAPTCHA (e.g., Cloudflare Turnstile).</p>
            <p>Matched rules: ${inspection.matchedRules.map((r) => r.id).join(', ')}</p>
          </body>
        </html>`,
        {
          status: 429,
          headers: { 'Content-Type': 'text/html' },
        }
      );
    }

    // Request passed WAF — now route to API or static assets
    // All requests get logged (allowed verdicts too)
    ctx.waitUntil(logRequestToD1(env.DB, ctx, logEntry));

    // Handle API endpoints (stubs only — never execute real operations)
    if (url.pathname === '/api/search') {
      const q = url.searchParams.get('q') || '';
      return new Response(
        JSON.stringify({
          query: q,
          results: [
            { id: 1, name: 'Blue Running Shoes', price: 89.99 },
            { id: 2, name: 'Red Sneakers', price: 45.99 },
            { id: 3, name: 'White Athletic Shoes', price: 129.99 },
          ],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    if (url.pathname === '/api/comment') {
      const c = url.searchParams.get('c') || '';
      return new Response(
        JSON.stringify({
          comment: c,
          posted_at: new Date().toISOString(),
          status: 'pending_moderation',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    if (url.pathname === '/api/file') {
      const name = url.searchParams.get('name') || '';
      return new Response(
        JSON.stringify({
          filename: name,
          size_bytes: 1024,
          last_modified: new Date().toISOString(),
          // Stub content — never read actual files
          content: '[File content would go here, but this is a stub]',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    if (url.pathname === '/api/ping') {
      const host = url.searchParams.get('host') || '';
      return new Response(
        JSON.stringify({
          target: host,
          status: 'online',
          response_time_ms: Math.random() * 100,
          // Stub response — never execute actual ping/shell commands
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // All other requests: try to serve static assets via default asset handler
    // If no static asset matches, return 404
    return env.ASSETS.fetch(request);
  },
};
