// WAF Dashboard Worker
// Serves dashboard UI and analytics API routes
// See PRD.md for full spec

interface Env {
  DB: D1Database;
}

type D1Row = Record<string, unknown>;

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function parseJsonArray(value: unknown): unknown[] {
  if (typeof value !== 'string' || value.trim() === '') {
    return [];
  }

  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * WAF Dashboard Worker
 *
 * Handles two API routes (/api/summary, /api/recent) and serves dashboard UI.
 * run_worker_first for /api/* routes ensures APIs are handled before static assets.
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle API routes
    if (url.pathname === '/api/summary') {
      try {
        // Aggregate stats from D1
        const summaryQuery = `
          SELECT
            COUNT(*) as total_requests,
            SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as total_blocked,
            SUM(CASE WHEN verdict = 'challenged' THEN 1 ELSE 0 END) as total_challenged,
            SUM(CASE WHEN verdict = 'allowed' THEN 1 ELSE 0 END) as total_allowed
          FROM requests
        `;

        const summaryResult = await env.DB.prepare(summaryQuery).first<D1Row>();

        // Verdict breakdown
        const verdictQuery = `
          SELECT verdict, COUNT(*) as count
          FROM requests
          GROUP BY verdict
        `;
        const verdictResults = await env.DB.prepare(verdictQuery).all<D1Row>();

        // Category breakdown from attack_categories.
        // attack_categories is stored as a JSON array of strings, like ["sqli"].
        // json_valid prevents malformed JSON from crashing the entire summary endpoint.
        const categoryQuery = `
          SELECT
            category_json.value as category,
            COUNT(*) as count
          FROM requests,
          json_each(
            CASE
              WHEN attack_categories IS NOT NULL
                AND json_valid(attack_categories)
              THEN attack_categories
              ELSE '[]'
            END
          ) AS category_json
          WHERE category_json.value IS NOT NULL
          GROUP BY category_json.value
          ORDER BY count DESC
        `;
        const categoryResults = await env.DB.prepare(categoryQuery).all<D1Row>();

        // Top 10 countries
        const countryQuery = `
          SELECT country, COUNT(*) as count
          FROM requests
          WHERE country IS NOT NULL AND country != ''
          GROUP BY country
          ORDER BY count DESC
          LIMIT 10
        `;
        const countryResults = await env.DB.prepare(countryQuery).all<D1Row>();

        // Top 10 ASN orgs
        const asnQuery = `
          SELECT asn_org, COUNT(*) as count
          FROM requests
          WHERE asn_org IS NOT NULL AND asn_org != ''
          GROUP BY asn_org
          ORDER BY count DESC
          LIMIT 10
        `;
        const asnResults = await env.DB.prepare(asnQuery).all<D1Row>();

        const summary = {
          total_requests: Number(summaryResult?.total_requests ?? 0),
          total_blocked: Number(summaryResult?.total_blocked ?? 0),
          total_challenged: Number(summaryResult?.total_challenged ?? 0),
          total_allowed: Number(summaryResult?.total_allowed ?? 0),

          verdict_breakdown:
            verdictResults.results?.reduce<Record<string, number>>((acc, row) => {
              const verdict = String(row.verdict ?? '');
              if (verdict) {
                acc[verdict] = Number(row.count ?? 0);
              }
              return acc;
            }, {}) ?? {},

          category_breakdown:
            categoryResults.results?.reduce<Record<string, number>>((acc, row) => {
              const category = String(row.category ?? '');
              if (category) {
                acc[category] = Number(row.count ?? 0);
              }
              return acc;
            }, {}) ?? {},

          top_countries:
            countryResults.results?.map((row) => ({
              country: String(row.country ?? ''),
              count: Number(row.count ?? 0),
            })) ?? [],

          top_asns:
            asnResults.results?.map((row) => ({
              asn_org: String(row.asn_org ?? ''),
              count: Number(row.count ?? 0),
            })) ?? [],
        };

        return jsonResponse(summary);
      } catch (error) {
        console.error('Summary API error:', error);
        return jsonResponse({ error: 'Database query failed' }, 500);
      }
    }

    if (url.pathname === '/api/recent') {
      try {
        // Get last 50 requests with all visible fields
        const recentQuery = `
          SELECT
            timestamp,
            method,
            path,
            query,
            body_preview,
            user_agent,
            client_ip,
            asn,
            asn_org,
            country,
            city,
            verdict,
            matched_rules,
            attack_categories
          FROM requests
          ORDER BY timestamp DESC
          LIMIT 50
        `;
        const recentResults = await env.DB.prepare(recentQuery).all<D1Row>();

        const recent = {
          requests:
            recentResults.results?.map((row) => ({
              timestamp: Number(row.timestamp ?? 0),
              method: String(row.method ?? ''),
              path: String(row.path ?? ''),
              query: row.query === null || row.query === undefined ? null : String(row.query),
              body_preview:
                row.body_preview === null || row.body_preview === undefined
                  ? null
                  : String(row.body_preview),
              user_agent: String(row.user_agent ?? ''),
              client_ip: String(row.client_ip ?? ''),
              asn: row.asn === null || row.asn === undefined ? null : Number(row.asn),
              asn_org: String(row.asn_org ?? ''),
              country: String(row.country ?? ''),
              city: String(row.city ?? ''),
              verdict: String(row.verdict ?? ''),
              matched_rules: parseJsonArray(row.matched_rules),
              attack_categories: parseJsonArray(row.attack_categories),
            })) ?? [],
        };

        return jsonResponse(recent);
      } catch (error) {
        console.error('Recent API error:', error);
        return jsonResponse({ error: 'Database query failed' }, 500);
      }
    }

    // All other requests: try to serve static assets.
    // If no static asset matches, return 404.
    return new Response('Not Found', { status: 404 });
  },
};