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

        const summaryResult = await env.DB.prepare(summaryQuery).first();

        // Verdict breakdown
        const verdictQuery = `
          SELECT verdict, COUNT(*) as count
          FROM requests
          GROUP BY verdict
        `;
        const verdictResults = await env.DB.prepare(verdictQuery).all();

        // Category breakdown (unique categories from matched_rules)
        const categoryQuery = `
          SELECT
            json_extract(value, '$.category') as category,
            COUNT(*) as count
          FROM requests,
          json_each(
            CASE
              WHEN attack_categories IS NOT NULL AND attack_categories != '[]'
              THEN attack_categories
              ELSE '[]'
            END
          )
          GROUP BY category
          ORDER BY count DESC
        `;
        const categoryResults = await env.DB.prepare(categoryQuery).all();

        // Top 10 countries
        const countryQuery = `
          SELECT country, COUNT(*) as count
          FROM requests
          WHERE country IS NOT NULL
          GROUP BY country
          ORDER BY count DESC
          LIMIT 10
        `;
        const countryResults = await env.DB.prepare(countryQuery).all();

        // Top 10 ASN orgs
        const asnQuery = `
          SELECT asn_org, COUNT(*) as count
          FROM requests
          WHERE asn_org IS NOT NULL
          GROUP BY asn_org
          ORDER BY count DESC
          LIMIT 10
        `;
        const asnResults = await env.DB.prepare(asnQuery).all();

        const summary = {
          total_requests: summaryResult?.total_requests || 0,
          total_blocked: summaryResult?.total_blocked || 0,
          total_challenged: summaryResult?.total_challenged || 0,
          verdict_breakdown: verdictResults.results?.reduce((acc: any, row: any) => {
            acc[row.verdict] = row.count;
            return acc;
          }, {}) || {},
          category_breakdown: categoryResults.results?.reduce((acc: any, row: any) => {
            acc[row.category] = row.count;
            return acc;
          }, {}) || {},
          top_countries: countryResults.results?.map((row: any) => ({
            country: row.country,
            count: row.count,
          })) || [],
          top_asns: asnResults.results?.map((row: any) => ({
            asn_org: row.asn_org,
            count: row.count,
          })) || [],
        };

        return new Response(JSON.stringify(summary), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (error) {
        console.error('Summary API error:', error);
        return new Response(JSON.stringify({ error: 'Database query failed' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
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
        const recentResults = await env.DB.prepare(recentQuery).all();

        const recent = {
          requests: recentResults.results?.map((row: any) => ({
            timestamp: row.timestamp,
            method: row.method,
            path: row.path,
            query: row.query,
            body_preview: row.body_preview,
            user_agent: row.user_agent,
            client_ip: row.client_ip,
            asn: row.asn,
            asn_org: row.asn_org,
            country: row.country,
            city: row.city,
            verdict: row.verdict,
            matched_rules: row.matched_rules ? JSON.parse(row.matched_rules) : [],
            attack_categories: row.attack_categories ? JSON.parse(row.attack_categories) : [],
          })) || [],
        };

        return new Response(JSON.stringify(recent), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (error) {
        console.error('Recent API error:', error);
        return new Response(JSON.stringify({ error: 'Database query failed' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // All other requests: try to serve static assets
    // If no static asset matches, return 404
    return new Response('Not Found', { status: 404 });
  },
};
