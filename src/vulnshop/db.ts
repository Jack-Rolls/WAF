/**
 * D1 Database Logging
 * 
 * Async logging to WAF requests table.
 * Uses ctx.waitUntil so database writes never delay the response.
 */

import { WafRule } from './waf';

export interface RequestLogEntry {
  timestamp: number;
  method: string;
  path: string;
  query?: string;
  bodyPreview?: string;
  userAgent?: string;
  clientIp: string;
  asn?: number;
  asnOrg?: string;
  country?: string;
  city?: string;
  verdict: 'allowed' | 'blocked' | 'challenged';
  matchedRules: WafRule[];
  matchedCategories: Set<string>;
}

/**
 * Log a request to D1
 * Runs asynchronously via ctx.waitUntil; never blocks the response
 */
export async function logRequestToD1(
  db: D1Database,
  ctx: ExecutionContext,
  entry: RequestLogEntry
): Promise<void> {
  // Extract geolocation from request.cf
  // This will be populated by Cloudflare's edge
  const ruleIds = entry.matchedRules.map((r) => r.id);
  const categories = Array.from(entry.matchedCategories);

  const query = `
    INSERT INTO requests (
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
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const stmt = db.prepare(query).bind(
    entry.timestamp,
    entry.method,
    entry.path,
    entry.query || null,
    entry.bodyPreview || null,
    entry.userAgent || null,
    entry.clientIp,
    entry.asn || null,
    entry.asnOrg || null,
    entry.country || null,
    entry.city || null,
    entry.verdict,
    JSON.stringify(ruleIds),
    JSON.stringify(categories)
  );

  // Queue the database write to run after response is sent
  ctx.waitUntil(stmt.run());
}
