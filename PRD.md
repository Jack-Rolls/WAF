# PRD: Cloudflare Workers WAF with OWASP Detection

## What we're building

A custom Web Application Firewall built on Cloudflare Workers that sits in front of a deliberately vulnerable demo app, inspects every incoming request for OWASP Top 10 attack patterns, decides whether to block / challenge / allow, logs every decision to D1, and visualizes the activity in a real-time dashboard. The dashboard also contains an "Attack Simulator" panel that fires curated attack payloads at the vulnerable app from the user's browser, so the system demos end-to-end in one screen.

## Why it exists

Resume project for a Cloudflare Security Engineering internship. Must demonstrate: understanding of OWASP Top 10, ability to think like an attacker AND defender, fluency with Cloudflare's developer platform (Workers, static assets, D1, the `cf` request object, `run_worker_first`).

## Architecture

Two Workers, one shared D1 database.

- **Worker A: `vulnshop`** — hosts the vulnerable demo app (static HTML + 4 fake API endpoints) and runs the WAF logic via `run_worker_first: true`. Every request hits the WAF before any asset is served.
- **Worker B: `waf-dashboard`** — hosts the dashboard UI (static HTML + Chart.js) and an `/api/*` route group for stats. Reads from the same D1.

Both Workers bind to the same D1 database (`waf-db`).

## Worker A: `vulnshop`

### Vulnerable demo frontend

A single-page HTML app, "VulnShop," with four sections, each with a labeled vulnerability hint:

1. **Product search** — calls `/api/search?q=...` (SQLi target).
2. **Comments** — calls `/api/comment?c=...` (XSS target).
3. **File viewer** — calls `/api/file?name=...` (path traversal target).
4. **Ping tool** — calls `/api/ping?host=...` (command injection target).

The "backend" endpoints are stubs that return fake responses. They do not actually execute SQL, render unsanitized HTML, read files, or run shell commands. The point is the WAF blocks the attack before it would reach a real backend.

### WAF logic

A single inspector function takes a `Request` and returns `{ matchedRules, severity, verdict }`.

- Detection categories: SQLi, XSS, path traversal, command injection.
- Rule format: `{ id, category, severity (low/med/high), description, pattern (regex) }`.
- Roughly 12-16 rules total, distributed across the four categories.
- Inspect: decoded URL path, decoded query string, body (for POST/PUT), `User-Agent`, `Referer`. URL-decode before regex matching.
- Severity rollup: any high-severity match = block, otherwise any medium = challenge, otherwise allow. Lows alone do not flip the verdict but should still be logged.
- Block response: 403 with JSON body listing matched rule IDs and descriptions.
- Challenge response: 429 with a stub HTML page (not a real CAPTCHA — note in code that Turnstile would go here in production).

### Logging

Every request, regardless of verdict, is written to D1's `requests` table. Use `ctx.waitUntil` so logging never delays the user-facing response.

Captured fields include: timestamp, method, path, query, body preview (truncated), user agent, client IP, ASN, ASN org, country, city, verdict, matched rule IDs (JSON array), attack categories (JSON array of unique categories from matched rules).

## Worker B: `waf-dashboard`

### API routes (Worker-handled)

- `GET /api/summary` — totals, breakdown by verdict, breakdown by attack category, top 10 attacker countries, top 10 attacker ASN orgs.
- `GET /api/recent` — latest 50 requests with all visible fields.

`run_worker_first` should be set to `["/api/*"]` so static assets are served directly for all other paths.

### Dashboard UI

Vanilla HTML + Chart.js (CDN). Polls `/api/summary` and `/api/recent` every 3 seconds. Sections:

1. **Top stats card** — total requests, total blocks, total challenges.
2. **Verdict doughnut chart** — allowed / challenged / blocked.
3. **Attack categories bar chart** — counts per OWASP category.
4. **Top countries bar chart** — top 10 attacker countries.
5. **Top ASNs table** — top 10 ASN organizations.
6. **Recent activity table** — most recent 50 requests, color-coded by verdict.
7. **Attack Simulator panel** — see below.

### Attack Simulator panel

Buttons that, when clicked, fire `fetch()` calls directly from the browser to the deployed `vulnshop` URL. Use `mode: 'no-cors'` so cross-origin restrictions don't block the request from landing. The dashboard does not need the response — it reads from D1 via the polling cycle.

Buttons:
- Run SQLi attacks (5 payloads)
- Run XSS attacks (5 payloads)
- Run Path Traversal attacks (4 payloads)
- Run Command Injection attacks (4 payloads)
- Run benign traffic (10 normal-looking requests, e.g. `q=blue running shoes`)
- Run full demo (interleaved mix of all of the above with small delays)

Payloads are hardcoded in the dashboard frontend. Use a 200ms delay between requests in a batch so the live charts have a moment to animate.

## Data model

```sql
CREATE TABLE requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT,
  body_preview TEXT,
  user_agent TEXT,
  client_ip TEXT,
  asn INTEGER,
  asn_org TEXT,
  country TEXT,
  city TEXT,
  verdict TEXT NOT NULL,        -- allowed | blocked | challenged
  matched_rules TEXT,           -- JSON array of rule IDs
  attack_categories TEXT        -- JSON array
);
CREATE INDEX idx_requests_ts ON requests(timestamp DESC);
CREATE INDEX idx_requests_verdict ON requests(verdict);
CREATE INDEX idx_requests_country ON requests(country);
```

## Constraints

- Cloudflare Workers free plan only.
- Workers + Static Assets, NOT Pages.
- `.workers.dev` subdomains.
- TypeScript for Workers, vanilla HTML/JS for frontends.
- No frontend framework, no build tool beyond what Wrangler provides.

## Out of scope

- Real CAPTCHA / Turnstile integration (stub it).
- User authentication on the dashboard (it's public-read; that's fine for a demo).
- Rule paranoia levels or ML-based detection.
- Persistent attacker fingerprinting beyond what `request.cf` provides.

## Demo script (must work end to end)

1. Open `waf-dashboard.<subdomain>.workers.dev` — dashboard loads, may have prior data or be empty.
2. Click "Run full demo" — within 10 seconds the verdict chart, category chart, and recent activity table all populate with mixed allow/challenge/block entries.
3. Open `vulnshop.<subdomain>.workers.dev` in a second tab — manually try one SQLi (`' OR 1=1--`) and one XSS (`<script>alert(1)</script>`); both get blocked with a 403 + matched rules in the response body.
4. Return to the dashboard — those two manual attacks appear in the recent activity table.

If any of these four steps fail, the project is not done.