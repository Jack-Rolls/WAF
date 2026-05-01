# Learning Log

## Phase 1: Project scaffolding and configuration

**What:** Initialized TypeScript + Wrangler configuration for two Cloudflare Workers with shared D1 database binding, and set up initial project structure.

**Why:** Phase 1 establishes the baseline that both Workers (vulnshop and waf-dashboard) will build upon. We configured `wrangler.jsonc` with two separate environments (one per Worker), each bound to the same D1 database (`waf-db`), so they can share request logs. Set TypeScript strict mode for type safety and used the current date (2026-05-01) as the compatibility date. The `run_worker_first` property will be used later to intercept requests before static assets are served.

**Interview hook:** "I set up the Workers infrastructure with two separate environments in one wrangler.jsonc to avoid managing two separate configs, and configured them to share a D1 binding so the dashboard and WAF both read from the same database."

---

## Phase 2: WAF rules engine, inspection logic, and D1 logging

**What:** Built the WAF core: 15 detection rules across 4 OWASP categories (SQLi, XSS, path traversal, command injection), request inspection with URL decoding and regex matching, and async D1 logging infrastructure.

**Why:** The WAF must inspect every request before any processing, so we made the rules simple and auditable (flat array, readable patterns). Inspection decodes URLs before matching because attackers often double-encode; we check path, query, body, User-Agent, and Referer. Severity rollup is deterministic: high → block (403), medium → challenge (429), low → allow, all get logged. D1 logging is async (ctx.waitUntil) so it never delays the user-facing response. Stub API endpoints are safe (return fake JSON, never execute SQL/commands/file reads).

**Interview hook:** "I implemented a flat-array rule engine so every regex is easily auditable, with severity-based verdict logic (high=block, med=challenge, low=allow), and async D1 logging that never slows down the request path."

---

## Phase 3: Dashboard API endpoints and real-time UI

**What:** Built the dashboard Worker with real D1 queries for `/api/summary` (aggregates stats, breakdowns, top lists) and `/api/recent` (last 50 requests), plus a full vanilla HTML/JS dashboard that polls APIs every 3 seconds and visualizes data with Chart.js.

**Why:** The dashboard must show live WAF activity, so APIs query D1 with efficient aggregations (GROUP BY, ORDER BY, LIMIT). UI uses vanilla HTML/CSS/JS with Chart.js from CDN—no frameworks. Polling happens automatically so charts update as vulnshop logs requests. Attack simulator buttons are placeholders for Phase 4.

**Interview hook:** "I built a real-time dashboard that queries D1 for live WAF stats and visualizes them with Chart.js, polling every 3 seconds to show immediate feedback when attacks are blocked."