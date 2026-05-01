# Learning Log

## Phase 1: Project scaffolding and configuration

**What:** Initialized TypeScript + Wrangler configuration for two Cloudflare Workers with shared D1 database binding, and set up initial project structure.

**Why:** Phase 1 establishes the baseline that both Workers (vulnshop and waf-dashboard) will build upon. We configured `wrangler.jsonc` with two separate environments (one per Worker), each bound to the same D1 database (`waf-db`), so they can share request logs. Set TypeScript strict mode for type safety and used the current date (2026-05-01) as the compatibility date. The `run_worker_first` property will be used later to intercept requests before static assets are served.

**Interview hook:** "I set up the Workers infrastructure with two separate environments in one wrangler.jsonc to avoid managing two separate configs, and configured them to share a D1 binding so the dashboard and WAF both read from the same database."