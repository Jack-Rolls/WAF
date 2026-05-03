# Cloudflare Workers WAF

A demo Web Application Firewall built on Cloudflare Workers. It protects a deliberately vulnerable app called **VulnShop**, detects common web attack patterns, logs every request decision to Cloudflare D1, and visualizes the activity in a real-time dashboard.

This project is built as a cybersecurity portfolio project to demonstrate request inspection, OWASP-style attack detection, edge security architecture, D1 logging, and dashboard-based security monitoring.

## Live Demo

- **VulnShop:** https://vulnshop.jackrolls1185.workers.dev
- **WAF Dashboard:** https://waf-dashboard.jackrolls1185.workers.dev

## What It Does

The project has two Cloudflare Workers:

1. **VulnShop Worker**
   - Serves a deliberately vulnerable demo app.
   - Runs WAF logic before handling requests.
   - Detects malicious request patterns.
   - Blocks, challenges, or allows traffic.
   - Logs every request to D1.

2. **WAF Dashboard Worker**
   - Reads WAF logs from D1.
   - Shows request totals, blocked attacks, attack categories, top countries, top ASNs, and recent activity.
   - Includes an Attack Simulator that sends curated attack payloads to VulnShop so the dashboard updates live.

## Attack Types Detected

The WAF detects simplified examples of common web attacks:

- **SQL Injection**
  - Example: `' OR 1=1--`
  - Target endpoint: `/api/search?q=...`

- **Cross-Site Scripting (XSS)**
  - Example: `<script>alert('xss')</script>`
  - Target endpoint: `/api/comment?c=...`

- **Path Traversal**
  - Example: `../../etc/passwd`
  - Target endpoint: `/api/file?name=...`

- **Command Injection**
  - Example: `127.0.0.1; cat /etc/passwd`
  - Target endpoint: `/api/ping?host=...`

## Architecture

```text
User / Attacker
      |
      v
VulnShop Worker
      |
      |-- WAF inspection
      |-- Rule matching
      |-- Allow / Block / Challenge decision
      |-- Async logging to D1
      v
Cloudflare D1 Database
      |
      v
WAF Dashboard Worker
      |
      |-- /api/summary
      |-- /api/recent
      |-- Dashboard UI + charts
```

## Tech Stack

- Cloudflare Workers
- Cloudflare D1
- Workers Static Assets
- TypeScript
- Vanilla HTML/CSS/JavaScript
- Chart.js
- Wrangler CLI

## Local Development

Start VulnShop in one terminal:

```bash
wrangler dev --env vulnshop --port 8787
```

Start the dashboard in a second terminal:

```bash
wrangler dev --env waf-dashboard --port 8788
```

Then open:

```text
http://localhost:8787
http://localhost:8788
```

## Local Test URLs

Allowed request:

```text
http://localhost:8787/api/search?q=shoes
```

SQL injection test:

```text
http://localhost:8787/api/search?q=%27%20OR%201%3D1--
```

XSS test:

```text
http://localhost:8787/api/comment?c=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

Path traversal test:

```text
http://localhost:8787/api/file?name=../../etc/passwd
```

Dashboard APIs:

```text
http://localhost:8788/api/summary
http://localhost:8788/api/recent
```

## Deployment

Deploy VulnShop:

```bash
wrangler deploy --env vulnshop
```

Deploy the dashboard:

```bash
wrangler deploy --env waf-dashboard
```

## Demo Flow

1. Open the dashboard.
2. Open VulnShop in another tab.
3. Send a normal request, such as searching for `shoes`.
4. Send attack payloads like SQLi, XSS, or path traversal.
5. Return to the dashboard and watch the request counts, charts, and recent activity update.
6. Click **Run Full Demo** in the dashboard to automatically generate a mix of benign and malicious traffic.

## What I Learned

This project helped me understand:

- How a WAF inspects HTTP requests before they reach an application.
- How common web attacks like SQL injection, XSS, path traversal, and command injection work.
- How to use Cloudflare Workers as an edge security layer.
- How to use D1 to log and query security events.
- How to build a simple security dashboard that turns raw logs into useful visibility.
- Why async logging matters so request handling is not slowed down.
- Why demo security tools need both backend detection and frontend observability.

## Limitations

This is a learning project, not a production-grade WAF.

The detection rules are simplified regex-based patterns. A real WAF would use more advanced techniques such as managed rulesets, anomaly scoring, request normalization, ML-based detection, paranoia levels, and broader protocol-level protections.

The goal of this project is to demonstrate architecture, detection logic, logging, and security visibility rather than compete with a production security product.