# Dashboard Redesign: Threat Intel Console

## What you are doing

You are redesigning the WAF dashboard frontend in this repo. You will replace the existing dashboard HTML/CSS/JS with a dark-themed, security-operations-style "Threat Intel Console" that looks like a real SOC tool, not a tutorial dashboard.

This is a frontend-only change. Do NOT modify the Worker code, the Worker API responses, the D1 schema, the WAF logic, or the VulnShop project. The only file that needs significant changes is:

- `src/waf-dashboard/public/index.html`

You may also touch:

- `src/waf-dashboard/public/` for any new asset files (logos, fonts) ONLY if absolutely necessary. Prefer inlining everything in `index.html`.

You may NOT touch:

- `src/waf-dashboard/index.ts` (the dashboard Worker)
- `src/vulnshop/` (anything)
- `wrangler.jsonc`
- `shared/schema.sql`
- `package.json` or `tsconfig.json`

## Operating principles

You are working with Jack, a CS junior who needs to be able to defend every line of this dashboard in technical interviews. Optimize for understanding over speed.

1. **Before writing code, explain.** When starting a major section (e.g. "the Red Team panel"), write a 2-4 sentence explanation in chat covering what you're about to build, why this approach, and how it fits the rest. Then write the code.

2. **Teach the primitives.** When introducing a non-obvious technique (CSS Grid for the layout, sparkline rendering with inline SVG, etc.), pause and explain the primitive in 2-3 sentences before using it.

3. **No invented complexity.** Use vanilla HTML, vanilla CSS, vanilla JavaScript. Use Chart.js from CDN where it earns its keep. Do NOT add a build step, do NOT add React, Tailwind, Vue, or any framework. Do NOT add npm packages.

4. **Ask before running shell commands.** You may edit files freely. Ask before running anything in the terminal.

5. **The Worker API is the source of truth.** Read `src/waf-dashboard/index.ts` first to understand the exact JSON shapes returned by `/api/summary` and `/api/recent`. Do not invent fields. Do not call endpoints that don't exist. The current API contract is documented in the "API contract" section below — verify it matches the actual code before you start.

## API contract (verify before you build)

The dashboard uses two endpoints. Confirm these shapes by reading `src/waf-dashboard/index.ts` before you start coding the frontend:

### `GET /api/summary` returns:

```json
{
  "total_requests": 104,
  "total_blocked": 37,
  "total_challenged": 8,
  "total_allowed": 59,
  "verdict_breakdown": { "allowed": 59, "blocked": 37, "challenged": 8 },
  "category_breakdown": { "xss": 20, "sqli": 13, "path_traversal": 10, "command_injection": 4 },
  "top_countries": [{ "country": "US", "count": 104 }],
  "top_asns": [{ "asn_org": "AT&T Enterprises, LLC", "count": 60 }]
}
```

### `GET /api/recent` returns:

```json
{
  "requests": [
    {
      "timestamp": 1699999999999,
      "method": "GET",
      "path": "/api/search",
      "query": "q=' OR 1=1--",
      "body_preview": null,
      "user_agent": "...",
      "client_ip": "2600:1700:280::",
      "asn": 7018,
      "asn_org": "AT&T Enterprises, LLC",
      "country": "US",
      "city": "Austin",
      "verdict": "blocked",
      "matched_rules": ["sql_001"],
      "attack_categories": ["sqli"]
    }
  ]
}
```

If the actual API returns different fields than described above, follow the actual API and tell Jack what diverged.

## Design spec — Threat Intel Console (Option C)

This is what you are building. Read this spec twice before writing any code.

### Visual identity

- **Theme:** dark mode only. Background `#0d0f12`, panels `#161a20`, panel borders `#252a31`.
- **Accent color:** Cloudflare orange `#F6821F`. Use sparingly — for the live indicator dot, the headline metric value (Threat Score), and one or two key emphasis moments. Not on every button.
- **Verdict colors:**
  - Blocked: `#ef4444` (red)
  - Challenged: `#f59e0b` (amber)
  - Allowed: `#22c55e` (green)
- **Text colors:** primary `#e6e8eb`, secondary `#8b95a3`, dim `#5a6371`.
- **Fonts:** load Inter for sans-serif and JetBrains Mono for monospace from Google Fonts via `<link>` tag. Use Inter for everything by default. Use JetBrains Mono for: paths, IPs, rule IDs, ASN numbers, payloads, and any code-like text.
- **Spacing:** generous. Use a 4px base unit. Panels have 20px internal padding. Gap between panels is 16px.
- **Borders:** 1px solid panel borders, 6px border radius on panels.
- **No gradients.** No drop shadows. No emoji icons in headers (the existing 🛡️ emoji is fine).

### Top bar

A thin horizontal bar across the top of the screen.

- Left: the title `▣ EDGE-WAF` in mono font, then a subtitle line below it: `vulnshop.workers.dev · 16 rules active · last sync: 2s ago`. The "16 rules active" is hardcoded for now. The "last sync" updates every refresh cycle.
- Right: a small status pill showing `ARMED ●` with a pulsing green dot, then `2.3 r/s` (live throughput — calculate this client-side as: requests received in the last 60 seconds / 60). If unavailable, show `— r/s`.
- Total height: ~64px.

### Headline metrics row

A 4-column grid below the top bar. Each column is a "stat card." 96px tall. Cards have:

- Top row: small dim label (`THREAT SCORE`, `BLOCKED`, `CHALLENGED`, `TOTAL`)
- Big number in the center, 36px font size, weight 600
- A bottom row showing either a 60-second sparkline (see below) or a delta line like `+12 / 1h`

The four cards are:

1. **THREAT SCORE** — calculated as `(blocked + challenged) / total * 100`, displayed as a percent. Below it: a sparkline of threat-score-per-minute for the last 60 seconds. Color the value in accent orange. Below sparkline: text `LOW` / `MEDIUM` / `HIGH` based on thresholds (under 10% = LOW green, 10-30% = MEDIUM amber, 30%+ = HIGH red).
2. **BLOCKED** — `total_blocked`. Sparkline of blocked-per-minute. Below sparkline: `+N / 1h` showing blocks in the last hour.
3. **CHALLENGED** — `total_challenged`. Same pattern.
4. **TOTAL** — `total_requests`. Same pattern.

#### How to render sparklines

Use inline SVG. No library. 60px wide, 20px tall. The data is the last 60 entries of "requests-per-second" or "blocks-per-second" derived from the `/api/recent` results' timestamps. Bin the timestamps into 60 one-second buckets and count. Render as a path. Color the line in accent orange for THREAT SCORE, red for BLOCKED, amber for CHALLENGED, neutral gray for TOTAL.

Explain to Jack how the binning works before you write the code.

### Red Team panel

A wide panel below the headline metrics. This is the attack simulator — it must be prominent and inviting.

- Heading: `RED TEAM` (mono, accent orange).
- Subtitle line: `Inject curated payloads to validate detection coverage`.
- A primary button `▶ FULL DEMO` (large, accent orange filled, ~40px tall).
- Five secondary buttons inline, smaller, dark-filled with light borders: `SQLi`, `XSS`, `Path Trav`, `Cmd Inj`, `Benign`.
- Below the buttons: a status line that updates after each run. After full demo: `Last run: 6:47 PM · all 5 categories fired · 18 detections`. After single category: `Last run: 6:47 PM · SQLi · 5 payloads sent`.

The attack payloads themselves are already implemented in the existing dashboard. **Carry forward the existing payload arrays exactly.** Do not invent new payloads. Find them in the current `index.html` and reuse them verbatim. They use `mode: 'no-cors'` and a 200ms delay between requests — preserve both.

### Detection categories panel

Below the Red Team panel, on the LEFT half of a 2-column grid.

- Heading: `DETECTIONS`.
- One row per category from `category_breakdown`. Each row has:
  - Category name, in mono, lowercase: `xss`, `sqli`, `path_traversal`, `command_injection`. (Format `path_traversal` as `path traversal` in display, same for command injection.)
  - A horizontal bar showing the proportion (longest category = full width, others scaled).
  - The count.
  - The percent of total detections.
- Sort descending by count.
- Bar color: red.

### Rule performance panel

On the RIGHT half of the same 2-column grid as Detection categories.

- Heading: `RULE PERFORMANCE`.
- Subtitle: `Most-fired rules in the last 100 detections`.
- Aggregate `matched_rules` arrays from `/api/recent` results. Count occurrences of each rule ID across all entries.
- Display top 8 rule IDs with counts and a small horizontal bar (scaled to the top entry).
- Rule IDs in mono. After the rule ID, show a short description if you can derive it from context, otherwise omit. (You don't have a rule catalog from the API — this panel is purely a count-by-id-string visualization. Leave space for a description column but show `—` if unknown.)
- If there are fewer than 8 distinct rule IDs in the data, show only what exists.
- This panel is empty-state friendly: show "No detections yet — fire the simulator above" if no rules have fired.

### Event Stream panel (replaces "Recent Activity")

A wide panel at the bottom of the page, taking the full grid width.

- Heading: `EVENT STREAM`.
- Subtitle: `Last 50 requests · auto-refreshing every 3s`.
- Each event is rendered as a 2-3 line block, NOT a table row. Tables are too dense for this kind of feed.
- Format:

```
9:17:32  GET  /api/search?q=' OR 1=1--
         🔴 BLOCKED · sql_001 (high) · 2600:1700:280::/48 · AT&T Enterprises, LLC
         payload: ' OR 1=1--
```

- Line 1: time (mono, dim), method (mono), full path with query (mono).
- Line 2: verdict pill (colored dot + uppercase verdict), matched rule IDs joined with commas (mono), client IP (mono, truncated to first 24 chars + `…` if longer), ASN org (truncated to 32 chars + `…` if longer).
- Line 3 (only for blocked/challenged events): the offending payload extracted from the query string or body preview. Render in mono, with the suspicious tokens highlighted in red. If you can't reliably extract the payload, omit line 3.
- Allowed requests get a single-line compact form: `9:17:30  GET  /api/comment  🟢 allowed  US · Miami University`.
- Use 12px-14px font sizes here so density stays readable.
- The most recent event has a subtle accent-orange left border for 2 seconds after it appears, then fades to the normal panel border. This makes new events visually obvious without being annoying.
- Wrap the feed in a div with a max height of 600px and `overflow-y: auto`.

### Layout grid

Use CSS Grid for the page layout. The grid is:

```
+----------------------------------------------------+
| TOP BAR                                            |
+----------------------------------------------------+
| HEADLINE METRICS (4 cards in a row)                |
+----------------------------------------------------+
| RED TEAM                                           |
+----------------------------------------------------+
| DETECTIONS          | RULE PERFORMANCE             |
+---------------------+------------------------------+
| EVENT STREAM (full width)                          |
+----------------------------------------------------+
```

Max content width: 1280px, centered. Page background fills the viewport.

On viewports under 900px wide:
- Headline metrics collapse from 4 columns to 2x2.
- Detections and Rule Performance stack vertically.
- Everything else stays single-column.

You are not required to support mobile fully — desktop is the primary target — but the layout should not visually break on a laptop screen at 1280px or a wide screen at 1920px.

### Polling

- `/api/summary` and `/api/recent` are polled every 3000ms (3 seconds). Use a single `setInterval` and `await Promise.all([fetchSummary(), fetchRecent()])`.
- On the first load, show a "loading…" placeholder in each panel. Do not show the empty-state until after the first fetch completes.
- If a fetch fails, log to console and keep polling. Don't crash the page.

### Live indicator

The pulsing green ARMED dot uses CSS animation. Define a `@keyframes pulse` that animates `opacity` from 0.4 to 1 and back over 1.5s, infinite.

## Implementation order

Build it in this order, committing in chat between phases (Jack will approve the actual git commits manually):

1. **Phase 1 — Skeleton.** Replace the entire `<body>` of `index.html` with the new dark theme, the top bar, an empty placeholder for each panel, the Google Fonts link, and the CSS variables. No data binding yet. Verify it renders cleanly on `wrangler dev` before moving on.
2. **Phase 2 — Headline metrics + sparklines.** Wire up the four headline cards to `/api/summary`. Implement sparklines using `/api/recent` data. Threat score logic and color coding.
3. **Phase 3 — Red Team panel.** Port the existing simulator buttons and payload arrays into the new visual style. Confirm clicks still fire requests at vulnshop and that the dashboard still updates.
4. **Phase 4 — Detection categories + Rule Performance.** Both panels in the 2-column grid.
5. **Phase 5 — Event Stream.** The big one. Multi-line event rendering, payload highlighting, recent-event animation.
6. **Phase 6 — Polish pass.** Empty states, loading states, responsive breakpoint, polish typography, verify everything works end-to-end with the Run Full Demo button.

After each phase: Jack will manually run `wrangler dev`, click around, and tell you if anything is broken.

## Things that are easy to get wrong

- **Don't break the existing simulator.** The current dashboard has working `fetch()` calls to vulnshop with the right payloads and the right CORS mode. Read those calls first. Reuse the array of payloads exactly. The only thing changing is the buttons that trigger them.
- **Don't fetch from URLs that don't exist.** The Worker only exposes `/api/summary` and `/api/recent`. Do not assume there's a `/api/rules` or `/api/insights` endpoint — there isn't.
- **Don't store dashboard state in localStorage.** It's not needed and adds complexity. In-memory state via `let` variables is fine.
- **Sparklines need real time-binned data.** Don't fake it with random numbers. Use the timestamps from `/api/recent` (last 50 requests) and bin them into 60 one-second buckets. If there's not enough data, show the sparkline as a flat line.
- **The accent color is precious.** Use it for: ARMED dot, primary FULL DEMO button, threat score number, and one or two other small touches. If everything is orange, nothing is orange.
- **Don't lose the `mode: 'no-cors'` on simulator fetches.** Cross-origin requests from the dashboard origin to the vulnshop origin will silently fail without it.

## Out of scope (do NOT do these)

- Don't add a geographic map (Leaflet, etc.) — single-country data is uninteresting and not worth the bytes.
- Don't add user authentication.
- Don't change the Worker code or D1 schema.
- Don't add new API endpoints.
- Don't add a build pipeline (Vite, Webpack, esbuild, etc.).
- Don't add npm packages. CDN imports are acceptable for fonts and Chart.js (if needed).
- Don't add icons libraries (Lucide, Font Awesome, etc.). The existing emoji are fine. SVG inline for anything else.
- Don't add dark mode toggling — dark mode is the only mode.

## Definition of done

The redesign is done when:

1. `wrangler dev --env waf-dashboard --port 8788` opens the new dashboard with no console errors.
2. Clicking "Run Full Demo" causes the headline metrics, detection categories, rule performance, and event stream to all visibly update within ~10 seconds.
3. The headline THREAT SCORE shows a non-zero percent and a sparkline.
4. Manually navigating to the vulnshop URL in another tab and firing a real attack (`?q=' OR 1=1--`) results in a new event appearing at the top of the event stream, with red verdict styling and the payload visible.
5. No browser console errors during normal operation. (Failed fetches are okay if they're from the simulator's `no-cors` mode — those always return opaque responses, that's expected.)
6. The page renders correctly at 1280px and 1920px viewport widths.
7. Jack can walk through the entire dashboard and explain what each panel is for, where the data comes from, and what would happen if the underlying API failed.

## First steps for you (Codex)

1. Open and read `src/waf-dashboard/index.ts` end-to-end. Confirm the API shapes match what's documented above.
2. Open and read `src/waf-dashboard/public/index.html` end-to-end. Note the simulator payloads, the polling interval, and the chart library currently in use.
3. Tell Jack in chat: a) what API fields you'll use, b) the simulator payloads you'll carry forward, c) any divergence you spotted between this spec and the actual code, d) your proposed phase 1 plan.
4. Wait for Jack to approve before writing any code.

When Jack says "begin phase 1," then start. Until then, only read.
