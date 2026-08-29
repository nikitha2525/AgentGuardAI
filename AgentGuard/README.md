# AgentGuard

**A real-time security firewall placed between an AI agent and its tools.**

Team **NetGen Builders** — Nikitha M (Lead), Anu Dharshini B, Malathi A

AgentGuard intercepts every proposed AI-agent action, checks it for prompt
injection and sensitive-data exposure, verifies tool permissions, calculates
a real-time risk score, and allows or blocks the action before it reaches
the underlying tool — with an explainable reason every time.

This repository is an interactive, deployable **prototype** of that idea:
a Next.js app where you can submit a simulated agent request and watch it
move through the AgentGuard pipeline in real time.

**Live demo pipeline:** `Intercept → Analyze → Verify → Risk Score → Allow / Block → Alert & Log`

---

## What's actually implemented

Unlike a static mockup, the detection logic in this prototype **really runs**:

| Capability | Where | How |
|---|---|---|
| Prompt injection detection | `lib/detectors.ts` | Pattern rules for instruction overrides, system-prompt exfiltration, role/persona hijacking, guardrail bypass attempts, delimiter injection, urgency manipulation |
| Sensitive data detection | `lib/detectors.ts` | Regex rules for emails, phone numbers, card numbers, SSNs, API keys/secrets, inline passwords |
| Tool permission control | `lib/detectors.ts` | A permission matrix flags high-sensitivity tool + action pairs (e.g. `payment_system` + `transfer`) |
| Real-time risk scoring | `lib/detectors.ts` | Weighted sum of every triggered finding plus a tool/action baseline, capped 0–100 |
| Action decision | `lib/detectors.ts` | Score thresholds map to `ALLOW` / `REVIEW` / `BLOCK` |
| Explainable alerts | `components/ThreatBreakdown.tsx` | Every finding ships with the rule that fired and why |
| Audit & monitoring log | `components/AuditLog.tsx` | In-memory session log of every analyzed request |

The production system (per the proposal) replaces the rule layer with the
FastAPI + NLP/ML service described in the pitch, without changing this
pipeline's contract — `POST /api/analyze` in → structured decision out.

---

## Repository structure

```
agentguard/
├── app/
│   ├── api/
│   │   └── analyze/
│   │       └── route.ts        # POST endpoint: runs the detection engine
│   ├── globals.css             # Tailwind base + design tokens
│   ├── layout.tsx              # Root layout, metadata
│   └── page.tsx                # Dashboard: form, pipeline, results, audit log
├── components/
│   ├── AboutSection.tsx        # Features / architecture / tech stack
│   ├── AuditLog.tsx            # Session audit table
│   ├── DecisionBadge.tsx       # ALLOW / REVIEW / BLOCK pill
│   ├── Pipeline.tsx            # Animated firewall pipeline stepper
│   ├── RequestForm.tsx         # Agent request input + demo scenarios
│   ├── RiskGauge.tsx           # Circular risk-score readout
│   └── ThreatBreakdown.tsx     # Explainable findings list
├── lib/
│   ├── detectors.ts            # Detection engine + risk scoring + demo scenarios
│   └── types.ts                # Shared types, tool/action metadata
├── public/                     # Static assets
├── .eslintrc.json
├── .gitignore
├── LICENSE
├── next.config.js
├── package.json
├── postcss.config.js
├── tailwind.config.ts
├── tsconfig.json
└── vercel.json
```

---

## Run it locally

Requires Node.js 18.18+ (Node 20/22 recommended).

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Try the preset
scenarios in the request form — one benign, one prompt-injection attempt,
one secrets leak, one unauthorized payment transfer — or write your own.

Production build check:

```bash
npm run build
npm run start
```

---

## Push to GitHub

```bash
cd agentguard
git init
git add .
git commit -m "Initial commit: AgentGuard prototype"
git branch -M main
git remote add origin https://github.com/<your-username>/agentguard.git
git push -u origin main
```

(Replace `<your-username>` with your GitHub username, e.g. `nikitha2525`,
and create the empty `agentguard` repo on GitHub first via "New repository".)

---

## Deploy to Vercel

**Option A — Vercel dashboard (no CLI needed)**

1. Push this repo to GitHub (above).
2. Go to [vercel.com/new](https://vercel.com/new) and import the `agentguard` repo.
3. Vercel auto-detects Next.js (the included `vercel.json` pins the framework
   and build/install commands explicitly). No environment variables are
   required — the detection engine runs entirely server-side in this app.
4. Click **Deploy**. You'll get a live URL like `agentguard-<hash>.vercel.app`.

**Option B — Vercel CLI**

```bash
npm install -g vercel
cd agentguard
vercel        # first deploy, follow the prompts
vercel --prod # promote to production
```

No secrets or third-party API keys are needed for this prototype — everything
runs in-process, so it deploys cleanly with zero configuration.

---

## Notes on the design

The prototype uses a dark, console/control-room palette (deep graphite
background, cold indigo for "analyzing," green/amber/red for allow/review/
block) with a monospace type for scores, logs, and technical readouts —
matching the audit-log, real-time-scoring nature of the product rather than
a generic marketing look. The system font stack is used intentionally
instead of a remote font fetch, so builds never depend on external network
access at build time.

The signature element is the **animated pipeline stepper**: each analyzed
request visibly moves through Intercept → Analyze → Verify → Score → Decide,
which is the core mental model from the proposal's workflow diagram.

---

## From prototype to production

This repo demonstrates the decision pipeline and UI. To move toward the full
proposal:

- Replace the regex/heuristic rules in `lib/detectors.ts` with the NLP/ML
  threat classifiers described in the pitch (FastAPI microservice).
- Persist the audit log to PostgreSQL/SQLite instead of in-memory React state.
- Add authentication and a real tool-permission registry per agent/tenant.
- Expose the attack-chain visualization as its own view for security teams.
