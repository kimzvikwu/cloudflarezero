# cf_ai_zeroday_triage — Zero Day Triage Desk

An AI-powered vulnerability triage app built entirely on Cloudflare. Paste in a newly disclosed vulnerability advisory, and the app:

1. Extracts the structured facts (CVE, product, affected and fixed versions, severity, exploitation status).
2. Matches them against the asset inventory you've stored.
3. Assesses exposure and recommends whether to **mitigate now, patch, or both**, with a staged patch plan, production verification steps and a compromise check.
4. **Waits for a human to approve or reject the plan.** The workflow sleeps durably until someone decides, and the model never makes the release or risk decision.
5. Records the outcome in memory, so the chat assistant can reference it later.

Throughout, the app keeps three outcomes separate that are often blurred: an exploit **blocked** (mitigation), a vulnerability **patched**, and a compromise **removed**.

## How it maps to the assignment

| Required component | Implementation |
|---|---|
| **LLM** | Llama 3.3 70B on Workers AI (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`), used for chat, advisory extraction and exposure assessment |
| **Workflow / coordination** | Cloudflare **Workflows** (`TriageWorkflow`): retried, durable steps for extract → match → assess → `waitForEvent` human approval (24-hour timeout) → record |
| **User input (chat or voice)** | Chat UI served by Workers Static Assets, with voice dictation through the browser's Web Speech API where supported |
| **Memory / state** | One SQLite-backed **Durable Object** per browser session (`SessionAgent`) that stores chat history, the asset inventory and triage records. Chat prompts include the inventory and recent triage outcomes |

```
Browser (chat, voice, inventory, triage UI)
   │  x-session-id
   ▼
Worker (router, input validation) ──► Workers Static Assets (public/)
   │                         │
   ▼                         ▼
SessionAgent DO          TriageWorkflow ──► Workers AI (Llama 3.3)
(SQLite: messages,         │  steps read/write the same DO over RPC
 assets, triages)  ◄───────┘  waitForEvent("approval") ◄── Approve/Reject button
```

## Run it

Prerequisites: Node.js 18+ and a Cloudflare account (the free plan works; Workers AI has a free daily allocation).

```bash
npm install
npx wrangler login        # opens a browser to authorize Wrangler
npm run deploy            # = wrangler deploy
```

Wrangler prints your URL (`https://cf-ai-zeroday-triage.<your-subdomain>.workers.dev`). Open it and then:

1. Add a few assets to the inventory, such as `OpenSSH 9.3p1` (internet-facing) and `nginx 1.25.3`.
2. Click **Load sample** (CVE-2024-6387, "regreSSHion") and then **Run triage workflow**.
3. Watch the progress bar. When the status reads **awaiting approval**, expand the plan, add a note and click **Approve** or **Reject**.
4. Ask the chat something like "Are we exposed to regreSSHion, and what's left after we mitigate?" It answers using the stored inventory and the triage outcome.

### Local development

```bash
npm run dev               # wrangler dev, served at http://localhost:8787
```

Durable Objects, Workflows and static assets run locally. The Workers AI binding always calls Cloudflare, so `wrangler dev` needs you to be logged in (`npx wrangler login`), and model calls count against your account's Workers AI usage.

### Typecheck

```bash
npm run typecheck
```

## API

All `/api/*` routes require an `x-session-id` header containing a UUID (the UI generates one and keeps it in `localStorage`).

| Method & path | Purpose |
|---|---|
| `GET /api/state` | Chat history, inventory and the 20 most recent triages |
| `POST /api/chat` `{ message }` | Chat with the assistant (inventory- and triage-aware) |
| `DELETE /api/chat` | Clear chat history |
| `POST /api/assets` `{ name, version, internetFacing, notes }` | Add an asset |
| `DELETE /api/assets/:id` | Remove an asset |
| `POST /api/triage` `{ advisory }` | Start a triage workflow (returns `triageId`) |
| `POST /api/triage/:id/decision` `{ decision: "approve" \| "reject", note }` | Send the human decision to the waiting workflow |

## Design choices

- **Humans keep authority.** The workflow can't move past assessment without an explicit decision, and a decision is accepted only from the session that owns the triage and only while it's awaiting approval.
- **Advisory text is untrusted.** It's wrapped in `<advisory>` tags, and the prompts tell the model to ignore instructions it contains. Model output is parsed as JSON and rendered with `textContent`, never as HTML.
- **Deterministic before generative.** Inventory matching runs as plain code before the model sees it, and the model receives both the name-matched candidates and the full inventory. That way, a fuzzy match can be caught without the model inventing assets.
- **Durable and retried.** Each model call runs in its own Workflow step with exponential-backoff retries and a timeout, and any step failure marks the triage `failed` with the error.
- **Input limits.** Chat messages are capped at 4,000 characters, advisories at 20,000 and asset fields at 120/60/300 characters.

## Project layout

```
src/index.ts      Worker router, SessionAgent Durable Object, TriageWorkflow
public/index.html Chat, voice, inventory and triage UI
wrangler.jsonc    Bindings: AI, Durable Object (SQLite), Workflow, static assets
PROMPTS.md        AI prompts used to build this project, and the runtime prompts
```
