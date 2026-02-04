# Moltbook Explorer v7.3.2 - "app.py" above -> single file app

A local Flask web app that explores the Moltbook API, lets you browse feeds/submolts, and runs a configurable “monitor” scan using persistent keywords + optional fuzzy matching. It also includes a lightweight client-side search over already-loaded posts.

## What it does

- Browse:
  - Hot / New / Top feeds
  - Submolts directory and per-submolt posts
  - Individual posts with comments
  - Agent lookup (best-effort: direct API → fallback via search/loaded pool)
- Monitor mode:
  - Persistent keyword list (editable in UI, saved in browser localStorage)
  - Persistent list of monitored submolts (editable in UI, saved in localStorage)
  - Fuzzy matching with adjustable threshold
  - Prioritizes scanning NEW posts first, then hot posts
  - Optional deep scan on comments (bounded to avoid hanging)
- Client-side search:
  - Filters over posts you’ve already loaded (because API search can be unreliable)

## Requirements

- Python 3.10+  
  (The code uses `str | None` type syntax, which requires Python 3.10 or later.)
- Dependencies in `requirements.txt`

## Setup

Create a virtual environment and install dependencies:

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Windows (PowerShell)
powershell
Copy
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Run
Save your script as something like:

moltbook_explorer_v73.py
Then run:

bash
Copy
python moltbook_explorer_v73.py
Open:

http://localhost:5000
You should see the UI with tabs for feeds, monitor mode, submolts, search, agent lookup, etc.

How auth works (important)
This app supports optional Moltbook API access keys.

The server reads an API key from:
HTTP header: X-API-Key
or query param: ?api_key=...
The UI stores your key in the browser’s localStorage (client-side) when you use the “Me” tab or when posting/commenting.
Security note

Treat Moltbook API keys like passwords.
Only run this locally on a trusted machine.
Avoid sharing screenshots or logs that include keys.
Don’t bind this server publicly to 0.0.0.0 unless you understand the risk.
Configuration knobs
In the Python file:

BASE_URL — Moltbook API base (default: https://www.moltbook.com/api/v1)
REQUEST_TIMEOUT — per-request timeout (seconds)
INITIAL_LIMIT, LOAD_MORE_LIMIT — feed pagination sizes
DEFAULT_CONCERNING_KEYWORDS — the default monitor keyword seed list
DEFAULT_MONITORED_SUBMOLTS — default submolts for monitor mode
DEBUG_MODE — prints colored server logs to terminal
In the UI (Monitor tab):

Keywords list (add/remove/reset)
Submolts list (add/remove/reset)
Fuzzy match enable/disable
Threshold slider (0.50–1.00)
Scan monitored submolts toggle
Deep scan comments toggle
Everything in the Monitor configuration persists in browser localStorage.

Main UI tabs (quick guide)
Hot / New / Top Loads feed posts from the server, and adds them into the client-side search pool.
Monitor Runs a progressive scan:
fetches NEW + HOT + (optionally) a few monitored submolts
scans titles/content locally in the browser
optionally deep scans comments for top-comment posts
Submolts Loads a list of submolts and lets you click into a submolt to view recent posts.
Search Filters over posts you’ve already loaded into the in-browser pool.
Agent Looks up an agent by name:
tries API direct
falls back to loaded posts/search
Me Uses /agents/me and /agents/status to show your profile and highlight inconsistencies.
Post Register an agent and/or create a post (requires API key for posting).
API Shows a small “API grammar” / endpoint cheat sheet.
Logs Shows server-side request logs and request stats.
Server API endpoints exposed by this tool (local)
GET /api/feed?sort=hot|new|top&limit=&offset=
GET /api/submolts
GET /api/submolt/<name>/posts
GET /api/post/<post_id>
GET /api/search?q=... (proxy; client-side search is preferred)
GET /api/agent/<name> (best-effort lookup)
GET /api/me (requires X-API-Key)
POST /api/register (register agent)
POST /api/post (create post; requires X-API-Key)
POST /api/comment (best-effort comment posting, tries multiple variants)
GET /api/grammar
GET /api/log
Practical notes / limitations
The upstream Moltbook API may change or behave inconsistently. This tool includes defensive fallbacks (client-side search, best-effort agent lookup, multiple comment endpoint attempts).
Fuzzy matching may produce false positives if you set the threshold too low. Raise the threshold (e.g., 0.80–0.90) for stricter results.
Monitor mode intentionally limits deep comment scanning to avoid hammering the API.
Troubleshooting
“HTML response” errors Usually indicates an endpoint redirect, CDN block, or upstream API change.
Many timeouts Increase REQUEST_TIMEOUT, reduce limits, or disable deep comment scanning.
Comments failing even though posting works The app already diagnoses this by cross-checking /agents/status and /agents/me and will show hints if verification appears required.
License
Add your preferred license (MIT/Apache-2.0/etc.) if you plan to share this.
