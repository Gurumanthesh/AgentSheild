# AgentShield

AgentShield is a Chrome extension for detecting suspicious messages, risky links, and scam-like content while users browse the web. The project includes a local heuristic detector, a FastAPI backend for structured evaluation, a lightweight React dashboard, and a test page for demonstration.

## Product objective

AgentShield helps users identify phishing, impersonation attempts, credential-harvesting flows, urgency tactics, and suspicious URLs without claiming that a page is completely safe. It explains the indicators it found and provides follow-up actions while relying on local checks when the backend is unavailable.

## Features

- Manifest V3 Chrome extension
- Popup with current-site status and risk score
- Local heuristic detection engine
- Backend analysis API with validation
- In-page warning banner for suspicious content
- Demo dashboard for analysis results
- Benign and suspicious detection tests
- Privacy-conscious design with minimal data handling

## Architecture

- Extension: Chrome extension logic with popup, content script, and background worker
- Backend: FastAPI application for structured analysis and validation
- Dashboard: Lightweight React + Vite app for local demonstration

## Project structure

- `manifest.json` — extension manifest
- `detector.js` — browser-side detection rules
- `content.js` — in-page warning insertion
- `background.js` — backend coordination and fallback logic
- `popup.html`, `popup.js`, `popup.css` — popup UI
- `analysis.html`, `analysis.js`, `analysis.css` — detailed analysis page
- `backend/app` — FastAPI backend implementation
- `backend/tests` — API and detector tests
- `frontend` — React dashboard
- `demo/test-page.html` — local demo page with benign and suspicious examples

## Prerequisites

- Node.js 18+
- Python 3.11+
- Chrome or Chromium browser

## Backend setup

```bash
cd /home/gurumanthesh/Documents/GitHub/AgentSheild-br
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

## Frontend dashboard

```bash
cd /home/gurumanthesh/Documents/GitHub/AgentSheild-br/frontend
npm install
npm run dev
```

## Extension installation

1. Open Chrome and go to `chrome://extensions`.
2. Enable Developer mode.
3. Click Load unpacked.
4. Select the project root directory.
5. Pin AgentShield to the toolbar.
6. Open the demo page or a normal site.
7. Click the extension icon and choose Analyze this page.

## API endpoints

- `GET /health`
- `POST /api/analyze`

Example request body:

```json
{
  "url": "https://example.com",
  "text": "Your account will be suspended. Verify immediately.",
  "links": [
    { "text": "Verify account", "url": "https://example.com/verify" }
  ]
}
```

## Test commands

```bash
cd /home/gurumanthesh/Documents/GitHub/AgentSheild-br
source .venv/bin/activate
pytest backend/tests -q
```

```bash
cd /home/gurumanthesh/Documents/GitHub/AgentSheild-br/frontend
npm run build
```

## Privacy and limitations

- The extension analyzes only minimal page text and link metadata.
- It does not collect passwords, cookies, or browsing history.
- A local heuristic result is not a verified threat-intelligence match.
- External AI or threat-intelligence integrations are optional and require backend configuration.
- The project is designed as an MVP demonstration and should be extended with real provider integrations before production usage.

## Future improvements

- Real-time link reputation checks
- Site-specific extraction for social platforms
- Optional AI explanation layer
- Persistent analysis history with user controls
- Broader threat-intelligence and policy tuning
