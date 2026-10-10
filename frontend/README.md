# NIDS Network Defense Console

React + TypeScript + Vite + Tailwind dashboard for the FastAPI capture service.

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

`VITE_API_URL` defaults to `http://127.0.0.1:8000`; set it in `.env` when the API
is hosted elsewhere. Start the backend from the repository root with
`python -m uvicorn backend.main:app --reload`.

The command center has navigable Overview, Sensors, Event stream, and
Infrastructure views. It reads `/health`, `/capture/status`,
`/sensors/status`, `/capture/interfaces`, and `/capture/events`, and controls
the pipeline through `/capture/start`, `/capture/stop`, and `/capture/switch`.
The Sensors view starts the configured production sensor plane without asking
for log paths; paths belong to deployment configuration, not browser users.
