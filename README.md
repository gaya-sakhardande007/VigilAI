# Vigil AI

A starter platform for Vigil AI with a Node.js backend and a polished Vigil AI-style frontend.

## Project structure

- `frontend/` - static landing page and scanner UI
- `backend/` - Express server that serves the frontend and AI scan endpoint

## Setup

1. Install backend dependencies:
   ```bash
   cd backend
   npm install
   ```

2. Start the server:
   ```bash
   npm start
   ```

3. Open your browser at:
   ```bash
   http://localhost:3000
   ```

## AI scan endpoint

- `POST /api/scan` accepts JSON `{ input: string }`
- Returns a structured threat verdict object for the UI
- `GET /api/health` returns a lightweight deployment health check

## OpenAI integration

Create a `.env` file in `backend/` with:

```bash
OPENAI_API_KEY=your_openai_api_key_here
```

If no API key is configured, or if OpenAI quota is unavailable, the server will return a local fallback threat analysis instead.

## Notes

- `node_modules` and `.env` are ignored by Git.
- Use `npm run dev` in `backend/` for hot reloading while developing.

## Deployment

This app deploys as a single Node.js service. The Express backend serves both the API and the static frontend.

### Environment variables

Set these in your hosting provider:

```bash
OPENAI_API_KEY=your_openai_api_key_here
DATABASE_URL=postgresql://user:password@host:5432/database
PORT=3000
```

### Docker deployment

Build and run locally:

```bash
docker build -t vigil-ai .
docker run --rm -p 3000:3000 --env OPENAI_API_KEY=your_openai_api_key_here vigil-ai
```

### Render deployment

This repo includes a Render blueprint in [render.yaml](render.yaml).

To deploy on Render:

1. Create a new Blueprint service from this repository.
2. Set `OPENAI_API_KEY` in the Render dashboard before the first deploy.
3. Render will provision the `vigil-ai-db` PostgreSQL database from `render.yaml` and inject `DATABASE_URL` into the web service.
4. Deploy the `vigil-ai` web service.
5. Verify the health check at `/api/health`.

Render will build from the existing Dockerfile, so there is no separate build command to maintain.

### Health check

Use this path for container or platform health checks:

```bash
GET /api/health
```

### Waitlist storage

When `DATABASE_URL` is configured, the waitlist is stored in PostgreSQL and the server creates the `waitlist_entries` table automatically.

If `DATABASE_URL` is not configured, the app falls back to `backend/data/waitlist.json` for local development only.
