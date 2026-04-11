# Vigil AI

Vigil AI is a live phishing and scam detection web app that analyzes suspicious links and messages in real time. It uses OpenAI for threat analysis, falls back safely when AI is unavailable, stores waitlist signups in PostgreSQL, and is deployed on Render.

## Live Links

- Live app: `https://vigil-ai-8n28.onrender.com`
- Health check: `https://vigil-ai-8n28.onrender.com/api/health`
- GitHub repo: `https://github.com/gaya-sakhardande007/LycheeAI`

## Quick Start

1. Open the live app: `https://vigil-ai-8n28.onrender.com`
2. Paste a suspicious URL or message into the scanner
3. Review the AI verdict, confidence score, signals, and recommended action

## What It Does

- Detects phishing links and scam messages in real time
- Uses OpenAI-powered analysis with resilient fallback detection
- Captures waitlist signups in PostgreSQL
- Includes production safeguards like health checks and rate limiting

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
- `POST /api/scan` is rate-limited to 20 requests per 15 minutes per client IP
- `POST /api/waitlist` is rate-limited to 5 requests per hour per client IP
- `GET /api/admin/waitlist` exports waitlist entries for admins when `ADMIN_API_KEY` is configured

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
ADMIN_API_KEY=replace_with_a_long_random_secret
PORT=3000
CANONICAL_PROTOCOL=https
ENFORCE_CANONICAL_HOST=false
PUBLIC_DOMAIN=
```

### Custom domain (so users do not use the Render URL)

You can point a real domain (for example `vigilai.com`) to this app and force all traffic to that domain.

1. Buy or use an existing domain from a registrar (Cloudflare, Namecheap, GoDaddy, etc.).
2. In Render, open the `vigil-ai` service and add a Custom Domain:
   - Add your apex domain (for example `vigilai.com`)
   - Add `www.vigilai.com` if you want both
3. At your DNS provider, create the records Render shows you (usually CNAME for `www`, ALIAS/ANAME or A records for apex).
4. Wait until Render marks the domain as verified and SSL certificate as active.
5. Set these environment variables in Render:
   - `PUBLIC_DOMAIN=vigilai.com`
   - `CANONICAL_PROTOCOL=https`
   - `ENFORCE_CANONICAL_HOST=true`
6. Redeploy the service.

After this, users can visit your custom domain directly, and requests to non-canonical hosts are redirected to your domain.

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

### Waitlist admin export

To export waitlist entries, configure `ADMIN_API_KEY` and call one of these:

```bash
curl -H "x-admin-key: your_admin_api_key" https://your-app.example.com/api/admin/waitlist
curl -H "Authorization: Bearer your_admin_api_key" "https://your-app.example.com/api/admin/waitlist?format=csv"
```

### Waitlist storage

When `DATABASE_URL` is configured, the waitlist is stored in PostgreSQL and the server creates the `waitlist_entries` table automatically.

If `DATABASE_URL` is not configured, the app falls back to `backend/data/waitlist.json` for local development only.
