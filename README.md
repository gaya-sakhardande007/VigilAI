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

## OpenAI integration

Create a `.env` file in `backend/` with:

```bash
OPENAI_API_KEY=your_openai_api_key_here
```

If no API key is configured, the server will return a safe placeholder scan result.

## Notes

- `node_modules` and `.env` are ignored by Git.
- Use `npm run dev` in `backend/` for hot reloading while developing.
