# Lychee AI

A starter platform for Lychee AI with a Node.js backend and a static frontend.

## Project structure

- `frontend/` - static HTML, CSS, and JavaScript files
- `backend/` - Express server that serves the frontend and a sample AI API route

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
   ```
   http://localhost:3000
   ```

## AI integration

The frontend sends prompts to `POST /api/ai`.

- If `OPENAI_API_KEY` is set in `.env`, the server will use OpenAI to generate responses.
- If no API key is configured, the server returns a placeholder response.

Create a `.env` file in `backend/` with:

```bash
OPENAI_API_KEY=your_openai_api_key_here
```

## API

- `GET /api/hello` - returns a simple status message
- `POST /api/ai` - accepts JSON `{ prompt: string }`

## Notes

- `node_modules` and `.env` are ignored by Git.
- Use `npm run dev` in `backend/` for automatic reloads.
