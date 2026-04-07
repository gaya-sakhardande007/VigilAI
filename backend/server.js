const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const { OpenAI } = require('openai');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const waitlistFilePath = path.join(__dirname, 'data', 'waitlist.json');
const databaseUrl = process.env.DATABASE_URL || '';

const openaiKey = process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_key_here'
  ? process.env.OPENAI_API_KEY
  : null;

const openai = openaiKey
  ? new OpenAI({ apiKey: openaiKey })
  : null;

const waitlistPool = databaseUrl
  ? new Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes('localhost') ? false : { rejectUnauthorized: false }
    })
  : null;

const waitlistStoreType = waitlistPool ? 'postgres' : 'file';
const waitlistStoreReady = ensureWaitlistStore();

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/api/hello', (req, res) => {
  res.json({
    message: 'Welcome to Vigil AI!',
    status: 'ready'
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'vigil-ai',
    openaiConfigured: Boolean(openaiKey),
    waitlistStorage: waitlistStoreType
  });
});

function buildFallbackScanResult(input) {
  const lower = input.toLowerCase();
  const suspiciousKeywords = ['paypa1', 'secure-login', 'verify your account', 'bit.ly', 'won $', 'free iphone', 'claim here', 'suspicious'];
  const isDangerous = suspiciousKeywords.some((keyword) => lower.includes(keyword));
  const isSafe = lower.includes('https://www.google.com') || lower.includes('https://www.microsoft.com') || lower.includes('https://www.apple.com');

  if (isDangerous) {
    return {
      verdict: 'DANGEROUS',
      confidence: 92,
      plain_summary: 'This looks like a scam or phishing attempt.',
      detail: 'The submitted text or URL contains suspicious markers associated with phishing and fake login pages. Do not click links or enter credentials.',
      signals: ['phishing URL', 'urgent verification request', 'shortened link'],
      signal_types: ['danger', 'warning', 'warning'],
      action: 'Do not interact with this message. Delete it and verify the sender independently.',
      source: 'fallback'
    };
  }

  if (isSafe) {
    return {
      verdict: 'SAFE',
      confidence: 88,
      plain_summary: 'This appears to be a legitimate link or message.',
      detail: 'The input uses a known and trusted URL format with no obvious scam indicators. It is likely safe, although you should still verify the source.',
      signals: ['trusted domain', 'no scam indicators'],
      signal_types: ['safe', 'safe'],
      action: 'Proceed carefully and confirm the sender if you are unsure.',
      source: 'fallback'
    };
  }

  return {
    verdict: 'SUSPICIOUS',
    confidence: 74,
    plain_summary: 'This content may be suspicious and should be treated cautiously.',
    detail: 'The message or URL contains elements that are often used in phishing and scam attempts, but it does not match a clearly malicious pattern.',
    signals: ['unusual domain', 'possible phishing language'],
    signal_types: ['warning', 'warning'],
    action: 'Avoid clicking links until you verify the origin of the message.',
    source: 'fallback'
  };
}

function parseJSONResponse(text) {
  const cleaned = text
    .replace(/```json|```/g, '')
    .replace(/\n/g, ' ')
    .trim();
  return JSON.parse(cleaned);
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function ensureWaitlistStore() {
  if (!waitlistPool) {
    return;
  }

  await waitlistPool.query(`
    CREATE TABLE IF NOT EXISTS waitlist_entries (
      email TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function readWaitlistEntries() {
  try {
    const file = await fs.readFile(waitlistFilePath, 'utf8');
    const parsed = JSON.parse(file);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }

    throw error;
  }
}

async function saveWaitlistEntries(entries) {
  await fs.writeFile(waitlistFilePath, `${JSON.stringify(entries, null, 2)}\n`, 'utf8');
}

async function joinWaitlist(email) {
  if (waitlistPool) {
    await waitlistStoreReady;

    const result = await waitlistPool.query(
      `
        INSERT INTO waitlist_entries (email)
        VALUES ($1)
        ON CONFLICT (email) DO NOTHING
        RETURNING email
      `,
      [email]
    );

    return {
      alreadyJoined: result.rowCount === 0,
      email
    };
  }

  const entries = await readWaitlistEntries();
  const existingEntry = entries.find((entry) => entry.email === email);

  if (existingEntry) {
    return {
      alreadyJoined: true,
      email
    };
  }

  entries.push({
    email,
    createdAt: new Date().toISOString()
  });

  await saveWaitlistEntries(entries);

  return {
    alreadyJoined: false,
    email
  };
}

app.post('/api/scan', async (req, res) => {
  const { input } = req.body;

  if (!input || typeof input !== 'string') {
    return res.status(400).json({ error: 'Input is required.' });
  }

  if (!openai) {
    return res.json(buildFallbackScanResult(input));
  }

  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'system',
          content: `You are Vigil AI, a cybersecurity threat detection engine. Analyze the user-submitted URL or message and return ONLY a JSON object with the following fields: {"verdict":"SAFE"|"SUSPICIOUS"|"DANGEROUS","confidence":0-100,"plain_summary":"One sentence for a non-technical person","detail":"2-3 sentences explaining what was found","signals":["short flag phrases"],"signal_types":["danger"|"warning"|"safe" for each signal],"action":"What the user should do right now"}. Respond with valid JSON only, no code fences, no markdown, no additional text.`
        },
        { role: 'user', content: `Analyze this input: ${input}` }
      ],
      temperature: 0.1,
      max_tokens: 260
    });

    const text = response.choices?.[0]?.message?.content || '';
    const result = parseJSONResponse(text);
    return res.json({ ...result, source: 'openai' });
  } catch (error) {
    const statusCode = error?.status || error?.response?.status;
    console.error('OpenAI error:', error?.response?.data || error.message || error);

    if (statusCode === 429) {
      return res.json({
        ...buildFallbackScanResult(input),
        fallback_reason: 'openai_quota_exceeded'
      });
    }

    return res.status(500).json({ error: 'Failed to generate AI response.' });
  }
});

app.post('/api/waitlist', async (req, res) => {
  const email = typeof req.body?.email === 'string' ? normalizeEmail(req.body.email) : '';

  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }

  try {
    const result = await joinWaitlist(email);

    return res.status(result.alreadyJoined ? 200 : 201).json({
      ok: true,
      alreadyJoined: result.alreadyJoined,
      email: result.email,
      storage: waitlistStoreType
    });
  } catch (error) {
    console.error('Waitlist error:', error.message || error);
    return res.status(500).json({ error: 'Failed to join waitlist.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
  console.log(`Vigil AI backend running on http://localhost:${PORT}`);
});
