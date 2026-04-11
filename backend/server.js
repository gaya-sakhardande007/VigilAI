const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { OpenAI } = require('openai');
const { Pool } = require('pg');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const dataDir = path.join(__dirname, 'data');
const waitlistFilePath = path.join(dataDir, 'waitlist.json');
const scanHistoryFilePath = path.join(dataDir, 'scan-history.json');
const reportsFilePath = path.join(dataDir, 'reports.json');

const databaseUrl = process.env.DATABASE_URL || '';
const adminApiKey = process.env.ADMIN_API_KEY || '';
const publicDomain = (process.env.PUBLIC_DOMAIN || '').trim().toLowerCase();
const enforceCanonicalHost = process.env.ENFORCE_CANONICAL_HOST === 'true';
const canonicalProtocol = (process.env.CANONICAL_PROTOCOL || 'https').toLowerCase() === 'http' ? 'http' : 'https';

const openaiKey = process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_key_here'
  ? process.env.OPENAI_API_KEY
  : null;

const openai = openaiKey ? new OpenAI({ apiKey: openaiKey }) : null;
const waitlistPool = databaseUrl
  ? new Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes('localhost') ? false : { rejectUnauthorized: false }
    })
  : null;

const waitlistStoreType = waitlistPool ? 'postgres' : 'file';
const waitlistStoreReady = ensureWaitlistStore();
const localDataReady = ensureLocalDataFiles();

app.set('trust proxy', 1);
app.use(express.json({ limit: '150kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.use((req, res, next) => {
  if (!enforceCanonicalHost || !publicDomain) {
    return next();
  }

  if (req.path === '/api/health') {
    return next();
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return next();
  }

  const forwardedHost = (req.headers['x-forwarded-host'] || '').toString().split(',')[0].trim();
  const requestHost = (forwardedHost || req.headers.host || '').toString().toLowerCase();

  if (!requestHost || requestHost === publicDomain) {
    return next();
  }

  return res.redirect(308, `${canonicalProtocol}://${publicDomain}${req.originalUrl || '/'}`);
});

app.use(express.static(path.join(__dirname, '../frontend')));

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests. Please try again in a few minutes.' }
});

const waitlistLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many waitlist requests. Please try again later.' }
});

const reportLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many report requests. Please try again in a few minutes.' }
});

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parseJSONResponse(text) {
  const cleaned = text.replace(/```json|```/g, '').trim();
  return JSON.parse(cleaned);
}

function buildInputSnippet(input) {
  return input.length > 120 ? `${input.slice(0, 117)}...` : input;
}

function limitFromQuery(value, fallback = 6, max = 50) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.min(parsed, max);
}

function getAdminToken(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  return (req.headers['x-admin-key'] || '').toString().trim();
}

function requireAdmin(req, res, next) {
  if (!adminApiKey) {
    return res.status(503).json({ error: 'Admin export is not configured.' });
  }
  if (getAdminToken(req) !== adminApiKey) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  return next();
}

function toCsv(entries) {
  const rows = ['email,createdAt'];
  for (const entry of entries) {
    const escapedEmail = `"${entry.email.replace(/"/g, '""')}"`;
    const escapedCreatedAt = `"${entry.createdAt.replace(/"/g, '""')}"`;
    rows.push(`${escapedEmail},${escapedCreatedAt}`);
  }
  return `${rows.join('\n')}\n`;
}

function buildFallbackScanResult(input) {
  const lower = input.toLowerCase();
  const suspiciousKeywords = ['paypa1', 'secure-login', 'verify your account', 'bit.ly', 'won $', 'free iphone', 'claim here', 'urgent', 'suspended'];
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

async function ensureJsonFile(filePath) {
  try {
    await fs.access(filePath);
  } catch {
    await fs.writeFile(filePath, '[]\n', 'utf8');
  }
}

async function ensureLocalDataFiles() {
  await fs.mkdir(dataDir, { recursive: true });
  await Promise.all([
    ensureJsonFile(waitlistFilePath),
    ensureJsonFile(scanHistoryFilePath),
    ensureJsonFile(reportsFilePath)
  ]);
}

async function readJsonArray(filePath) {
  const content = await fs.readFile(filePath, 'utf8');
  const parsed = JSON.parse(content);
  return Array.isArray(parsed) ? parsed : [];
}

async function writeJsonArray(filePath, entries) {
  await fs.writeFile(filePath, `${JSON.stringify(entries, null, 2)}\n`, 'utf8');
}

async function appendJsonEntry(filePath, entry, maxEntries = 120) {
  const entries = await readJsonArray(filePath);
  entries.unshift(entry);
  await writeJsonArray(filePath, entries.slice(0, maxEntries));
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
  if (waitlistPool) {
    await waitlistStoreReady;
    const result = await waitlistPool.query(`
      SELECT email, created_at
      FROM waitlist_entries
      ORDER BY created_at DESC
    `);
    return result.rows.map((row) => ({
      email: row.email,
      createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at
    }));
  }

  await localDataReady;
  const entries = await readJsonArray(waitlistFilePath);
  return [...entries].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
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
    return { alreadyJoined: result.rowCount === 0, email };
  }

  await localDataReady;
  const entries = await readJsonArray(waitlistFilePath);
  const existingEntry = entries.find((entry) => entry.email === email);
  if (existingEntry) {
    return { alreadyJoined: true, email };
  }

  entries.push({ email, createdAt: new Date().toISOString() });
  await writeJsonArray(waitlistFilePath, entries);
  return { alreadyJoined: false, email };
}

function buildScanRecord(input, result, mode, fingerprint) {
  return {
    id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    inputSnippet: buildInputSnippet(input),
    inputType: fingerprint?.inputType || 'Unknown',
    verdict: result.verdict,
    confidence: result.confidence,
    summary: result.plain_summary,
    detail: result.detail,
    source: result.source || 'unknown',
    mode: mode || 'deep',
    signals: result.signals || [],
    campaign: fingerprint?.campaign || null,
    target: fingerprint?.target || null
  };
}

function buildInsights(entries) {
  const verdictCounts = entries.reduce((accumulator, entry) => {
    accumulator[entry.verdict] = (accumulator[entry.verdict] || 0) + 1;
    return accumulator;
  }, {});

  const signalCounts = entries.reduce((accumulator, entry) => {
    for (const signal of entry.signals || []) {
      accumulator[signal] = (accumulator[signal] || 0) + 1;
    }
    return accumulator;
  }, {});

  const topVerdict = Object.entries(verdictCounts).sort((left, right) => right[1] - left[1])[0]?.[0] || 'None';
  const topSignal = Object.entries(signalCounts).sort((left, right) => right[1] - left[1])[0]?.[0] || 'Waiting';
  const dangerCount = entries.filter((entry) => entry.verdict === 'DANGEROUS').length;
  const dangerRate = entries.length ? Math.round((dangerCount / entries.length) * 100) : 0;

  return {
    totalScans: entries.length,
    dangerRate,
    topVerdict,
    topSignal,
    verdictCounts
  };
}

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Welcome to Vigil AI!', status: 'ready' });
});

app.get('/api/health', async (req, res) => {
  await localDataReady;
  const history = await readJsonArray(scanHistoryFilePath);
  const reports = await readJsonArray(reportsFilePath);

  res.json({
    status: 'ok',
    service: 'vigil-ai',
    openaiConfigured: Boolean(openaiKey),
    waitlistStorage: waitlistStoreType,
    scanHistoryCount: history.length,
    reportCount: reports.length
  });
});

app.post('/api/scan', scanLimiter, async (req, res) => {
  const input = typeof req.body?.input === 'string' ? req.body.input.trim() : '';
  const mode = typeof req.body?.mode === 'string' ? req.body.mode : 'deep';
  const fingerprint = typeof req.body?.fingerprint === 'object' && req.body.fingerprint ? req.body.fingerprint : null;

  if (!input) {
    return res.status(400).json({ error: 'Input is required.' });
  }

  let result;
  if (!openai) {
    result = buildFallbackScanResult(input);
  } else {
    try {
      const response = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'You are Vigil AI, a cybersecurity threat detection engine. Analyze the user-submitted URL or message and return ONLY a valid JSON object with the following fields: {"verdict":"SAFE"|"SUSPICIOUS"|"DANGEROUS","confidence":0-100,"plain_summary":"One sentence for a non-technical person","detail":"2-3 sentences explaining what was found","signals":["short flag phrases"],"signal_types":["danger"|"warning"|"safe"],"action":"What the user should do right now"}. No markdown or extra text.'
          },
          { role: 'user', content: `Analyze this input: ${input}` }
        ],
        temperature: 0.1,
        max_tokens: 260
      });

      const text = response.choices?.[0]?.message?.content || '';
      result = { ...parseJSONResponse(text), source: 'openai' };
    } catch (error) {
      const statusCode = error?.status || error?.response?.status;
      console.error('OpenAI error:', error?.message || error);
      if (statusCode === 429) {
        result = { ...buildFallbackScanResult(input), fallback_reason: 'openai_quota_exceeded' };
      } else {
        result = buildFallbackScanResult(input);
      }
    }
  }

  await localDataReady;
  await appendJsonEntry(scanHistoryFilePath, buildScanRecord(input, result, mode, fingerprint), 120);
  return res.json(result);
});

app.get('/api/scan/history', async (req, res) => {
  await localDataReady;
  const entries = await readJsonArray(scanHistoryFilePath);
  return res.json({ entries: entries.slice(0, limitFromQuery(req.query.limit)) });
});

app.get('/api/scan/insights', async (req, res) => {
  await localDataReady;
  const entries = await readJsonArray(scanHistoryFilePath);
  return res.json(buildInsights(entries.slice(0, 100)));
});

app.post('/api/reports', reportLimiter, async (req, res) => {
  const label = typeof req.body?.label === 'string' ? req.body.label.trim() : '';
  const verdict = typeof req.body?.verdict === 'string' ? req.body.verdict.trim() : '';
  if (!label || !verdict) {
    return res.status(400).json({ error: 'Report label and verdict are required.' });
  }

  await localDataReady;
  const entry = {
    id: `report_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    label,
    inputSnippet: buildInputSnippet(typeof req.body?.input === 'string' ? req.body.input : ''),
    verdict,
    confidence: req.body?.confidence || 0,
    plainSummary: typeof req.body?.plainSummary === 'string' ? req.body.plainSummary : '',
    detail: typeof req.body?.detail === 'string' ? req.body.detail : '',
    action: typeof req.body?.action === 'string' ? req.body.action : '',
    signals: Array.isArray(req.body?.signals) ? req.body.signals.slice(0, 12) : [],
    source: typeof req.body?.source === 'string' ? req.body.source : 'unknown',
    mode: typeof req.body?.mode === 'string' ? req.body.mode : 'deep',
    fingerprint: typeof req.body?.fingerprint === 'object' && req.body.fingerprint ? req.body.fingerprint : null
  };

  await appendJsonEntry(reportsFilePath, entry, 120);
  return res.status(201).json({ ok: true, entry });
});

app.get('/api/reports', async (req, res) => {
  await localDataReady;
  const entries = await readJsonArray(reportsFilePath);
  return res.json({ entries: entries.slice(0, limitFromQuery(req.query.limit)) });
});

app.post('/api/waitlist', waitlistLimiter, async (req, res) => {
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
    console.error('Waitlist error:', error?.message || error);
    return res.status(500).json({ error: 'Failed to join waitlist.' });
  }
});

app.get('/api/admin/waitlist', requireAdmin, async (req, res) => {
  try {
    const entries = await readWaitlistEntries();
    if (req.query.format === 'csv') {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="waitlist-export.csv"');
      return res.send(toCsv(entries));
    }
    return res.json({ storage: waitlistStoreType, count: entries.length, entries });
  } catch (error) {
    console.error('Waitlist export error:', error?.message || error);
    return res.status(500).json({ error: 'Failed to export waitlist.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Vigil AI backend running on http://localhost:${PORT}`);
  });
}
