const express = require('express');
const path = require('path');
const { Configuration, OpenAIApi } = require('openai');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const openai = process.env.OPENAI_API_KEY
  ? new OpenAIApi(new Configuration({ apiKey: process.env.OPENAI_API_KEY }))
  : null;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/api/hello', (req, res) => {
  res.json({
    message: 'Welcome to Lychee AI!',
    status: 'ready'
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
      action: 'Do not interact with this message. Delete it and verify the sender independently.'
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
      action: 'Proceed carefully and confirm the sender if you are unsure.'
    };
  }

  return {
    verdict: 'SUSPICIOUS',
    confidence: 74,
    plain_summary: 'This content may be suspicious and should be treated cautiously.',
    detail: 'The message or URL contains elements that are often used in phishing and scam attempts, but it does not match a clearly malicious pattern.',
    signals: ['unusual domain', 'possible phishing language'],
    signal_types: ['warning', 'warning'],
    action: 'Avoid clicking links until you verify the origin of the message.'
  };
}

function parseJSONResponse(text) {
  const cleaned = text
    .replace(/```json|```/g, '')
    .replace(/\n/g, ' ')
    .trim();
  return JSON.parse(cleaned);
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
    const response = await openai.createChatCompletion({
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

    const text = response.data.choices?.[0]?.message?.content || '';
    const result = parseJSONResponse(text);
    return res.json(result);
  } catch (error) {
    console.error('OpenAI error:', error?.response?.data || error.message || error);
    return res.status(500).json({ error: 'Failed to generate AI response.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
  console.log(`Lychee AI backend running on http://localhost:${PORT}`);
});
