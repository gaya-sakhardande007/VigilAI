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

app.post('/api/ai', async (req, res) => {
  const { prompt } = req.body;

  if (!prompt || typeof prompt !== 'string') {
    return res.status(400).json({ error: 'Prompt is required.' });
  }

  if (!openai) {
    return res.json({
      response: `AI integration placeholder response for prompt: ${prompt}`
    });
  }

  try {
    const completion = await openai.createChatCompletion({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 250
    });

    const content = completion.data.choices?.[0]?.message?.content?.trim() || '';
    res.json({ response: content });
  } catch (error) {
    console.error('OpenAI error:', error?.response?.data || error.message || error);
    res.status(500).json({ error: 'Failed to generate AI response.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
  console.log(`Lychee AI backend running on http://localhost:${PORT}`);
});
