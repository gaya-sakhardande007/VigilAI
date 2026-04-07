const sendButton = document.getElementById('sendButton');
const promptInput = document.getElementById('prompt');
const result = document.getElementById('result');

sendButton.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();

  if (!prompt) {
    result.textContent = 'Please enter a prompt before sending.';
    return;
  }

  result.textContent = 'Generating AI response...';

  try {
    const response = await fetch('/api/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });

    const data = await response.json();

    if (!response.ok) {
      result.textContent = data.error || 'Something went wrong while generating the response.';
      return;
    }

    result.textContent = data.response;
  } catch (error) {
    result.textContent = `Request failed: ${error.message}`;
  }
});
