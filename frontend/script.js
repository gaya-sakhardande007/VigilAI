const scanInput = document.getElementById('scanInput');
const scanBtn = document.getElementById('scanBtn');
const scanResult = document.getElementById('scanResult');
const modeSwitches = document.getElementById('modeSwitches');
const saveReportBtn = document.getElementById('saveReportBtn');
const copyFingerprintBtn = document.getElementById('copyFingerprintBtn');
const clearWorkbenchBtn = document.getElementById('clearWorkbenchBtn');
const waitlistBtn = document.getElementById('waitlistBtn');
const refreshIntelBtn = document.getElementById('refreshIntelBtn');
const historyList = document.getElementById('historyList');
const reportsList = document.getElementById('reportsList');
const threatMix = document.getElementById('intelThreatMix');

const riskElements = {
  social: { bar: document.getElementById('barSocial'), value: document.getElementById('barSocialValue') },
  domain: { bar: document.getElementById('barDomain'), value: document.getElementById('barDomainValue') },
  credential: { bar: document.getElementById('barCredential'), value: document.getElementById('barCredentialValue') },
  malware: { bar: document.getElementById('barMalware'), value: document.getElementById('barMalwareValue') }
};

const heroRiskElements = {
  social: { bar: document.getElementById('heroBarSocial'), value: document.getElementById('heroBarSocialValue') },
  domain: { bar: document.getElementById('heroBarDomain'), value: document.getElementById('heroBarDomainValue') },
  credential: { bar: document.getElementById('heroBarCredential'), value: document.getElementById('heroBarCredentialValue') },
  malware: { bar: document.getElementById('heroBarMalware'), value: document.getElementById('heroBarMalwareValue') }
};

const modeCopy = {
  deep: { label: 'Deep Explain', persona: 'Family account', action: 'Verify before opening' },
  action: { label: 'Action Mode', persona: 'High-risk moment', action: 'Follow the response steps' },
  family: { label: 'Family Shield', persona: 'Parent or elder', action: 'Use simple safety advice' }
};

let currentMode = 'deep';
let latestFingerprint = null;
let latestScanResult = null;
let intelAnimatedOnce = false;

function clamp(value) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function escapeHtml(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function setBusyState(isBusy) {
  scanResult.classList.toggle('is-busy', isBusy);
}

function flashResult() {
  scanResult.classList.add('is-fresh');
  window.setTimeout(() => scanResult.classList.remove('is-fresh'), 700);
}

function renderInfoState(title, message) {
  scanResult.innerHTML = `<div class="result-body"><div class="meta-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(message)}</p></div></div>`;
  flashResult();
}

function setBar(target, score) {
  const safeScore = clamp(score);
  target.bar.style.width = safeScore + '%';
  target.value.textContent = safeScore;
}

function animateMetricValue(elementId, nextValue, suffix = '', duration = 680, forceFromZero = false) {
  const element = document.getElementById(elementId);
  if (!element) return;

  const startValue = forceFromZero ? 0 : Number.parseInt(String(element.textContent).replace(/[^0-9]/g, ''), 10) || 0;
  const targetValue = Math.max(0, Number(nextValue || 0));
  if (startValue === targetValue) {
    element.textContent = `${targetValue}${suffix}`;
    return;
  }

  const start = performance.now();
  const tick = (now) => {
    const progress = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = Math.round(startValue + (targetValue - startValue) * eased);
    element.textContent = `${value}${suffix}`;
    if (progress < 1) {
      requestAnimationFrame(tick);
    }
  };

  requestAnimationFrame(tick);
}

function animateTelemetryRows() {
  const rows = Array.from(document.querySelectorAll('.telemetry-row'));
  rows.forEach((row, index) => {
    row.classList.remove('is-live');
    row.style.animationDelay = `${index * 80}ms`;
    window.setTimeout(() => row.classList.add('is-live'), 20);
  });
}

function detectInputType(input) {
  if (/https?:\/\//i.test(input)) return 'URL + message';
  if (/www\./i.test(input) || /\.[a-z]{2,}(\/|\?|$)/i.test(input)) return 'URL';
  if (input.length > 180) return 'Long-form message';
  return 'Short message';
}

function inferCampaignType(lower) {
  if (/password|verify|account|login|bank|paypal|microsoft|apple/.test(lower)) return 'Credential phishing';
  if (/won|free iphone|claim|gift|reward|bonus/.test(lower)) return 'Prize or reward scam';
  if (/invoice|payment|crypto|wallet|transfer/.test(lower)) return 'Payment redirection';
  if (/download|apk|attachment|installer|update/.test(lower)) return 'Malware delivery';
  return 'Needs review';
}

function inferTarget(lower) {
  if (/bank|account|verify|login|password|code/.test(lower)) return 'Credentials';
  if (/payment|invoice|transfer|wallet|crypto/.test(lower)) return 'Money';
  if (/family|mom|dad|child|parent/.test(lower)) return 'Family trust';
  if (/download|install|attachment|apk/.test(lower)) return 'Device access';
  return 'Attention';
}

function domainHygiene(input, lower) {
  const suspiciousTlds = ['.xyz', '.top', '.click', '.live', '.gq', '.ru'];
  const shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl'];
  let hygiene = 'Clean';
  if (suspiciousTlds.some((tld) => lower.includes(tld)) || shorteners.some((value) => lower.includes(value))) hygiene = 'Suspicious';
  if (/(paypa1|micr0soft|app1e|lloyds-bank-secure)/.test(lower)) hygiene = 'Spoofed';
  if (!/(https?:\/\/|www\.|\.[a-z]{2,})/.test(input)) hygiene = 'No link detected';
  return hygiene;
}

function buildPreview(input) {
  const pattern = /(urgent|verify|suspended|claim|free iphone|won|password|login|bank|secure|bit\.ly|download|attachment|payment|reward)/gi;
  const safe = escapeHtml(input || 'Paste input to see highlighted suspicious language.');
  return safe.replace(pattern, '<mark>$1</mark>');
}

function buildPlaybook(campaign, hygiene, mode) {
  if (mode === 'action') {
    return [
      { title: 'Stop', note: 'Do not click, reply, or open attachments.' },
      { title: 'Verify elsewhere', note: 'Use the official website or saved phone number.' },
      { title: 'Report', note: 'If this targets a bank or workplace, alert them now.' }
    ];
  }
  if (mode === 'family') {
    return [
      { title: 'Pause first', note: 'If a message rushes you, treat it as suspicious.' },
      { title: 'Ask someone you trust', note: 'Show it to family before acting.' },
      { title: 'Use the real app', note: 'Open the official app yourself instead of links.' }
    ];
  }
  const secondStep = hygiene === 'Spoofed' ? 'The domain looks imitative. Use a known official URL.' : 'Check if the content pushes login, payment, or download.';
  return [
    { title: 'Profile the threat', note: campaign + ' indicators are present.' },
    { title: 'Validate source', note: secondStep },
    { title: 'Contain exposure', note: 'If you already clicked, reset passwords and notify the service.' }
  ];
}

function analyzeInputLocal(input) {
  const lower = input.toLowerCase();
  const urgentMatches = (lower.match(/urgent|immediately|now|suspended|locked|final notice|act fast/g) || []).length;
  const credentialMatches = (lower.match(/verify|login|password|code|account|bank|paypal|microsoft|apple/g) || []).length;
  const rewardMatches = (lower.match(/won|free|claim|reward|bonus|gift/g) || []).length;
  const malwareMatches = (lower.match(/download|apk|attachment|installer|file|update/g) || []).length;
  const spoofMatches = (lower.match(/paypa1|micr0soft|app1e|lloyds-bank-secure/g) || []).length;
  const linkMatches = (lower.match(/https?:\/\/|www\.|bit\.ly|tinyurl|\.xyz|\.top|\.click/g) || []).length;

  const scores = {
    social: clamp(24 + urgentMatches * 16 + rewardMatches * 10),
    domain: clamp(10 + linkMatches * 18 + spoofMatches * 24),
    credential: clamp(18 + credentialMatches * 14 + spoofMatches * 10),
    malware: clamp(6 + malwareMatches * 20 + rewardMatches * 6)
  };

  return {
    inputType: detectInputType(input),
    campaign: inferCampaignType(lower),
    target: inferTarget(lower),
    hygiene: domainHygiene(input, lower),
    scores,
    overallRisk: clamp((scores.social + scores.domain + scores.credential + scores.malware) / 4),
    preview: buildPreview(input),
    heroAttack: input.trim() ? inferCampaignType(lower) : 'Credential phishing'
  };
}

function renderPlaybook(items) {
  const container = document.getElementById('playbookTimeline');
  container.innerHTML = items.map((item, index) => `<div class="timeline-item"><div class="timeline-badge">${index + 1}</div><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.note)}</p></div></div>`).join('');
}

function updateHeroOrb(score) {
  const degrees = Math.max(12, clamp(score) * 3.6);
  let color = 'var(--cyan)';
  if (score >= 75) color = 'var(--red)';
  else if (score >= 45) color = 'var(--amber)';
  else color = 'var(--mint)';
  document.getElementById('heroOrb').style.background = `conic-gradient(${color} 0deg ${degrees}deg, rgba(255,255,255,0.1) ${degrees}deg 360deg)`;
}

function renderFingerprint(fingerprint) {
  latestFingerprint = fingerprint;
  document.getElementById('fingerprintType').textContent = fingerprint.inputType;
  document.getElementById('fingerprintCampaign').textContent = fingerprint.campaign;
  document.getElementById('fingerprintTarget').textContent = fingerprint.target;
  document.getElementById('fingerprintHygiene').textContent = fingerprint.hygiene;
  document.getElementById('forensicPreview').innerHTML = fingerprint.preview;
  document.getElementById('heroOrbValue').textContent = fingerprint.overallRisk;
  document.getElementById('heroAttack').textContent = fingerprint.heroAttack;
  document.getElementById('heroMode').textContent = modeCopy[currentMode].label;
  document.getElementById('heroPersona').textContent = modeCopy[currentMode].persona;
  document.getElementById('heroAction').textContent = modeCopy[currentMode].action;

  Object.keys(riskElements).forEach((key) => {
    setBar(riskElements[key], fingerprint.scores[key]);
    setBar(heroRiskElements[key], fingerprint.scores[key]);
  });

  renderPlaybook(buildPlaybook(fingerprint.campaign, fingerprint.hygiene, currentMode));
  updateHeroOrb(fingerprint.overallRisk);
}

function signalClass(type) {
  if (type === 'danger') return 'tag-danger';
  if (type === 'safe') return 'tag-safe';
  return 'tag-warning';
}

function buildFallbackNotice(data) {
  if (data.source !== 'fallback') return '';
  const message = data.fallback_reason === 'openai_quota_exceeded'
    ? 'OpenAI quota unavailable for this project, so this verdict came from local detection.'
    : 'This verdict was generated by fallback analysis.';
  return `<div class="meta-card"><strong>Fallback analysis active</strong><p>${escapeHtml(message)}</p></div>`;
}

function animateResultLayers() {
  const header = scanResult.querySelector('.result-header');
  if (header) {
    header.classList.add('result-animate-header');
  }

  const cards = Array.from(scanResult.querySelectorAll('.result-body > .meta-card, .result-body > .stack-row'));
  cards.forEach((card, index) => {
    card.classList.add('result-animate-card');
    card.style.animationDelay = `${index * 70}ms`;
  });

  const tags = Array.from(scanResult.querySelectorAll('.tag'));
  tags.forEach((tag, index) => {
    tag.classList.add('result-animate-tag');
    tag.style.animationDelay = `${220 + index * 50}ms`;
  });
}

function renderResult(data) {
  if (data.error) {
    latestScanResult = null;
    saveReportBtn.disabled = true;
    renderInfoState('Scan failed', data.error);
    return;
  }

  latestScanResult = data;
  saveReportBtn.disabled = false;

  const badgeClass = data.verdict === 'SAFE' ? 'badge-safe' : data.verdict === 'DANGEROUS' ? 'badge-danger' : 'badge-suspicious';
  const sourceLabel = data.source === 'openai' ? 'OpenAI-backed analysis' : data.source === 'fallback' ? 'Fallback local analysis' : 'Threat analysis';
  const enrichedAction = currentMode === 'family' ? 'Plain-language advice: ' + data.action : currentMode === 'action' ? 'Immediate action: ' + data.action : data.action;
  const signalTags = (data.signals || []).map((signal, index) => {
    const type = data.signal_types && data.signal_types[index] ? data.signal_types[index] : 'warning';
    return `<span class="tag ${signalClass(type)}">${escapeHtml(signal)}</span>`;
  }).join('');

  const fingerprintCards = latestFingerprint ? `<div class="stack-row"><div class="meta-card"><strong>Fingerprint snapshot</strong><p>${escapeHtml(latestFingerprint.campaign)} targeting ${escapeHtml(latestFingerprint.target.toLowerCase())} with ${escapeHtml(latestFingerprint.hygiene.toLowerCase())} link hygiene.</p></div><div class="meta-card"><strong>Mode framing</strong><p>${escapeHtml(modeCopy[currentMode].label)} rewrites guidance for ${escapeHtml(modeCopy[currentMode].persona.toLowerCase())} scenarios.</p></div></div>` : '';

  scanResult.innerHTML = `<div class="result-header"><div class="verdict-wrap"><div class="verdict-badge ${badgeClass}">${escapeHtml(data.verdict.charAt(0))}</div><div><div class="verdict-title">${escapeHtml(data.verdict)}</div><div class="result-meta">${escapeHtml(sourceLabel)}</div></div></div><div class="confidence-chip">Confidence ${escapeHtml(data.confidence)}%</div></div><div class="result-body">${buildFallbackNotice(data)}${fingerprintCards}<div class="stack-row"><div class="meta-card"><strong>Plain summary</strong><p>${escapeHtml(data.plain_summary)}</p></div><div class="meta-card"><strong>Recommended move</strong><p>${escapeHtml(enrichedAction)}</p></div></div><div class="meta-card"><strong>Deep analysis</strong><p>${escapeHtml(data.detail)}</p></div><div class="meta-card"><strong>Signals</strong><div class="tags">${signalTags || '<span class="tag tag-safe">No additional signals</span>'}</div></div></div>`;

  animateResultLayers();
  flashResult();
}

function relativeTime(dateString) {
  const diff = Date.now() - new Date(dateString).getTime();
  const minutes = Math.max(1, Math.round(diff / 60000));
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function renderHistory(entries) {
  if (!entries.length) {
    historyList.innerHTML = '<div class="empty-state">No scan history yet.</div>';
    return;
  }
  historyList.innerHTML = entries.map((entry) => `<div class="list-item"><div class="list-item-header"><strong>${escapeHtml(entry.verdict)}</strong><span class="list-pill">${escapeHtml(relativeTime(entry.createdAt))}</span></div><p>${escapeHtml(entry.summary || entry.inputSnippet || 'No summary')}</p><div class="list-meta"><span class="list-pill">${escapeHtml(entry.inputType || 'Unknown')}</span><span class="list-pill">${escapeHtml(entry.source || 'local')}</span><span class="list-pill">${escapeHtml(String(entry.confidence || 0))}%</span></div></div>`).join('');
}

function renderReports(entries) {
  if (!entries.length) {
    reportsList.innerHTML = '<div class="empty-state">No saved reports yet.</div>';
    return;
  }
  reportsList.innerHTML = entries.map((entry) => `<div class="list-item"><div class="list-item-header"><strong>${escapeHtml(entry.label)}</strong><span class="list-pill">${escapeHtml(relativeTime(entry.createdAt))}</span></div><p>${escapeHtml(entry.plainSummary || entry.inputSnippet || 'Saved case')}</p><div class="list-meta"><span class="list-pill">${escapeHtml(entry.verdict)}</span><span class="list-pill">${escapeHtml(entry.mode || 'deep')}</span></div></div>`).join('');
}

function renderInsights(data) {
  const totalScans = Number(data.totalScans || 0);
  const dangerRate = Number(data.dangerRate || 0);

  animateMetricValue('intelTotalScans', totalScans, '', 720, !intelAnimatedOnce);
  animateMetricValue('intelDangerRate', dangerRate, '%', 780, !intelAnimatedOnce);
  document.getElementById('intelTopVerdict').textContent = data.topVerdict || 'None';
  document.getElementById('intelTopSignal').textContent = data.topSignal || 'No pattern';

  const headline = document.getElementById('intelHeadline');
  if (headline) {
    headline.textContent = totalScans
      ? `Across ${totalScans} recent scans, ${dangerRate}% were high-risk.`
      : 'Waiting for enough scans to detect a pattern.';
  }

  const verdictEntries = Object.entries(data.verdictCounts || {});
  const verdictClass = (verdict) => {
    if (verdict === 'SAFE') return 'telemetry-fill-safe';
    if (verdict === 'DANGEROUS') return 'telemetry-fill-danger';
    return 'telemetry-fill-warning';
  };

  threatMix.innerHTML = verdictEntries.length
    ? verdictEntries.map(([verdict, count]) => {
      const share = totalScans ? clamp((Number(count) / totalScans) * 100) : 0;
      return `<div class="telemetry-row"><div class="telemetry-top"><span class="telemetry-verdict">${escapeHtml(verdict)}</span><span class="telemetry-count">${escapeHtml(String(count))} scans (${share}%)</span></div><div class="telemetry-track"><i class="telemetry-fill ${verdictClass(verdict)}" style="width:${share}%"></i></div></div>`;
    }).join('')
    : '<div class="empty-state">No telemetry yet.</div>';

  animateTelemetryRows();
  intelAnimatedOnce = true;
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

async function loadIntel() {
  refreshIntelBtn.disabled = true;
  refreshIntelBtn.classList.add('is-spinning');
  try {
    const [history, insights, reports] = await Promise.all([
      fetchJson('/api/scan/history?limit=6'),
      fetchJson('/api/scan/insights'),
      fetchJson('/api/reports?limit=6')
    ]);
    renderHistory(history.entries || []);
    renderInsights(insights || {});
    renderReports(reports.entries || []);
  } catch (error) {
    const message = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    historyList.innerHTML = message;
    reportsList.innerHTML = message;
    threatMix.innerHTML = message;
  } finally {
    refreshIntelBtn.disabled = false;
    refreshIntelBtn.classList.remove('is-spinning');
  }
}

async function doScan() {
  const input = scanInput.value.trim();
  if (!input) {
    renderInfoState('No input provided', 'Paste suspicious content to run the scan.');
    return;
  }

  renderFingerprint(analyzeInputLocal(input));
  setBusyState(true);
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';
  scanResult.innerHTML = '<div class="loading"><span></span><span></span><span></span></div>';

  try {
    const data = await fetchJson('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input, mode: currentMode, fingerprint: latestFingerprint })
    });
    renderResult(data);
    await loadIntel();
  } catch (error) {
    renderInfoState('Scan failed', error.message);
  } finally {
    setBusyState(false);
    scanBtn.disabled = false;
    scanBtn.textContent = 'Run threat scan';
  }
}

async function joinWaitlist() {
  const emailInput = document.getElementById('emailInput');
  const waitlistSuccess = document.getElementById('waitlistSuccess');
  const waitlistError = document.getElementById('waitlistError');
  const email = emailInput.value.trim();
  waitlistSuccess.style.display = 'none';
  waitlistError.style.display = 'none';
  waitlistError.textContent = '';

  if (!email || !email.includes('@')) {
    waitlistError.textContent = 'Enter a valid email address.';
    waitlistError.style.display = 'block';
    emailInput.focus();
    return;
  }

  waitlistBtn.disabled = true;
  waitlistBtn.textContent = 'Joining...';
  try {
    const data = await fetchJson('/api/waitlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    waitlistSuccess.textContent = data.alreadyJoined ? 'You are already on the waitlist.' : "You're on the list. We'll be in touch soon.";
    waitlistSuccess.style.display = 'block';
    emailInput.value = '';
  } catch (error) {
    waitlistError.textContent = error.message;
    waitlistError.style.display = 'block';
  } finally {
    waitlistBtn.disabled = false;
    waitlistBtn.textContent = 'Join waitlist';
  }
}

async function saveReport() {
  if (!latestScanResult) {
    renderInfoState('No scan to save', 'Run a scan first so there is a report to store.');
    return;
  }

  saveReportBtn.disabled = true;
  saveReportBtn.textContent = 'Saving...';

  try {
    await fetchJson('/api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: `${latestScanResult.verdict} case`,
        input: scanInput.value.trim(),
        verdict: latestScanResult.verdict,
        confidence: latestScanResult.confidence,
        plainSummary: latestScanResult.plain_summary,
        detail: latestScanResult.detail,
        action: latestScanResult.action,
        signals: latestScanResult.signals || [],
        source: latestScanResult.source || 'unknown',
        mode: currentMode,
        fingerprint: latestFingerprint
      })
    });
    renderInfoState('Report saved', 'This case is now in the saved reports panel.');
    await loadIntel();
  } catch (error) {
    renderInfoState('Save failed', error.message);
  } finally {
    saveReportBtn.disabled = false;
    saveReportBtn.textContent = 'Save report';
  }
}

function copyInputFingerprint() {
  if (!latestFingerprint) {
    renderInfoState('Nothing to copy', 'Paste content to generate a threat fingerprint first.');
    return;
  }

  const text = [
    'Vigil AI Threat Fingerprint',
    'Mode: ' + modeCopy[currentMode].label,
    'Input type: ' + latestFingerprint.inputType,
    'Likely campaign: ' + latestFingerprint.campaign,
    'Target lure: ' + latestFingerprint.target,
    'Link hygiene: ' + latestFingerprint.hygiene,
    'Risk scores: social ' + latestFingerprint.scores.social + ', domain ' + latestFingerprint.scores.domain + ', credential ' + latestFingerprint.scores.credential + ', malware ' + latestFingerprint.scores.malware
  ].join('\n');

  navigator.clipboard.writeText(text).then(() => {
    renderInfoState('Fingerprint copied', 'The local threat profile is now on your clipboard.');
  }).catch(() => {
    renderInfoState('Clipboard unavailable', 'Your browser blocked clipboard access.');
  });
}

function clearWorkbench() {
  scanInput.value = '';
  latestScanResult = null;
  saveReportBtn.disabled = true;
  renderFingerprint(analyzeInputLocal(''));
  renderInfoState('Workbench cleared', 'Paste suspicious content to start another analysis.');
}

function setupRevealAnimations() {
  const revealElements = Array.from(document.querySelectorAll('.reveal'));
  revealElements.forEach((element, index) => {
    element.style.transitionDelay = `${Math.min(index * 40, 300)}ms`;
  });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  revealElements.forEach((element) => observer.observe(element));
}

function applyMode(mode) {
  currentMode = mode;
  Array.from(modeSwitches.querySelectorAll('.mode-chip')).forEach((button) => {
    button.classList.toggle('active', button.dataset.mode === mode);
  });
  renderFingerprint(analyzeInputLocal(scanInput.value));
}

modeSwitches.addEventListener('click', (event) => {
  const button = event.target.closest('[data-mode]');
  if (!button) return;
  applyMode(button.dataset.mode);
});

scanInput.addEventListener('input', () => renderFingerprint(analyzeInputLocal(scanInput.value)));
scanInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) doScan();
});

Array.from(document.querySelectorAll('[data-example]')).forEach((button) => {
  button.addEventListener('click', () => {
    scanInput.value = button.dataset.example;
    renderFingerprint(analyzeInputLocal(scanInput.value));
    renderInfoState('Example loaded', 'Run the scan to compare API verdict with local fingerprint.');
  });
});

scanBtn.addEventListener('click', doScan);
saveReportBtn.addEventListener('click', saveReport);
copyFingerprintBtn.addEventListener('click', copyInputFingerprint);
clearWorkbenchBtn.addEventListener('click', clearWorkbench);
waitlistBtn.addEventListener('click', joinWaitlist);
refreshIntelBtn.addEventListener('click', loadIntel);

document.getElementById('motionToggle').addEventListener('click', (event) => {
  const btn = event.target.closest('[data-motion]');
  if (!btn) return;
  const mode = btn.dataset.motion;
  document.body.classList.remove('motion-subtle', 'motion-bold');
  if (mode === 'subtle') document.body.classList.add('motion-subtle');
  if (mode === 'bold') document.body.classList.add('motion-bold');
  Array.from(document.querySelectorAll('.motion-btn')).forEach((b) => {
    b.classList.toggle('active', b.dataset.motion === mode);
  });
  try { localStorage.setItem('vigil-motion', mode); } catch (_) {}
});

try {
  const saved = localStorage.getItem('vigil-motion');
  if (saved && saved !== 'balanced') {
    document.body.classList.add(saved === 'subtle' ? 'motion-subtle' : 'motion-bold');
    const saved_btn = document.querySelector(`[data-motion="${saved}"]`);
    if (saved_btn) {
      Array.from(document.querySelectorAll('.motion-btn')).forEach((b) => b.classList.toggle('active', b === saved_btn));
    }
  }
} catch (_) {}

applyMode('deep');
renderFingerprint(analyzeInputLocal(''));
setupRevealAnimations();

// Wake-up detection and keep-alive for Render free tier
(function initWakeUp() {
  const banner = document.getElementById('wakeUpBanner');
  const msg = document.getElementById('wakeUpMsg');
  let wakeTimer = null;
  let elapsed = 0;

  const messages = [
    'Free hosting takes ~20\u202fseconds on first visit. Hang tight.',
    'Still waking up\u2026 almost there.',
    'Taking a little longer than usual\u2014 server loading.',
    'Nearly ready. Thanks for your patience.'
  ];

  function showBanner() {
    banner.hidden = false;
    wakeTimer = setInterval(() => {
      elapsed += 5;
      const idx = Math.min(Math.floor(elapsed / 10), messages.length - 1);
      msg.textContent = messages[idx];
    }, 5000);
  }

  function hideBanner() {
    banner.hidden = true;
    clearInterval(wakeTimer);
  }

  // Show banner only if health takes > 2 seconds
  const slowTimer = setTimeout(showBanner, 2000);

  fetch('/api/health', { cache: 'no-store' })
    .then(() => {
      clearTimeout(slowTimer);
      hideBanner();
      loadIntel();
    })
    .catch(() => {
      clearTimeout(slowTimer);
      hideBanner();
      loadIntel();
    });

  // Keep-alive: ping health every 8 minutes while page is open
  setInterval(() => {
    fetch('/api/health', { cache: 'no-store' }).catch(() => {});
  }, 8 * 60 * 1000);
})();
