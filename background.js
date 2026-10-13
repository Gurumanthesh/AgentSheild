const extensionAPI = globalThis.browser || globalThis.chrome;
const storageAPI = extensionAPI?.storage?.local || extensionAPI?.storage || null;
const actionAPI = extensionAPI?.action || extensionAPI?.browserAction || null;
const runtimeAPI = extensionAPI?.runtime || null;

const API_BASE_URLS = [
  'https://agentsheild-br.onrender.com',
  'http://127.0.0.1:8000',
];
const API_TIMEOUT_MS = 8000;
const DEFAULT_WORDS = ['password', 'secret', 'token', 'api_key'];

async function getStoredData(keys) {
  if (!storageAPI || typeof storageAPI.get !== 'function') {
    return {};
  }

  const result = storageAPI.get(keys);
  if (result && typeof result.then === 'function') {
    return result;
  }

  return new Promise((resolve, reject) => {
    try {
      storageAPI.get(keys, resolve);
    } catch (error) {
      reject(error);
    }
  });
}

async function setStoredData(data) {
  if (!storageAPI || typeof storageAPI.set !== 'function') {
    return;
  }

  const result = storageAPI.set(data);
  if (result && typeof result.then === 'function') {
    return result;
  }

  return new Promise((resolve, reject) => {
    try {
      storageAPI.set(data, resolve);
    } catch (error) {
      reject(error);
    }
  });
}

function updateBadge(enabled) {
  if (!actionAPI) {
    return;
  }

  if (typeof actionAPI.setBadgeText === 'function') {
    actionAPI.setBadgeText({ text: enabled ? 'ON' : 'OFF' });
  }

  if (typeof actionAPI.setBadgeBackgroundColor === 'function') {
    actionAPI.setBadgeBackgroundColor({ color: enabled ? '#22c55e' : '#6b7280' });
  }
}

function deriveLocalAnalysis(payload) {
  const text = String(payload?.text || '');
  const url = String(payload?.url || '');
  const links = Array.isArray(payload?.links) ? payload.links : [];
  const lowered = text.toLowerCase();
  let score = 0;
  const indicators = [];

  if (!text && !url && links.length === 0) {
    return { status: 'not_analyzed', risk_score: 0, risk_level: 'low', summary: 'No content available to analyze.', indicators: [], recommendations: ['Add page content or a URL to analyze.'], analyzed_at: new Date().toISOString(), engine: 'local-fallback' };
  }

  const keywords = [
    ['urgent', 'Urgent language detected.', 'Time-pressure language can be used to discourage verification.'],
    ['password', 'Sensitive-information language found.', 'Password requests are common in phishing flows.'],
    ['otp', 'OTP or verification code language detected.', 'Attackers often request recovery codes or one-time codes.'],
    ['you won', 'Prize claim language detected.', 'Unexpected prize or giveaway claims often lead to scams.'],
    ['bank', 'Banking or payment language detected.', 'Be cautious with requests involving financial or account details.'],
  ];

  for (const [keyword, evidence, explanation] of keywords) {
    if (lowered.includes(keyword)) {
      score += 15;
      indicators.push({ type: 'keyword_match', severity: 'medium', evidence, explanation });
      break;
    }
  }

  if (/(?:\d{1,3}\.){3}\d{1,3}/.test(url.toLowerCase())) {
    score += 20;
    indicators.push({ type: 'url_obfuscation', severity: 'high', evidence: 'The URL includes an IP address.', explanation: 'IP-based destinations can hide an official service domain.' });
  }

  if (/(?:javascript:|data:|vbscript:)/.test(url.toLowerCase())) {
    score += 25;
    indicators.push({ type: 'unsafe_scheme', severity: 'high', evidence: 'The URL used a script-like scheme.', explanation: 'Unsafe schemes are frequently associated with deceptive links.' });
  }

  if (links.some((link) => link && /bit\.ly|tinyurl|is\.gd|t\.co|goo\.gl/.test(String(link.url || '').toLowerCase()))) {
    score += 12;
    indicators.push({ type: 'shortened_link', severity: 'medium', evidence: 'Shortened link detected.', explanation: 'Shortened links can hide the final destination and should be checked carefully.' });
  }

  score = Math.min(score, 100);

  let status = 'no_suspicious_indicators_detected';
  let riskLevel = 'low';
  let summary = 'No suspicious indicators detected.';

  if (score >= 75) {
    status = 'high_risk';
    riskLevel = 'critical';
    summary = 'High-risk indicators suggest a potentially dangerous page or message.';
  } else if (score >= 45) {
    status = 'suspicious';
    riskLevel = 'medium';
    summary = 'Several suspicious indicators were detected. Verify the page before taking action.';
  } else if (score > 0) {
    status = 'suspicious';
    riskLevel = 'low';
    summary = 'Minor suspicious indicators were detected. Review before proceeding.';
  }

  return {
    status,
    risk_score: score,
    risk_level: riskLevel,
    summary,
    indicators,
    recommendations: [
      'Verify the sender or site through an official channel before entering credentials.',
      'Do not click links from urgent or pressure-based messaging without confirming the destination.',
    ],
    analyzed_at: new Date().toISOString(),
    engine: 'local-fallback',
  };
}

async function analyzePageData(payload) {
  const safePayload = {
    url: String(payload?.url || ''),
    text: String(payload?.text || '').slice(0, 12000),
    links: Array.isArray(payload?.links) ? payload.links.slice(0, 20).map((link) => ({
      text: String(link?.text || '').slice(0, 2000),
      url: String(link?.url || '').slice(0, 2000),
    })) : [],
  };

  let lastError = null;

  for (const baseUrl of API_BASE_URLS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    try {
      const response = await fetch(`${baseUrl}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(safePayload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        const text = await response.text();
        throw new Error(`Non-JSON response from ${baseUrl}: ${text.slice(0, 200)}`);
      }

      const json = await response.json();
      if (json && typeof json === 'object') {
        return json;
      }

      throw new Error(`Empty or invalid JSON payload from ${baseUrl}`);
    } catch (error) {
      lastError = error;
      console.warn(`AgentShield backend request failed for ${baseUrl}. Trying next endpoint if available.`, error);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  console.warn('AgentShield backend unavailable, using local fallback.', lastError);
  return deriveLocalAnalysis(safePayload);
}

async function persistAnalysis(result, url) {
  await setStoredData({
    lastAnalysis: result,
    lastAnalyzedUrl: url,
    analysisTimestamp: Date.now(),
  });
}

async function initializeSettings() {
  const result = await getStoredData(['enabled', 'blockedWords']);
  const enabled = result.enabled !== false;
  const blockedWords = Array.isArray(result.blockedWords) && result.blockedWords.length
    ? result.blockedWords
    : DEFAULT_WORDS;

  await setStoredData({ enabled, blockedWords });
  updateBadge(enabled);
}

if (runtimeAPI && typeof runtimeAPI.onInstalled?.addListener === 'function') {
  runtimeAPI.onInstalled.addListener(() => {
    void initializeSettings();
  });
}

if (runtimeAPI && typeof runtimeAPI.onMessage?.addListener === 'function') {
  runtimeAPI.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === 'updateStatus') {
      updateBadge(Boolean(message.enabled));
      sendResponse({ ok: true });
      return true;
    }

    if (message?.type === 'getStatus') {
      void getStoredData(['enabled']).then((result) => {
        sendResponse({ enabled: result.enabled !== false });
      }).catch(() => {
        sendResponse({ enabled: true });
      });
      return true;
    }

    if (message?.type === 'REQUEST_ANALYSIS') {
      void analyzePageData(message.payload || {}).then(async (result) => {
        await persistAnalysis(result, String(message.payload?.url || ''));
        sendResponse(result);
      }).catch((error) => {
        console.error('Analysis failed', error);
        const fallback = deriveLocalAnalysis(message.payload || {});
        persistAnalysis(fallback, String(message.payload?.url || '')).finally(() => sendResponse(fallback));
      });
      return true;
    }

    sendResponse({ ok: false });
    return false;
  });
}
