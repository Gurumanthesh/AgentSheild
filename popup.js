const extensionAPI = globalThis.browser || globalThis.chrome;
const storageAPI = extensionAPI?.storage?.local || extensionAPI?.storage || null;
const tabsAPI = extensionAPI?.tabs || null;
const runtimeAPI = extensionAPI?.runtime || null;
const scriptingAPI = extensionAPI?.scripting || null;

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

const stateLabel = document.getElementById('state-label');
const riskScore = document.getElementById('risk-score');
const summaryText = document.getElementById('summary-text');
const pageHost = document.getElementById('page-host');
const pageUrl = document.getElementById('page-url');
const alertCount = document.getElementById('alert-count');
const lastCheck = document.getElementById('last-check');
const statusBox = document.getElementById('status-box');

function formatStatus(value) {
  if (!value) return 'Not analyzed';
  return value.replace(/_/g, ' ');
}

function renderResult(result) {
  const safeStatus = result?.status || 'not_analyzed';
  stateLabel.textContent = formatStatus(safeStatus);
  riskScore.textContent = String(result?.risk_score ?? 0);
  summaryText.textContent = result?.summary || 'The page has not been checked yet.';
  alertCount.textContent = String(Array.isArray(result?.indicators) ? result.indicators.length : 0);

  const timestamp = result?.analyzed_at ? new Date(result.analyzed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
  lastCheck.textContent = timestamp;

  statusBox.classList.remove('status-neutral', 'status-safe', 'status-warn', 'status-danger');
  if (safeStatus === 'high_risk') {
    statusBox.classList.add('status-danger');
  } else if (safeStatus === 'suspicious') {
    statusBox.classList.add('status-warn');
  } else if (safeStatus === 'no_suspicious_indicators_detected') {
    statusBox.classList.add('status-safe');
  } else {
    statusBox.classList.add('status-neutral');
  }
}

async function loadCurrentTabInfo() {
  const queryTabs = tabsAPI?.query ? tabsAPI.query.bind(tabsAPI) : null;
  const [tab] = queryTabs ? await queryTabs({ active: true, currentWindow: true }) : [];
  const url = tab?.url || '';
  if (url) {
    try {
      const parsed = new URL(url);
      pageHost.textContent = parsed.hostname || 'Local page';
      pageUrl.textContent = parsed.href;
    } catch {
      pageHost.textContent = 'Local page';
      pageUrl.textContent = url;
    }
  } else {
    pageHost.textContent = 'Not available';
    pageUrl.textContent = 'Could not resolve the current tab.';
  }

  const stored = await getStoredData(['lastAnalysis', 'lastAnalyzedUrl']);
  if (stored.lastAnalysis && stored.lastAnalyzedUrl === url) {
    renderResult(stored.lastAnalysis);
  } else {
    renderResult({ status: 'not_analyzed', risk_score: 0, summary: 'The page has not been checked yet.', indicators: [] });
  }
}

async function analyzeCurrentPage() {
  const queryTabs = tabsAPI?.query ? tabsAPI.query.bind(tabsAPI) : null;
  const [tab] = queryTabs ? await queryTabs({ active: true, currentWindow: true }) : [];
  if (!tab || !tab.id) {
    renderResult({ status: 'analysis_unavailable', risk_score: 0, summary: 'The active tab could not be inspected.', indicators: [] });
    return;
  }

  stateLabel.textContent = 'Analyzing';
  summaryText.textContent = 'Inspecting page content and links...';
  riskScore.textContent = '…';
  statusBox.classList.remove('status-neutral', 'status-safe', 'status-warn', 'status-danger');
  statusBox.classList.add('status-neutral');

  try {
    const executeScript = scriptingAPI?.executeScript ? scriptingAPI.executeScript.bind(scriptingAPI) : null;
    const scriptResult = executeScript
      ? await executeScript({
          target: { tabId: tab.id },
          func: () => {
            const text = document.body ? document.body.innerText.slice(0, 12000) : '';
            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 20).map((link) => ({
              text: link.textContent ? link.textContent.trim() : '',
              url: link.href,
            }));
            return {
              url: window.location.href,
              text,
              links,
            };
          },
        })
      : [{ result: { url: tab.url || '', text: '', links: [] } }];

    const response = runtimeAPI && typeof runtimeAPI.sendMessage === 'function'
      ? await runtimeAPI.sendMessage({
          type: 'REQUEST_ANALYSIS',
          payload: scriptResult[0]?.result || { url: tab.url || '', text: '', links: [] },
        })
      : null;

    renderResult(response || { status: 'analysis_unavailable', risk_score: 0, summary: 'The page could not be analyzed from this tab.', indicators: [] });
  } catch (error) {
    console.error('Page analysis failed', error);
    renderResult({ status: 'analysis_unavailable', risk_score: 0, summary: 'The page could not be analyzed from this tab.', indicators: [] });
  }
}

document.getElementById('analyze-button').addEventListener('click', analyzeCurrentPage);
document.getElementById('details-button').addEventListener('click', () => {
  const analysisUrl = runtimeAPI && typeof runtimeAPI.getURL === 'function' ? runtimeAPI.getURL('analysis.html') : 'analysis.html';
  if (tabsAPI && typeof tabsAPI.create === 'function') {
    tabsAPI.create({ url: analysisUrl });
    return;
  }
  window.open(analysisUrl, '_blank');
});
document.getElementById('options-link').addEventListener('click', () => {
  if (runtimeAPI && typeof runtimeAPI.openOptionsPage === 'function') {
    runtimeAPI.openOptionsPage();
    return;
  }
  if (tabsAPI && typeof tabsAPI.create === 'function') {
    tabsAPI.create({ url: (runtimeAPI && typeof runtimeAPI.getURL === 'function') ? runtimeAPI.getURL('options.html') : 'options.html' });
  }
});

loadCurrentTabInfo();
