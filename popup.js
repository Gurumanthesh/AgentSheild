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
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
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

  const stored = await chrome.storage.local.get(['lastAnalysis', 'lastAnalyzedUrl']);
  if (stored.lastAnalysis && stored.lastAnalyzedUrl === url) {
    renderResult(stored.lastAnalysis);
  } else {
    renderResult({ status: 'not_analyzed', risk_score: 0, summary: 'The page has not been checked yet.', indicators: [] });
  }
}

async function analyzeCurrentPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
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
    const [{ result }] = await chrome.scripting.executeScript({
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
    });

    const response = await chrome.runtime.sendMessage({
      type: 'REQUEST_ANALYSIS',
      payload: result,
    });

    renderResult(response);
  } catch (error) {
    console.error('Page analysis failed', error);
    renderResult({ status: 'analysis_unavailable', risk_score: 0, summary: 'The page could not be analyzed from this tab.', indicators: [] });
  }
}

document.getElementById('analyze-button').addEventListener('click', analyzeCurrentPage);
document.getElementById('details-button').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('analysis.html') });
});
document.getElementById('options-link').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

loadCurrentTabInfo();
