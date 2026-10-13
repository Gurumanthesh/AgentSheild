const extensionAPI = globalThis.browser || globalThis.chrome;
const storageAPI = extensionAPI?.storage?.local || extensionAPI?.storage || null;

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

function formatStatusLabel(value) {
  if (!value) return 'Not analyzed';
  return value.replace(/_/g, ' ');
}

async function renderAnalysis() {
  const result = await getStoredData(['lastAnalysis']);
  const analysis = result.lastAnalysis || {
    status: 'not_analyzed',
    risk_score: 0,
    summary: 'No analysis available yet.',
    indicators: [],
    recommendations: [],
  };

  const statusText = document.getElementById('status-text');
  const riskScore = document.getElementById('risk-score');
  const summaryText = document.getElementById('summary-text');
  const indicatorList = document.getElementById('indicator-list');
  const recommendationList = document.getElementById('recommendation-list');

  statusText.textContent = formatStatusLabel(analysis.status);
  riskScore.textContent = analysis.risk_score ?? 0;
  summaryText.textContent = analysis.summary || 'No analysis available yet.';

  indicatorList.innerHTML = (analysis.indicators || []).length
    ? (analysis.indicators || []).map((indicator) => `<li><strong>${indicator.type}</strong> — ${indicator.explanation || indicator.evidence}</li>`).join('')
    : '<li>No indicators available.</li>';

  recommendationList.innerHTML = (analysis.recommendations || []).length
    ? (analysis.recommendations || []).map((rec) => `<li>${rec}</li>`).join('')
    : '<li>No recommendations available.</li>';
}

renderAnalysis();
