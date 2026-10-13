function formatStatusLabel(value) {
  if (!value) return 'Not analyzed';
  return value.replace(/_/g, ' ');
}

async function renderAnalysis() {
  const result = await chrome.storage.local.get(['lastAnalysis']);
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
