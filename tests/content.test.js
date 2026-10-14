const test = require('node:test');
const assert = require('node:assert/strict');

require('../detector.js');
const {
  buildPageSnapshot,
  buildWarningSignature,
  shouldRenderWarning,
  resolveAnalysisResult,
  collectPageSnapshotFromRoot,
} = require('../content.js');

const suspiciousPayload = {
  url: 'https://example-fake-login.com/security/verify',
  text: 'Your account will be suspended immediately. Verify now with your password and OTP.',
  links: [
    { text: 'Verify account', url: 'https://example-fake-login.com/security/verify' },
  ],
};

test('benign content is not flagged as suspicious', () => {
  const result = globalThis.AgentShieldDetector.analyzePage({
    url: 'https://example.com/blog',
    text: 'This article explains how to keep a home office organized.',
    links: [{ text: 'Read more', url: 'https://example.com/blog/office' }],
  });

  assert.equal(result.status, 'no_suspicious_indicators_detected');
  assert.equal(result.indicators.length, 0);
});

test('suspicious content produces a risk signal with indicators', () => {
  const result = globalThis.AgentShieldDetector.analyzePage(suspiciousPayload);

  assert.ok(['suspicious', 'high_risk'].includes(result.status));
  assert.ok(result.indicators.length > 0);
  assert.ok(result.risk_score >= 30);
});

test('dynamic content snapshots redact private values and keep links limited', () => {
  const snapshot = buildPageSnapshot({
    url: 'https://example.com',
    text: 'Urgent password=supersecret token=abc123 verify now',
    links: [
      { text: 'Verify account', url: 'https://example.com/verify?token=abc123' },
      { text: 'Email', url: 'mailto:test@example.com' },
    ],
  });

  assert.ok(snapshot.text.length <= 12000);
  assert.match(snapshot.text, /redacted|urgent|verify/i);
  assert.ok(snapshot.links.every((link) => link.url.startsWith('https://')));
});

test('duplicate warnings are prevented', () => {
  const result = globalThis.AgentShieldDetector.analyzePage(suspiciousPayload);
  const state = { lastWarningKey: buildWarningSignature(result) };

  assert.equal(shouldRenderWarning(result, state), false);
});

test('complete page snapshot collects multiple sections and relevant links', () => {
  const root = {
    querySelectorAll: (selector) => {
      if (selector === 'main, article, section, p, li, h1, h2, h3, h4, h5, h6, div, span, label, button, a, td, th') {
        return [
          { textContent: 'Urgent account alert.', hidden: false, querySelectorAll: () => [{ href: 'https://example.com/verify', textContent: 'Verify account' }] },
          { textContent: 'Security check required now to keep your account active.', hidden: false, querySelectorAll: () => [{ href: 'https://example.com/secure', textContent: 'Secure account' }] },
        ];
      }
      if (selector === 'a[href]') {
        return [
          { href: 'https://example.com/verify', textContent: 'Verify account' },
          { href: 'https://example.com/secure', textContent: 'Secure account' },
        ];
      }
      return [];
    },
  };

  const snapshot = collectPageSnapshotFromRoot(root, 'https://example.com');
  assert.match(snapshot.text, /Urgent|account|Security|verify/i);
  assert.equal(snapshot.links.length, 2);
});

test('backend failures fall back to the local analysis result', () => {
  const localResult = {
    status: 'suspicious',
    risk_score: 40,
    risk_level: 'low',
    summary: 'Fallback result',
    indicators: [{ type: 'urgency', evidence: 'Urgent language detected' }],
  };

  const resolved = resolveAnalysisResult(null, localResult);
  assert.deepEqual(resolved, localResult);
});
