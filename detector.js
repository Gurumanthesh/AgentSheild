(function (global) {
  const URGENT_PATTERNS = [
    'act now',
    'immediately',
    'within 24 hours',
    'today only',
    'urgent',
    'final warning',
    'do not delay',
  ];

  const CREDENTIAL_PATTERNS = [
    'otp',
    'one time password',
    'recovery code',
    'bank login',
    'bank account details',
    'password',
    'verify your account',
    'security check',
  ];

  const FINANCIAL_PATTERNS = [
    'refund',
    'invoice',
    'payment required',
    'wire transfer',
    'bank transfer',
    'claim your payout',
    'unexpected payment',
  ];

  const PRIZE_PATTERNS = [
    'you won',
    'free prize',
    'lucky winner',
    'claim your reward',
    'bonus winner',
    'cash giveaway',
  ];

  const IMPERSONATION_PATTERNS = [
    'bank of america',
    'paypal security',
    'apple support',
    'google support',
    'microsoft support',
    'amazon account',
    'official notice',
  ];

  const SHORTENER_HOSTS = [
    'bit.ly',
    'tinyurl.com',
    'goo.gl',
    't.co',
    'ow.ly',
    'is.gd',
    'tiny.cc',
    'rebrand.ly',
  ];

  function isoNow() {
    return new Date().toISOString();
  }

  function addIndicator(indicators, type, severity, evidence, explanation) {
    indicators.push({
      type,
      severity,
      evidence,
      explanation,
    });
  }

  function scoreUrl(url) {
    let score = 0;
    const indicators = [];
    if (!url) return { score, indicators };

    const lowered = url.toLowerCase();
    if (/(?:\d{1,3}\.){3}\d{1,3}/.test(lowered)) {
      score += 20;
      addIndicator(indicators, 'url_obfuscation', 'high', 'IP-address format appears in the URL.', 'IP-based destinations can be used to hide a real service domain.');
    }

    if (SHORTENER_HOSTS.some((host) => lowered.includes(host))) {
      score += 15;
      addIndicator(indicators, 'shortened_link', 'medium', 'Shortened link host detected.', 'Short links can hide the final destination and should be verified carefully.');
    }

    if (/(?:javascript:|data:|vbscript:)/.test(lowered)) {
      score += 25;
      addIndicator(indicators, 'unsafe_scheme', 'high', 'The link uses a script-like URL scheme.', 'URLs using javascript: or data: are often used for deceptive or malicious behavior.');
    }

    return { score: Math.min(score, 60), indicators };
  }

  function analyzePage(page) {
    const text = (page && page.text) ? String(page.text).trim() : '';
    const url = (page && page.url) ? String(page.url).trim() : '';
    const links = Array.isArray(page && page.links) ? page.links : [];
    const lowerText = text.toLowerCase();
    const indicators = [];
    let score = 0;

    if (!text && !url && links.length === 0) {
      return {
        status: 'not_analyzed',
        risk_score: 0,
        risk_level: 'low',
        summary: 'No content available to analyze.',
        indicators: [],
        recommendations: [
          'Open a page or provide a URL and text to evaluate.',
          'Use the extension to inspect the active page content.',
        ],
        analyzed_at: isoNow(),
        engine: 'local-heuristics',
      };
    }

    for (const pattern of URGENT_PATTERNS) {
      if (lowerText.includes(pattern)) {
        score += 15;
        addIndicator(indicators, 'urgency', 'medium', `Urgent language found: ${pattern}.`, 'Time-pressure language can cause users to act before verifying the source.');
        break;
      }
    }

    for (const pattern of CREDENTIAL_PATTERNS) {
      if (lowerText.includes(pattern)) {
        score += 18;
        addIndicator(indicators, 'credential_request', 'high', `Sensitive-information language found: ${pattern}.`, 'Requests for passwords, OTPs, or recovery codes are common scam patterns.');
        break;
      }
    }

    for (const pattern of FINANCIAL_PATTERNS) {
      if (lowerText.includes(pattern)) {
        score += 12;
        addIndicator(indicators, 'financial_pressure', 'medium', `Financial language detected: ${pattern}.`, 'Unexpected payment or refund demands can be a sign of fraud.');
        break;
      }
    }

    for (const pattern of PRIZE_PATTERNS) {
      if (lowerText.includes(pattern)) {
        score += 18;
        addIndicator(indicators, 'prize_scam', 'high', `Prize claim language detected: ${pattern}.`, 'Unexpected winnings claims often lead to requests for a fee or private details.');
        break;
      }
    }

    for (const pattern of IMPERSONATION_PATTERNS) {
      if (lowerText.includes(pattern)) {
        score += 16;
        addIndicator(indicators, 'impersonation_language', 'high', `Impersonation pattern matched: ${pattern}.`, 'Scammers often impersonate banks or major platforms to gain trust quickly.');
        break;
      }
    }

    if (/(suspend|locked|deactivated|verify now|immediate action)/.test(lowerText)) {
      score += 12;
      addIndicator(indicators, 'account_security', 'medium', 'Account-security warning language detected.', 'Urgent account warnings can be used to pressure a user into clicking a deceptive link.');
    }

    const urlResult = scoreUrl(url);
    score += urlResult.score;
    indicators.push(...urlResult.indicators);

    for (const link of links.slice(0, 10)) {
      if (!link || !link.url) continue;
      const href = String(link.url).toLowerCase();
      const visibleText = String(link.text || '').toLowerCase();
      if (SHORTENER_HOSTS.some((host) => href.includes(host))) {
        score += 10;
        addIndicator(indicators, 'shortened_link', 'medium', `Shortened destination found: ${link.url}.`, 'Shortened URLs hide the final destination and should be checked carefully.');
      }

      if (visibleText && link.url && visibleText !== href && /(verify|login|secure|update|alert)/.test(visibleText)) {
        score += 8;
        addIndicator(indicators, 'link_text_mismatch', 'medium', 'The visible link text does not match the destination purpose.', 'Mismatched link text can be a tactic to make a malicious destination appear trustworthy.');
      }
    }

    const deduped = [];
    const seen = new Set();
    for (const indicator of indicators) {
      const key = `${indicator.type}|${indicator.severity}|${indicator.evidence}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(indicator);
      }
    }

    score = Math.max(0, Math.min(score, 100));

    let status = 'no_suspicious_indicators_detected';
    let summary = 'No suspicious indicators detected.';
    let riskLevel = 'low';

    if (score >= 75) {
      status = 'high_risk';
      summary = 'High-risk indicators suggest a potentially dangerous page or message.';
      riskLevel = 'critical';
    } else if (score >= 45) {
      status = 'suspicious';
      summary = 'Several suspicious indicators were detected. Verify the page before taking action.';
      riskLevel = 'medium';
    } else if (score > 0) {
      status = 'suspicious';
      summary = 'Minor suspicious indicators were detected. Review before proceeding.';
      riskLevel = 'low';
    }

    const recommendations = [
      'Verify the sender or site through an official channel before entering credentials.',
      'Do not click links from urgent or pressure-based messaging without confirming the destination.',
    ];
    if (deduped.length > 0) {
      recommendations.unshift('Review the risk explanations above before entering sensitive information.');
    }

    return {
      status,
      risk_score: score,
      risk_level: riskLevel,
      summary,
      indicators: deduped,
      recommendations,
      analyzed_at: isoNow(),
      engine: 'local-heuristics',
    };
  }

  global.AgentShieldDetector = { analyzePage };
})(typeof window !== 'undefined' ? window : globalThis);
