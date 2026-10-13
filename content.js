(() => {
  const BANNER_ID = 'agentshield-warning-banner';
  const CHECK_DELAY_MS = 650;
  const MAX_TEXT_CHARS = 12000;
  const MAX_LINKS = 12;

  function sanitizeText(value) {
    return String(value || '')
      .replace(/\s+/g, ' ')
      .replace(/[\u0000-\u001f\u007f]/g, ' ')
      .replace(/(password|passphrase|api[_-]?key|auth[_-]?token|session[_-]?id|cookie|jwt)[\s:=]+[A-Za-z0-9._~+/-]+=*/gi, '$1=[redacted]')
      .replace(/(?:Bearer\s+)[A-Za-z0-9\-._~+/]+=*/gi, '[redacted]')
      .trim()
      .slice(0, MAX_TEXT_CHARS);
  }

  function sanitizeUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) {
      return '';
    }

    try {
      const parsed = new URL(raw);
      return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : raw;
    } catch {
      return raw;
    }
  }

  function buildPageSnapshot({ url = '', text = '', links = [] } = {}) {
    const safeUrl = sanitizeUrl(url);
    const safeText = sanitizeText(text);
    const safeLinks = Array.isArray(links) ? links.slice(0, MAX_LINKS).map((link) => {
      const item = link || {};
      const href = sanitizeUrl(item.url);
      const label = sanitizeText(item.text).slice(0, 1200);

      if (!href || /^javascript:|^data:|^mailto:|^tel:/i.test(href)) {
        return null;
      }

      return {
        text: label,
        url: href,
      };
    }).filter(Boolean) : [];

    return {
      url: safeUrl,
      text: safeText,
      links: safeLinks,
    };
  }

  function collectPageSnapshot() {
    if (typeof document === 'undefined' || !document.body) {
      return { url: '', text: '', links: [] };
    }

    const rawLinks = Array.from(document.querySelectorAll('a[href]')).slice(0, MAX_LINKS).map((link) => ({
      text: link.textContent || '',
      url: link.href || '',
    }));

    return buildPageSnapshot({
      url: window.location.href,
      text: document.body.innerText || '',
      links: rawLinks,
    });
  }

  function buildWarningSignature(result) {
    const indicators = Array.isArray(result?.indicators) ? result.indicators : [];
    return `${result?.status || 'not_analyzed'}|${result?.risk_score ?? 0}|${indicators.map((indicator) => `${indicator.type}:${indicator.severity}`).join(',')}|${result?.summary || ''}`;
  }

  function resolveAnalysisResult(remoteResult, fallbackResult) {
    if (remoteResult && typeof remoteResult === 'object' && remoteResult.status) {
      return remoteResult;
    }
    return fallbackResult;
  }

  function shouldRenderWarning(result, state) {
    if (!result || !Array.isArray(result.indicators) || result.indicators.length === 0) {
      return false;
    }

    if (!['high_risk', 'suspicious'].includes(result.status)) {
      return false;
    }

    const key = buildWarningSignature(result);
    if (state.lastWarningKey && state.lastWarningKey === key) {
      return false;
    }

    state.lastWarningKey = key;
    return true;
  }

  function buildBanner(result) {
    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.setAttribute('role', 'alert');
    banner.style.position = 'fixed';
    banner.style.top = '12px';
    banner.style.right = '12px';
    banner.style.zIndex = '2147483647';
    banner.style.maxWidth = '360px';
    banner.style.padding = '12px 14px';
    banner.style.borderRadius = '12px';
    banner.style.background = '#111827';
    banner.style.color = '#f8fafc';
    banner.style.border = '1px solid rgba(148, 163, 184, 0.4)';
    banner.style.boxShadow = '0 12px 28px rgba(15, 23, 42, 0.2)';
    banner.style.fontFamily = 'Arial, sans-serif';
    banner.style.fontSize = '13px';
    banner.style.lineHeight = '1.5';
    banner.style.boxSizing = 'border-box';

    const heading = document.createElement('div');
    const riskLabel = (result?.risk_level || 'low').toString().replace(/_/g, ' ');
    heading.textContent = `AgentShield warning · ${riskLabel}`;
    heading.style.fontWeight = '700';
    heading.style.marginBottom = '4px';

    const summary = document.createElement('div');
    summary.textContent = result.summary || 'Potentially suspicious content detected.';
    summary.style.marginBottom = '8px';

    const list = document.createElement('ul');
    list.style.margin = '0 0 10px';
    list.style.paddingLeft = '18px';
    list.style.color = '#e2e8f0';
    (result.indicators || []).slice(0, 3).forEach((indicator) => {
      const item = document.createElement('li');
      item.textContent = `${indicator.type || 'indicator'}: ${indicator.explanation || indicator.evidence || 'Suspicious pattern detected.'}`;
      list.appendChild(item);
    });

    const details = document.createElement('div');
    details.hidden = true;
    details.style.marginBottom = '10px';
    details.style.paddingTop = '8px';
    details.style.borderTop = '1px solid rgba(148, 163, 184, 0.4)';
    details.style.color = '#cbd5e1';

    const detailText = document.createElement('div');
    detailText.textContent = 'This page contains language or links that resemble phishing or scam patterns. AgentShield is flagging it as a risk signal, not as a confirmed scam.';
    details.appendChild(detailText);

    const actionRow = document.createElement('div');
    actionRow.style.display = 'flex';
    actionRow.style.gap = '8px';
    actionRow.style.flexWrap = 'wrap';

    const dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.textContent = 'Dismiss';
    dismiss.style.background = 'transparent';
    dismiss.style.border = '1px solid rgba(148, 163, 184, 0.4)';
    dismiss.style.color = '#f8fafc';
    dismiss.style.borderRadius = '8px';
    dismiss.style.padding = '6px 10px';
    dismiss.style.cursor = 'pointer';
    dismiss.addEventListener('click', () => banner.remove());

    const whyButton = document.createElement('button');
    whyButton.type = 'button';
    whyButton.textContent = 'Why am I seeing this?';
    whyButton.style.background = '#1d4ed8';
    whyButton.style.border = '1px solid #1d4ed8';
    whyButton.style.color = '#f8fafc';
    whyButton.style.borderRadius = '8px';
    whyButton.style.padding = '6px 10px';
    whyButton.style.cursor = 'pointer';
    whyButton.addEventListener('click', () => {
      details.hidden = !details.hidden;
      whyButton.textContent = details.hidden ? 'Why am I seeing this?' : 'Hide details';
    });

    actionRow.appendChild(dismiss);
    actionRow.appendChild(whyButton);

    banner.appendChild(heading);
    banner.appendChild(summary);
    banner.appendChild(list);
    banner.appendChild(details);
    banner.appendChild(actionRow);
    return banner;
  }

  function maybeShowWarning(payload, state = { lastWarningKey: '' }) {
    const result = globalThis.AgentShieldDetector?.analyzePage?.(payload);
    if (!result || !Array.isArray(result.indicators) || result.indicators.length === 0) {
      const existing = document.getElementById(BANNER_ID);
      if (existing) {
        existing.remove();
      }
      return null;
    }

    if (!shouldRenderWarning(result, state)) {
      return null;
    }

    const existing = document.getElementById(BANNER_ID);
    if (existing) {
      existing.remove();
    }

    if (result.status === 'high_risk' || result.status === 'suspicious') {
      const banner = buildBanner(result);
      if (document.body) {
        document.body.appendChild(banner);
      }
      return result;
    }

    return null;
  }

  function scanPage(state) {
    if (typeof document === 'undefined' || !document.body) {
      return null;
    }

    const protocol = document.location?.protocol || '';
    if (protocol.startsWith('chrome:') || protocol.startsWith('chrome-extension:') || protocol.startsWith('moz-extension:') || protocol.startsWith('about:')) {
      return null;
    }

    const payload = collectPageSnapshot();
    return maybeShowWarning(payload, state);
  }

  function scheduleScan(state) {
    if (state.timeoutId) {
      clearTimeout(state.timeoutId);
    }

    state.timeoutId = setTimeout(() => {
      scanPage(state);
    }, CHECK_DELAY_MS);
  }

  function startMonitoring() {
    if (typeof document === 'undefined') {
      return;
    }

    const state = { timeoutId: null, lastWarningKey: '' };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => scheduleScan(state), { once: true });
    } else {
      scheduleScan(state);
    }

    const observer = new MutationObserver(() => scheduleScan(state));
    const root = document.body || document.documentElement;
    if (root) {
      observer.observe(root, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: false,
      });
    }

    return state;
  }

  const runtimeState = startMonitoring();

  const publicApi = {
    sanitizeText,
    sanitizeUrl,
    buildPageSnapshot,
    collectPageSnapshot,
    buildWarningSignature,
    resolveAnalysisResult,
    shouldRenderWarning,
    maybeShowWarning,
    buildBanner,
    scanPage,
    scheduleScan,
    state: runtimeState,
  };

  globalThis.AgentShieldContent = publicApi;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = publicApi;
  }
})();
