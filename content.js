(() => {
  const BANNER_ID = 'agentshield-warning-banner';
  const CHECK_DELAY_MS = 800;
  let lastRunKey = '';
  let lastBannerText = '';

  function buildBanner(result) {
    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.setAttribute('role', 'alert');
    banner.style.position = 'fixed';
    banner.style.top = '12px';
    banner.style.right = '12px';
    banner.style.zIndex = '2147483647';
    banner.style.maxWidth = '340px';
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

    const title = document.createElement('div');
    title.textContent = 'AgentShield Warning';
    title.style.fontWeight = '700';
    title.style.marginBottom = '4px';

    const text = document.createElement('div');
    text.textContent = result.summary || 'Potentially suspicious content detected.';
    text.style.marginBottom = '8px';

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

    banner.appendChild(title);
    banner.appendChild(text);
    banner.appendChild(dismiss);
    return banner;
  }

  function maybeShowWarning(payload) {
    const result = window.AgentShieldDetector?.analyzePage(payload);
    if (!result || !result.indicators || result.indicators.length === 0) {
      const existing = document.getElementById(BANNER_ID);
      if (existing) existing.remove();
      return;
    }

    const key = `${window.location.href}|${result.status}|${result.risk_score}`;
    if (key === lastRunKey && lastBannerText === result.summary) {
      return;
    }

    lastRunKey = key;
    lastBannerText = result.summary;
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
    if (result.status === 'high_risk' || result.status === 'suspicious') {
      document.body.appendChild(buildBanner(result));
    }
  }

  function scanPage() {
    if (!document.body || document.location.protocol === 'chrome:' || document.location.protocol === 'chrome-extension:') {
      return;
    }

    const text = document.body.innerText || '';
    const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 20).map((link) => ({
      text: link.textContent ? link.textContent.trim() : '',
      url: link.href,
    }));

    const payload = {
      url: window.location.href,
      text: text.slice(0, 12000),
      links,
    };

    maybeShowWarning(payload);
  }

  let timeoutId = null;

  function scheduleScan() {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    timeoutId = setTimeout(scanPage, CHECK_DELAY_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleScan, { once: true });
  } else {
    scheduleScan();
  }

  const observer = new MutationObserver(() => scheduleScan());
  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    characterData: false,
  });
})();
