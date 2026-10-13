const extensionAPI = globalThis.browser || globalThis.chrome;
const storageAPI = extensionAPI?.storage?.local || extensionAPI?.storage || null;
const runtimeAPI = extensionAPI?.runtime || null;

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

const blockedWordsField = document.getElementById('blocked-words');
const saveButton = document.getElementById('save-button');
const statusMessage = document.getElementById('status-message');

function parseWords(rawText) {
  return [...new Set(
    rawText
      .split(/[\n,]+/)
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean)
  )];
}

async function loadSettings() {
  const result = await getStoredData(['blockedWords']);
  const blockedWords = Array.isArray(result.blockedWords) && result.blockedWords.length
    ? result.blockedWords
    : ['password', 'secret', 'token', 'api_key'];

  blockedWordsField.value = blockedWords.join(', ');
}

saveButton.addEventListener('click', async () => {
  const words = parseWords(blockedWordsField.value);
  await setStoredData({ blockedWords: words });
  statusMessage.textContent = 'Settings saved successfully.';

  if (runtimeAPI && typeof runtimeAPI.sendMessage === 'function') {
    await runtimeAPI.sendMessage({ type: 'updateStatus', enabled: true });
  }
});

loadSettings();
