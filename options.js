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
  const result = await chrome.storage.local.get(['blockedWords']);
  const blockedWords = Array.isArray(result.blockedWords) && result.blockedWords.length
    ? result.blockedWords
    : ['password', 'secret', 'token', 'api_key'];

  blockedWordsField.value = blockedWords.join(', ');
}

saveButton.addEventListener('click', async () => {
  const words = parseWords(blockedWordsField.value);
  await chrome.storage.local.set({ blockedWords: words });
  statusMessage.textContent = 'Settings saved successfully.';
  chrome.runtime.sendMessage({ type: 'updateStatus', enabled: true });
});

loadSettings();
