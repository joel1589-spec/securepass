const DEFAULT_API = 'http://127.0.0.1:5000';

function normalizeApi(api) {
  return (api || DEFAULT_API).replace(/\/$/, '');
}

async function apiFetch(path, options = {}) {
  const stored = await chrome.storage.local.get(['api', 'token']);
  const api = normalizeApi(stored.api);
  const token = stored.token;
  if (!token) {
    throw new Error('Connectez d’abord l’extension à SecurePass.');
  }
  const headers = Object.assign({
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  }, options.headers || {});
  const res = await fetch(api + path, Object.assign({}, options, { headers }));
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    throw new Error(data.message || 'Action refusée par SecurePass.');
  }
  return data;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.action === 'checkAccess') {
        const data = await apiFetch('/api/extension/config', { method: 'GET' });
        sendResponse({ ok: true, plan: data.plan, message: data.message || 'Extension autorisée' });
        return;
      }

      if (msg.action === 'generateSecurePass') {
        await apiFetch('/api/extension/config', { method: 'GET' });
        const data = await apiFetch('/api/extension/generate', {
          method: 'POST',
          body: JSON.stringify({ length: msg.length || 18 })
        });
        sendResponse({ ok: true, password: data.password });
        return;
      }

      if (msg.action === 'autosaveCredential') {
        await apiFetch('/api/extension/config', { method: 'GET' });
        const data = await apiFetch('/api/extension/autosave', {
          method: 'POST',
          body: JSON.stringify({ site: msg.site, login: msg.login, password: msg.password })
        });
        sendResponse({ ok: true, message: data.message, score: data.score });
        return;
      }

      sendResponse({ ok: false, message: 'Action inconnue' });
    } catch (e) {
      sendResponse({ ok: false, message: e.message || 'Erreur SecurePass' });
    }
  })();
  return true;
});
