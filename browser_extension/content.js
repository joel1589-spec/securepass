const SP_STATE = new WeakMap();

function isWeakPassword(password) {
  if (!password) return true;
  let score = 0;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  return score < 4;
}

function sendMessage(payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(payload, (res) => resolve(res || { ok: false, message: 'SecurePass ne répond pas' }));
  });
}

function setPasswordValue(input, password) {
  input.value = password;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function findLoginNear(passwordInput) {
  const form = passwordInput.form || document;
  const selectors = [
    'input[type="email"]',
    'input[name*=email i]',
    'input[name*=user i]',
    'input[id*=email i]',
    'input[id*=user i]',
    'input[type="text"]'
  ];
  for (const sel of selectors) {
    const el = form.querySelector(sel);
    if (el && el.value && el !== passwordInput) return el.value.trim();
  }
  return '';
}

async function autosaveFromField(input) {
  const password = input.value || '';
  if (password.length < 4) return;
  const login = findLoginNear(input);
  const res = await sendMessage({
    action: 'autosaveCredential',
    site: location.hostname,
    login,
    password
  });
  if (res.ok) {
    showMiniNotice('Identifiant sauvegardé dans le coffre SecurePass.');
  }
}

function showMiniNotice(text) {
  const n = document.createElement('div');
  n.textContent = text;
  n.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:2147483647;background:#052e1a;color:#bbf7d0;border:1px solid #16a34a;padding:10px 12px;border-radius:12px;font-family:Arial,sans-serif;box-shadow:0 12px 35px #0008';
  document.body.appendChild(n);
  setTimeout(()=>n.remove(), 3500);
}

function removeBox() {
  const old = document.getElementById('sp-box');
  if (old) old.remove();
}

function showBox(input, text, mode = 'initial') {
  removeBox();
  const box = document.createElement('div');
  box.id = 'sp-box';
  box.style.cssText = `
    position: fixed; right: 20px; top: 20px; z-index: 2147483647;
    background: #07111f; color: white; border: 1px solid #16a34a;
    border-radius: 14px; padding: 14px; width: 330px; font-family: Arial, sans-serif;
    box-shadow: 0 20px 70px #0008; line-height: 1.35;
  `;
  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
      <b style="color:#22c55e">SecurePass</b>
      <button id="spClose" style="background:transparent;color:#94a3b8;border:0;font-size:18px;cursor:pointer">×</button>
    </div>
    <p style="color:#cbd5e1;margin:12px 0">${text}</p>
    <button id="spYes" style="background:#16a34a;color:white;border:0;padding:10px 12px;border-radius:10px;margin-right:8px;font-weight:700;cursor:pointer">Générer</button>
    <button id="spNo" style="background:#334155;color:white;border:0;padding:10px 12px;border-radius:10px;cursor:pointer">Ignorer</button>
    <p id="spMsg" style="color:#fca5a5;margin:10px 0 0;font-size:13px"></p>
  `;
  document.body.appendChild(box);

  document.getElementById('spClose').onclick = () => box.remove();
  document.getElementById('spNo').onclick = () => {
    const state = SP_STATE.get(input) || {};
    state.initialIgnored = true;
    SP_STATE.set(input, state);
    box.remove();
  };
  document.getElementById('spYes').onclick = async () => {
    const msg = document.getElementById('spMsg');
    msg.textContent = 'Génération en cours...';
    const res = await sendMessage({ action: 'generateSecurePass', length: 18 });
    if (res.ok && res.password) {
      setPasswordValue(input, res.password);
      autosaveFromField(input);
      const state = SP_STATE.get(input) || {};
      state.generatedBySecurePass = true;
      state.warnedWeak = true;
      SP_STATE.set(input, state);
      box.remove();
    } else {
      msg.textContent = res.message || 'Erreur SecurePass';
    }
  };
}

async function checkAccessSilently() {
  const res = await sendMessage({ action: 'checkAccess' });
  return res;
}

function attach(input) {
  if (input.dataset.securepassV38 === '1') return;
  input.dataset.securepassV38 = '1';
  SP_STATE.set(input, { initialIgnored: false, warnedWeak: false, timer: null });

  input.addEventListener('focus', async () => {
    const state = SP_STATE.get(input) || {};
    if (state.initialPromptShown) return;
    state.initialPromptShown = true;
    SP_STATE.set(input, state);

    const access = await checkAccessSilently();
    if (!access.ok) {
      showBox(input, access.message || 'Votre plan ne permet pas l’extension SecurePass. Passez en Pro ou Enterprise.');
      return;
    }
    showBox(input, 'Voulez-vous utiliser SecurePass pour générer un mot de passe fort ?');
  });

  if (input.form && !input.form.dataset.securepassAutosave) {
    input.form.dataset.securepassAutosave = '1';
    input.form.addEventListener('submit', () => {
      const pwd = input.form.querySelector('input[type="password"]');
      if (pwd && pwd.value) autosaveFromField(pwd);
    }, true);
  }

  input.addEventListener('blur', () => {
    if ((input.value || '').length >= 6) autosaveFromField(input);
  });

  input.addEventListener('input', () => {
    const state = SP_STATE.get(input) || {};
    clearTimeout(state.timer);

    state.timer = setTimeout(async () => {
      const current = input.value || '';
      if (state.generatedBySecurePass) return;
      if (current.length < 6) return;
      if (state.warnedWeak && state.lastWarnedValue === current) return;

      const access = await checkAccessSilently();
      if (!access.ok) return;

      if (isWeakPassword(current)) {
        state.warnedWeak = true;
        state.lastWarnedValue = current;
        SP_STATE.set(input, state);
        showBox(input, 'Mot de passe faible détecté. Voulez-vous que SecurePass génère un mot de passe fort ?', 'weak');
      }
    }, 900);

    SP_STATE.set(input, state);
  });
}

function injectSecurePass() {
  document.querySelectorAll('input[type="password"]').forEach(attach);
}

injectSecurePass();
setInterval(injectSecurePass, 1500);
