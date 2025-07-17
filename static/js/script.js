// script.js

// ─── Global State ──────────────────────────────────────────────────────
let token = null,
    socket = null,
    myKeyPair = null,
    mySignKeyPair = null,
    myECDHKeyPair = null,
    username = null;

const chatHistory = {};   // { peer: [ { from, to, text, timestamp, ... } ] }
const publicKeys   = {};  // RSA publicKey cache
const verifyKeys   = {};  // Signing pubkey cache

// Reference to native fetch (avoid recursion in logout)
const _origFetch = window.fetch.bind(window);


// ─── Wire UI handlers on load ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Registration
  document.getElementById('reg-btn').addEventListener('click', sendOtp);
  document.getElementById('reg-verify-btn').addEventListener('click', confirmRegistration);

  // Login (2FA)
  document.getElementById('login-btn').addEventListener('click', loginStep1);
  document.getElementById('login-verify-btn').addEventListener('click', loginStep2);

  // Forgot-Password (code-only)
  document.getElementById('forgot-link').addEventListener('click', showResetForm);
  document.getElementById('reset-request-btn').addEventListener('click', forgotPassword);
  document.getElementById('reset-confirm-btn').addEventListener('click', confirmReset);

  // Chat & Logout
  document.getElementById('send-btn').addEventListener('click', sendMessage);
  document.getElementById('recipientSelect').addEventListener('change', switchChat);
  document.getElementById('logout-btn').addEventListener('click', logout);

  // Disable send until socket connects
  document.getElementById('send-btn').disabled = true;
});


// ─── 1) REGISTRATION ────────────────────────────────────────────────────
async function sendOtp() {
  const u = document.getElementById('reg-username').value.trim();
  const p = document.getElementById('reg-password').value.trim();
  const e = document.getElementById('reg-email').value.trim();
  const captcha = grecaptcha.getResponse();

  if (!u || !p || !e || !captcha) {
    return alert('All fields + CAPTCHA required');
  }

  try {
    const res = await _origFetch('/auth/pre_register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p, email: e, captcha })
    });

    if (res.ok) {
      alert('✅ OTP sent—check your email');
      document.getElementById('reg').style.display     = 'none';
      document.getElementById('reg-otp').style.display = 'block';
    } else {
      const ct = res.headers.get('Content-Type') || '';
      let errMsg = res.statusText;
      if (ct.includes('application/json')) {
        const data = await res.json().catch(() => ({}));
        errMsg = data.error || JSON.stringify(data);
      } else {
        errMsg = await res.text().catch(() => res.statusText);
      }
      alert(`Error (${res.status}): ${errMsg}`);
      grecaptcha.reset();
    }
  } catch (err) {
    console.error('Send OTP error:', err);
    alert('Network error—could not send OTP');
    grecaptcha.reset();
  }
}

async function confirmRegistration() {
  const u = document.getElementById('reg-username').value.trim();
  const code = document.getElementById('reg-otp-code').value.trim();
  if (!code) {
    return alert('Enter OTP');
  }

  try {
    const res = await _origFetch('/auth/verify_register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, otp: code })
    });
    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      alert('✅ Registered! Please log in.');
      location.reload();
    } else {
      alert(`Error: ${data.error || 'Registration failed'}`);
    }
  } catch (err) {
    console.error('Confirm registration error:', err);
    alert('Registration confirmation failed');
  }
}


// ─── 2) LOGIN WITH OTP ──────────────────────────────────────────────────
async function loginStep1() {
  username = document.getElementById('username').value.trim();
  const p = document.getElementById('password').value.trim();
  if (!username || !p) return alert('Username/password required');

  try {
    const res = await _origFetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: p })
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      return alert(`Error: ${data.error || 'Login failed'}`);
    }

    alert('✅ Login code sent—check your email');
    document.getElementById('login').style.display    = 'none';
    document.getElementById('login-otp').style.display = 'block';
  } catch (err) {
    console.error('Login step1 error:', err);
    alert('Login request failed');
  }
}

async function loginStep2() {
  const code = document.getElementById('login-otp-code').value.trim();
  if (!code) return alert('Enter login code');

  try {
    const res = await _origFetch('/auth/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, otp: code })
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      return alert(`Error: ${data.error || 'Verification failed'}`);
    }

    token = data.token;
    await initializeApp();
  } catch (err) {
    console.error('Login step2 error:', err);
    alert('Verification failed');
  }
}


// ─── 3) FORGOT PASSWORD (code-only) ───────────────────────────────────────
function showResetForm() {
  // Switch tabs to Reset
  document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
  document.querySelector('[data-tab="reset"]').classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('reset').classList.add('active');
}

async function forgotPassword() {
  const u = document.getElementById('reset-username').value.trim();
  const e = document.getElementById('reset-email').value.trim();
  if (!u || !e) return alert('Username + email required');

  try {
    const res  = await _origFetch('/auth/forgot_password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, email: e })
    });
    const data = await res.json().catch(() => ({}));
    alert(data.message || data.error);

    document.getElementById('reset').style.display        = 'none';
    document.getElementById('reset-verify').style.display = 'block';
  } catch (err) {
    console.error('Forgot password error:', err);
    alert('Network error—could not request reset code');
  }
}

async function confirmReset() {
  const u  = document.getElementById('reset-username').value.trim();
  const c  = document.getElementById('reset-code').value.trim();
  const pw = document.getElementById('reset-newpw').value.trim();
  if (!c || !pw) return alert('Code + new password required');

  try {
    const res  = await _origFetch('/auth/reset_password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, code: c, password: pw })
    });
    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      alert('✅ Password reset! Please log in.');
      location.reload();
    } else {
      alert(`Error: ${data.error}`);
    }
  } catch (err) {
    console.error('Reset confirmation error:', err);
    alert('Network error—could not reset password');
  }
}


// ─── 4) AFTER LOGIN: INIT CHAT ─────────────────────────────────────────
async function initializeApp() {
  // auto‐logout on token expiry
  const exp = getTokenExpiration(token);
  if (exp) setTimeout(() => { alert('Session expired'); logout(); }, exp - Date.now());

  // Hide authentication UI
  document.getElementById('auth-section').style.display = 'none';
  // Show chat UI
  document.getElementById('chat-section').classList.remove('hidden');
  document.getElementById('logout-btn').style.display = 'inline-block';

  // Reset in-memory caches
  Object.keys(chatHistory).forEach(k => delete chatHistory[k]);
  Object.keys(publicKeys).forEach(k => delete publicKeys[k]);
  Object.keys(verifyKeys).forEach(k => delete verifyKeys[k]);

  // Generate and register keys, load roster/history, connect socket
  await generateRSAKeys();
  await generateECDHKeys();
  await generateSigningKeys();
  await registerKey();
  await loadRoster();
  await loadChatHistory();
  connectSocket();
}


// ─── 5) UTILITIES: JWT & Fetch ─────────────────────────────────────────
function getTokenExpiration(tkn) {
  try {
    const payload = JSON.parse(atob(tkn.split('.')[1]));
    return payload.exp * 1000;
  } catch {
    return null;
  }
}

async function fetchWithAuth(url, opts = {}) {
  opts.headers = opts.headers || {};
  opts.headers['Authorization'] = `Bearer ${token}`;
  const res = await _origFetch(url, opts);
  if (res.status === 401 && token) {
    await logout();
    alert('Session expired—please log in again.');
  }
  return res;
}


// ─── 6) CHAT SEND & RECEIVE ────────────────────────────────────────────
async function sendMessage() {
  if (!socket || socket.disconnected) {
    return alert('Still connecting… please wait before sending.');
  }

  const text = document.getElementById('message').value.trim();
  const to   = document.getElementById('recipientSelect').value;
  if (!to || !text) return alert('Select a recipient and enter text');

  try {
    const resp = await fetchWithAuth(`/keys/ecdh/${to}`);
    if (!resp.ok) throw new Error('Failed to fetch peer ECDH key');
    const { publicKey: ecdhPublicKey } = await resp.json();

    const recipECDH = await window.crypto.subtle.importKey(
      'spki', base64ToBuffer(ecdhPublicKey),
      { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );

    const eph = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
    );
    const ephPub = bufferToBase64(await window.crypto.subtle.exportKey('spki', eph.publicKey));

    const aesKey = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: recipECDH }, eph.privateKey,
      { name: 'AES-GCM', length: 256 }, true, ['encrypt']
    );

    const encoder = new TextEncoder();
    const dataBuf = encoder.encode(text);
    const sig     = bufferToBase64(await window.crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' }, mySignKeyPair.privateKey, dataBuf
    ));
    const iv      = window.crypto.getRandomValues(new Uint8Array(12));
    const ct      = bufferToBase64(await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, dataBuf
    ));

    const messagePayload = {
      room: 'main', from: username, to,
      ephemeralPubKey: ephPub,
      iv: bufferToBase64(iv),
      ciphertext: ct,
      signature: sig,
      timestamp: new Date().toISOString()
    };

    socket.emit('message', messagePayload);

    await fetchWithAuth('/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(messagePayload)
    });

    if (!chatHistory[to]) chatHistory[to] = [];
    chatHistory[to].push({ from: username, to, text, timestamp: Date.now() });
    switchChat();
    document.getElementById('status').textContent =
      `✉️ Sent to ${to} at ${new Date().toLocaleTimeString()}`;
    document.getElementById('message').value = '';
  } catch (err) {
    console.error('Send message error:', err);
    alert('Failed to send message');
  }
}


// ─── 7) LOAD & DECRYPT CHAT HISTORY ─────────────────────────────────────
async function loadChatHistory() {
  const sel = document.getElementById('recipientSelect');
  for (let opt of sel.options) {
    const peer = opt.value;
    if (!peer) continue;
    chatHistory[peer] = [];

    const resp = await fetchWithAuth(`/messages/${peer}`);
    if (!resp.ok) continue;
    const history = await resp.json();

    for (let record of history) {
      await decryptAndStore(record);
    }
  }
}

async function decryptAndStore(m) {
  try {
    const ephKey = await window.crypto.subtle.importKey(
      'spki', base64ToBuffer(m.ephemeralPubKey),
      { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const aesKey = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephKey },
      myECDHKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      true, ['decrypt']
    );

    const plain = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuffer(m.iv) },
      aesKey,
      base64ToBuffer(m.ciphertext)
    );
    const text = new TextDecoder().decode(plain);

    if (m.signature && m.from !== username) {
      const vk = await getSignVerifyKey(m.from);
      const ok = await window.crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' }, vk,
        base64ToBuffer(m.signature),
        new TextEncoder().encode(text)
      );
      if (!ok) {
        console.warn('Signature invalid, dropping message from', m.from);
        return;
      }
    }

    const peer = (m.from === username) ? m.to : m.from;
    if (!chatHistory[peer]) chatHistory[peer] = [];
    chatHistory[peer].push({
      from:      m.from,
      to:        m.to,
      text,
      timestamp: new Date(m.timestamp).getTime()
    });

    if (document.getElementById('recipientSelect').value === peer) {
      switchChat();
    } else {
      const sel2 = document.getElementById('recipientSelect');
      for (let opt of sel2.options) {
        if (opt.value === m.from && !opt.textContent.startsWith('✉️')) {
          opt.textContent = `✉️ ${opt.value}`;
        }
      }
    }

  } catch (err) {
    console.warn('Decrypt error:', err);
  }
}


// ─── 8) SOCKET.IO ───────────────────────────────────────────────────────
function connectSocket() {
  socket = io('/chat', { auth: { token } });

  socket.on('connect', () => {
    document.getElementById('send-btn').disabled = false;
  });

  socket.on('connect_error', err => {
    console.error('Socket error:', err);
    if (err.message === 'Unauthorized') {
      alert('Socket auth failed; please log in again');
      logout();
    }
  });

  socket.on('history', async msgs => {
    for (let m of msgs) await decryptAndStore(m);
    switchChat();
  });

  socket.on('message', async data => {
    await decryptAndStore(data);
  });

  socket.emit('join', { room: 'main', user: username });
}


// ─── 9) UI RENDER ───────────────────────────────────────────────────────
function switchChat() {
  const sel  = document.getElementById('recipientSelect'),
        peer = sel.value,
        chatDiv = document.getElementById('chat');
  chatDiv.innerHTML = '';

  for (let opt of sel.options) {
    if (opt.value === peer && opt.textContent.startsWith('✉️')) {
      opt.textContent = peer;
    }
  }

  if (!peer || !chatHistory[peer]) return;
  chatHistory[peer]
    .sort((a, b) => a.timestamp - b.timestamp)
    .forEach(msg => {
      const cls  = msg.from === username ? 'sent' : 'recv';
      const time = new Date(msg.timestamp).toLocaleTimeString();
      const safe = (() => { const d = document.createElement('div'); d.textContent = msg.text; return d.innerHTML; })();
      chatDiv.innerHTML += `
        <div class="${cls}">
          <strong>${msg.from}:</strong> ${safe}
          <div style="font-size:0.8em; color:gray;">${time}</div>
        </div>`;
    });
  chatDiv.scrollTop = chatDiv.scrollHeight;
}


// ─── 10) KEY MANAGEMENT HELPERS ─────────────────────────────────────────
async function generateRSAKeys() {
  const saved = await loadKeyPair(username);
  if (saved) { myKeyPair = saved; return; }
  myKeyPair = await window.crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['encrypt','decrypt']
  );
  await saveKeyPair(username, myKeyPair);
}

async function generateSigningKeys() {
  const tag   = username + '_sign';
  const saved = await loadKeyPair(tag);
  if (saved) { mySignKeyPair = saved; return; }
  mySignKeyPair = await window.crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['sign','verify']
  );
  await saveKeyPair(tag, mySignKeyPair);
}

async function generateECDHKeys() {
  const tag   = username + '_ecdh';
  const saved = await loadKeyPair(tag);
  if (saved) { myECDHKeyPair = saved; return; }
  myECDHKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveKey']
  );
  await saveKeyPair(tag, myECDHKeyPair);
}

async function registerKey() {
  const rsaSpki = await window.crypto.subtle.exportKey('spki', myKeyPair.publicKey);
  const ecdhSpki= await window.crypto.subtle.exportKey('spki', myECDHKeyPair.publicKey);
  const signSpki= await window.crypto.subtle.exportKey('spki', mySignKeyPair.publicKey);

  await fetchWithAuth('/keys/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      publicKey:      btoa(String.fromCharCode(...new Uint8Array(rsaSpki))),
      ecdhPublicKey:  btoa(String.fromCharCode(...new Uint8Array(ecdhSpki))),
      signPublicKey:  btoa(String.fromCharCode(...new Uint8Array(signSpki)))
    })
  });
}

async function loadRoster() {
  const res = await fetchWithAuth('/users');
  if (!res.ok) throw new Error('Roster fetch failed');
  const { users } = await res.json();
  const sel = document.getElementById('recipientSelect');
  sel.innerHTML = '<option value="">— Select User —</option>';
  users.filter(u => u !== username).sort().forEach(u => {
    const opt = document.createElement('option');
    opt.value = u; opt.textContent = u;
    sel.appendChild(opt);
  });
}

async function getSignVerifyKey(user) {
  if (verifyKeys[user]) return verifyKeys[user];
  const res = await fetchWithAuth(`/keys/public-sign/${user}`);
  const { signPublicKey } = await res.json();
  const key = await window.crypto.subtle.importKey(
    'spki', base64ToBuffer(signPublicKey),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
  );
  verifyKeys[user] = key;
  return key;
}

async function logout() {
  token = null;
  if (socket) socket.disconnect();
  location.reload();
}


// ─── 11) UTILITIES & STORAGE ──────────────────────────────────────────
function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuffer(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}

// IndexedDB key storage
const DB_NAME = 'SecureChatKeysDB', STORE = 'keypairs', DB_VER = 1;
function openDB() {
  return new Promise((res, rej) => {
    const rq = indexedDB.open(DB_NAME, DB_VER);
    rq.onsuccess = () => res(rq.result);
    rq.onerror   = () => rej(rq.error);
    rq.onupgradeneeded = e => e.target.result.createObjectStore(STORE);
  });
}
async function saveKeyPair(user, kp) {
  const db = await openDB();
  const tx = db.transaction(STORE, 'readwrite');
  tx.objectStore(STORE).put(kp, user);
  return tx.complete;
}
async function loadKeyPair(user) {
  const db = await openDB();
  const tx = db.transaction(STORE, 'readonly');
  const rq = tx.objectStore(STORE).get(user);
  return new Promise(res => rq.onsuccess = () => res(rq.result || null));
}
