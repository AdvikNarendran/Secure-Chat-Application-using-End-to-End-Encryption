// chat.js
// ----------------------
import { fetchWithAuth, base64ToBuffer, bufferToBase64 } from './utils.js';
import { getSignVerifyKey } from './keyManagement.js';
import { io } from 'socket.io-client';

export async function sendMessage(text, to, username, socket) {
  // Retrieve peer ECDH publicKey
  const resKey = await fetchWithAuth(`/keys/ecdh/${to}`);
  if (!resKey.ok) throw new Error('ECDH key fetch failed');
  const { publicKey: peerEcdhB64 } = await resKey.json();

  const peerEcdhKey = await window.crypto.subtle.importKey(
    'spki', base64ToBuffer(peerEcdhB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );

  // Generate ephemeral key
  const eph = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveKey']
  );
  const ephPubB64 = bufferToBase64(
    await window.crypto.subtle.exportKey('spki', eph.publicKey)
  );

  // Derive AES key
  const aesKey = await window.crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerEcdhKey },
    eph.privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );

  const encoder = new TextEncoder();
  const dataBuf = encoder.encode(text);

  // Sign message
  const sig = bufferToBase64(
    await window.crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      window.appState.mySignKeyPair.privateKey,
      dataBuf
    )
  );

  // Encrypt
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ct = bufferToBase64(
    await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      dataBuf
    )
  );

  const messagePayload = {
    room: 'main', from: username, to,
    ephemeralPubKey: ephPubB64,
    iv: bufferToBase64(iv), ciphertext: ct,
    signature: sig,
    timestamp: new Date().toISOString()
  };

  // Send via socket and persist
  socket.emit('message', messagePayload);
  await fetchWithAuth('/messages', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify(messagePayload)
  });

  // Update local history
  if (!window.appState.chatHistory[to]) window.appState.chatHistory[to] = [];
  window.appState.chatHistory[to].push({ from: username, to, text, timestamp: Date.now() });
}

export async function loadRoster() {
  const res = await fetchWithAuth('/users');
  if (!res.ok) throw new Error('Roster fetch failed');
  return (await res.json()).users;
}

export async function loadChatHistory(username) {
  const users = await loadRoster();
  for (const peer of users.filter(u => u !== username)) {
    window.appState.chatHistory[peer] = [];
    const res = await fetchWithAuth(`/messages/${peer}`);
    if (!res.ok) continue;
    const history = await res.json();
    for (const msg of history) {
      await decryptAndStore(msg);
    }
  }
}

export async function decryptAndStore(m) {
  try {
    // Import ephemeral key
    const ephKey = await window.crypto.subtle.importKey(
      'spki', base64ToBuffer(m.ephemeralPubKey),
      { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    // Derive AES key
    const aesKey = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephKey },
      window.appState.myEcdhKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']
    );
    // Decrypt
    const plainBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuffer(m.iv) },
      aesKey, base64ToBuffer(m.ciphertext)
    );
    const text = new TextDecoder().decode(plainBuf);

    // Verify signature if incoming
    if (m.signature && m.from !== window.appState.username) {
      const vk = await getSignVerifyKey(m.from);
      const ok = await window.crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' }, vk,
        base64ToBuffer(m.signature), new TextEncoder().encode(text)
      );
      if (!ok) return console.warn('Invalid sig from', m.from);
    }

    const peer = m.from === window.appState.username ? m.to : m.from;
    window.appState.chatHistory[peer].push({
      from: m.from, to: m.to, text,
      timestamp: new Date(m.timestamp).getTime()
    });
  } catch (e) {
    console.warn('Decrypt error:', e);
  }
}

export function switchChat() {
  const sel = document.getElementById('recipientSelect');
  const peer = sel.value;
  const chatDiv = document.getElementById('chat');
  chatDiv.innerHTML = '';
  if (!peer) return;
  window.appState.chatHistory[peer]
    .sort((a,b)=>a.timestamp-b.timestamp)
    .forEach(msg => {
      const cls = msg.from===window.appState.username?'sent':'recv';
      const safe = (()=>{const d=document.createElement('div'); d.textContent=msg.text; return d.innerHTML;})();
      const time = new Date(msg.timestamp).toLocaleTimeString();
      chatDiv.innerHTML += `
        <div class="${cls}">
          <strong>${msg.from}:</strong> ${safe}
          <div style="font-size:0.8em;color:gray;">${time}</div>
        </div>`;
    });
  chatDiv.scrollTop = chatDiv.scrollHeight;
}
