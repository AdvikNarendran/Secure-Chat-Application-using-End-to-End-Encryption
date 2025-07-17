export function getTokenExpiration(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp * 1000;
  } catch {
    return null;
  }
}

export async function fetchWithAuth(url, opts = {}) {
  opts.headers = opts.headers || {};
  opts.headers['Authorization'] = `Bearer ${window.appState.token}`;
  const res = await window._origFetch(url, opts);
  if (res.status === 401 && window.appState.token) {
    await logout();
    alert('Session expired—please log in again.');
  }
  return res;
}

export function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
export function base64ToBuffer(b64) {
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
export async function saveKeyPair(keyName, kp) {
  const db = await openDB();
  const tx = db.transaction(STORE, 'readwrite');
  tx.objectStore(STORE).put(kp, keyName);
  return new Promise((res, rej) => {
    tx.oncomplete = () => res();
    tx.onerror    = () => rej(tx.error);
  });
}
export async function loadKeyPair(keyName) {
  const db = await openDB();
  const tx = db.transaction(STORE, 'readonly');
  const rq = tx.objectStore(STORE).get(keyName);
  return new Promise(res => rq.onsuccess = () => res(rq.result || null));
}