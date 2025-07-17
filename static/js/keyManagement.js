// keyManagement.js
// ----------------------
import { loadKeyPair, saveKeyPair } from './utils.js';
import { fetchWithAuth, bufferToBase64 } from './utils.js';

export async function generateRSAKeys(username) {
  const existing = await loadKeyPair(username);
  if (existing) return existing;
  const kp = await window.crypto.subtle.generateKey(
    { name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' },
    true, ['encrypt','decrypt']
  );
  await saveKeyPair(username, kp);
  return kp;
}

export async function generateSigningKeys(username) {
  const tag = `${username}_sign`;
  const existing = await loadKeyPair(tag);
  if (existing) return existing;
  const kp = await window.crypto.subtle.generateKey(
    { name:'RSASSA-PKCS1-v1_5', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' },
    true, ['sign','verify']
  );
  await saveKeyPair(tag, kp);
  return kp;
}

export async function generateEcdhKeys(username) {
  const tag = `${username}_ecdh`;
  const existing = await loadKeyPair(tag);
  if (existing) return existing;
  const kp = await window.crypto.subtle.generateKey(
    { name:'ECDH', namedCurve:'P-256' },
    true, ['deriveKey']
  );
  await saveKeyPair(tag, kp);
  return kp;
}

export async function registerKeyPairs(username) {
  const rsa = await window.appState.myKeyPair;
  const ecdh = await window.appState.myEcdhKeyPair;
  const sign = await window.appState.mySignKeyPair;
  const rsaSpki = await window.crypto.subtle.exportKey('spki',rsa.publicKey);
  const ecdhSpki= await window.crypto.subtle.exportKey('spki',ecdh.publicKey);
  const signSpki= await window.crypto.subtle.exportKey('spki',sign.publicKey);
  await fetchWithAuth('/keys/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    publicKey:btoa(String.fromCharCode(...new Uint8Array(rsaSpki))),
    ecdhPublicKey:btoa(String.fromCharCode(...new Uint8Array(ecdhSpki))),
    signPublicKey:btoa(String.fromCharCode(...new Uint8Array(signSpki)))
  })});
}

export async function getSignVerifyKey(user) {
  if (window.appState.verifyKeys[user]) return window.appState.verifyKeys[user];
  const res = await fetchWithAuth(`/keys/public-sign/${user}`);
  const { signPublicKey } = await res.json();
  const key = await window.crypto.subtle.importKey(
    'spki', base64ToBuffer(signPublicKey),
    { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' },
    false, ['verify']
  );
  window.appState.verifyKeys[user] = key;
  return key;
}

export async function logout() {
  window.appState.token = null;
  if (window.appState.socket) window.appState.socket.disconnect();
  location.reload();
}