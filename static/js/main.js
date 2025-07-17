// main.js
// ----------------------
import * as Utils from './utils.js';
import * as Auth from './auth.js';
import * as Chat from './chat.js';
import * as Socket from './socket.js';
import * as Keys from './keyManagement.js';

// Bind native fetch
window._origFetch = window.fetch.bind(window);
// Global state
window.appState = { token:null, username:null, chatHistory:{}, verifyKeys:{},
  myKeyPair:null, mySignKeyPair:null, myEcdhKeyPair:null, socket:null
};

document.addEventListener('DOMContentLoaded', () => {
  // Registration
  document.getElementById('reg-btn').onclick = () => {
    const u=document.getElementById('reg-username').value.trim();
    const p=document.getElementById('reg-password').value.trim();
    const e=document.getElementById('reg-email').value.trim();
    const c=grecaptcha.getResponse();
    if(!u||!p||!e||!c) return alert('All fields+CAPTCHA required');
    Auth.sendOtp(u,p,e,c).then(res=>{
      if(res.ok){ alert('OTP sent');
        document.getElementById('reg').style.display='none';
        document.getElementById('reg-otp').style.display='block';
      } else res.json().then(d=>alert(d.error||res.statusText));
    }).catch(e=>alert('Network error'));
  };
  document.getElementById('reg-verify-btn').onclick = async () => {
    const u=document.getElementById('reg-username').value.trim();
    const code=document.getElementById('reg-otp-code').value.trim();
    if(!code) return alert('Enter OTP');
    const res=await Auth.confirmRegistration(u,code);
    const data=await res.json();
    if(res.ok){ alert('Registered!'); location.reload(); }
    else alert(data.error||'Err');
  };

  // Login
  document.getElementById('login-btn').onclick = async () => {
    const u=document.getElementById('username').value.trim();
    const p=document.getElementById('password').value.trim();
    if(!u||!p) return alert('Required');
    window.appState.username=u;
    const res=await Auth.loginStep1(u,p);
    const data=await res.json();
    if(!res.ok) return alert(data.error||'Fail');
    alert('Code sent');
    document.getElementById('login').style.display='none';
    document.getElementById('login-otp').style.display='block';
  };
  document.getElementById('login-verify-btn').onclick = async () => {
    const code=document.getElementById('login-otp-code').value.trim();
    if(!code) return alert('Enter code');
    const res=await Auth.loginStep2(window.appState.username,code);
    const data=await res.json();
    if(!res.ok) return alert(data.error||'Fail');
    window.appState.token=data.token;
    await initializeApp();
  };

  // Forgot/reset
  document.getElementById('forgot-link').onclick=()=>{
    document.getElementById('login').style.display='none';
    document.getElementById('reset').style.display='block';
  };
  document.getElementById('reset-request-btn').onclick=async ()=>{
    const u=document.getElementById('reset-username').value.trim();
    const e=document.getElementById('reset-email').value.trim();
    if(!u||!e) return alert('Required');
    const res=await Auth.forgotPassword(u,e);
    const d=await res.json(); alert(d.message||d.error);
    document.getElementById('reset').style.display='none';
    document.getElementById('reset-verify').style.display='block';
  };
  document.getElementById('reset-confirm-btn').onclick=async ()=>{
    const u=document.getElementById('reset-username').value.trim();
    const c=document.getElementById('reset-code').value.trim();
    const pw=document.getElementById('reset-newpw').value.trim();
    if(!c||!pw) return alert('Required');
    const res=await Auth.confirmReset(u,c,pw);
    const d=await res.json();
    if(res.ok){ alert('Reset!'); location.reload(); }
    else alert(d.error);
  };

  // Chat/send
  document.getElementById('send-btn').onclick = async () => {
    const text=document.getElementById('message').value.trim();
    const to=document.getElementById('recipientSelect').value;
    if(!to||!text) return alert('Select and enter text');
    try {
      await Chat.sendMessage(text,to,window.appState.username, window.appState.socket);
      Chat.switchChat();
    } catch(e){ console.error(e); alert('Send failed'); }
  };
  document.getElementById('recipientSelect').onchange = Chat.switchChat;
  document.getElementById('logout-btn').onclick = Keys.logout;
});

async function initializeApp() {
  const exp = Utils.getTokenExpiration(window.appState.token);
  if(exp) setTimeout(()=>{ alert('Session expired'); Keys.logout(); }, exp - Date.now());

  document.getElementById('login-otp').style.display = 'none';
  document.getElementById('controls').style.display  = 'block';
  document.getElementById('logout-btn').style.display= 'inline-block';

  // clear state
  window.appState.chatHistory = {};
  window.appState.verifyKeys  = {};

  // key gen & register
  window.appState.myKeyPair     = await Keys.generateRSAKeys(window.appState.username);
  window.appState.mySignKeyPair = await Keys.generateSigningKeys(window.appState.username);
  window.appState.myEcdhKeyPair = await Keys.generateEcdhKeys(window.appState.username);
  await Keys.registerKeyPairs(window.appState.username);

  // load roster/history
  const users = await Chat.loadRoster();
  const sel = document.getElementById('recipientSelect');
  sel.innerHTML = '<option value="">— Select User —</option>';
  users.filter(u=>u!==window.appState.username).forEach(u=>{
    const opt = document.createElement('option'); opt.value=u; opt.textContent=u;
    sel.appendChild(opt);
  });
  await Chat.loadChatHistory(window.appState.username);

  // socket connect
  window.appState.socket = Socket.connectSocket(window.appState.token, window.appState.username);
}
