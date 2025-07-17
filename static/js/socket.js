// socket.js
// ----------------------
import { io } from 'https://cdn.socket.io/4.5.4/socket.io.esm.min.js'; // ✅ correct
import { decryptAndStore } from './chat.js';

export function connectSocket(token, username) {
  const socket = io('/chat', { auth: { token } });
  socket.on('connect', () => document.getElementById('send-btn').disabled=false);
  socket.on('connect_error', err => {
    console.error('Socket error',err);
    if (err.message==='Unauthorized') logout();
  });
  socket.on('history', async msgs => { for(const m of msgs) await decryptAndStore(m); switchChat(); });
  socket.on('message', async m => { await decryptAndStore(m); switchChat(); });
  socket.emit('join',{room:'main',user:username});
  return socket;
}