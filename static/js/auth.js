// auth.js
// ----------------------
import { _origFetch } from './main.js';

export async function sendOtp(username, password, email, captcha) {
  return _origFetch('/auth/pre_register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, email, captcha })
  });
}

export async function confirmRegistration(username, otp) {
  return _origFetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, otp })
  });
}

export async function loginStep1(username, password) {
  return _origFetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
}

export async function loginStep2(username, otp) {
  return _origFetch('/auth/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, otp })
  });
}

export async function forgotPassword(username, email) {
  return _origFetch('/auth/forgot_password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email })
  });
}

export async function confirmReset(username, code, newPassword) {
  return _origFetch('/auth/reset_password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, code, password: newPassword })
  });
}