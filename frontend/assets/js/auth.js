/* =============================================
   CyberSentinel Pro — Auth JS
   Manages Utoken / Atoken in localStorage
============================================= */

const API_BASE = 'http://127.0.0.1:5000';

function getToken() {
  return localStorage.getItem('Utoken') || localStorage.getItem('Atoken') || null;
}

function getUserRole() {
  return localStorage.getItem('Atoken') ? 'admin' : 'user';
}

function getUserData() {
  try { return JSON.parse(localStorage.getItem('user_data') || '{}'); }
  catch { return {}; }
}

function logout() {
  const token = getToken();
  if (token) {
    fetch(API_BASE + '/api/auth/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    }).catch(() => {});
  }
  localStorage.removeItem('Utoken');
  localStorage.removeItem('Atoken');
  localStorage.removeItem('user_data');
  showToast('Logged out successfully', 'info');
  setTimeout(() => window.location.href = 'login.html', 800);
}

function requireAuth(redirectTo = 'login.html') {
  if (!getToken()) { window.location.href = redirectTo; return false; }
  return true;
}

function requireAdmin() {
  if (!localStorage.getItem('Atoken')) { window.location.href = 'login.html'; return false; }
  return true;
}

// Toast notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.animation = 'slideOutToast 0.4s ease forwards'; setTimeout(() => toast.remove(), 400); }, 3600);
}

// Update user name in nav if element exists
document.addEventListener('DOMContentLoaded', () => {
  const nameEl = document.getElementById('user-name-nav');
  if (nameEl) {
    const u = getUserData();
    if (u.name) nameEl.textContent = `Hi, ${u.name.split(' ')[0]}`;
  }
});
