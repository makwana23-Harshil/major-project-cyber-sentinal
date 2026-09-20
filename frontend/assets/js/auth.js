/* =============================================
   CyberSentinel Pro — Auth JS
   JWT Authentication using sessionStorage

   Admin:
     Atoken
     admin_data

   User:
     Utoken
     user_data
============================================= */

const API_BASE = 'http://127.0.0.1:5000';


// =============================================
// Check if current page belongs to admin panel
// =============================================

function isAdminPage() {
    return window.location.pathname.includes('admin');
}


// =============================================
// Get JWT token for current page
// =============================================

function getToken() {

    if (isAdminPage()) {
        return sessionStorage.getItem('Atoken') || null;
    }

    return sessionStorage.getItem('Utoken') || null;
}


// =============================================
// Get current user data
// =============================================

function getUserData() {

    try {

        if (isAdminPage()) {

            return JSON.parse(
                sessionStorage.getItem('admin_data') || '{}'
            );

        }

        return JSON.parse(
            sessionStorage.getItem('user_data') || '{}'
        );

    } catch (error) {

        console.error('Failed to read user data:', error);

        return {};
    }
}


// =============================================
// Get current role
// =============================================

function getUserRole() {

    return isAdminPage() ? 'admin' : 'user';

}


// =============================================
// Logout
// =============================================

function logout() {

    const token = getToken();

    // Inform backend
    if (token) {

        fetch(API_BASE + '/api/auth/logout', {

            method: 'POST',

            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }

        }).catch(() => {});

    }


    // Remove only current role's session
    if (isAdminPage()) {

        sessionStorage.removeItem('Atoken');
        sessionStorage.removeItem('admin_data');

    } else {

        sessionStorage.removeItem('Utoken');
        sessionStorage.removeItem('user_data');

    }


    showToast('Logged out successfully', 'info');


    setTimeout(() => {

        window.location.href = 'login.html';

    }, 800);
}


// =============================================
// Require normal user authentication
// =============================================

function requireAuth(redirectTo = 'login.html') {

    const token = sessionStorage.getItem('Utoken');

    if (!token) {

        window.location.href = redirectTo;

        return false;
    }

    return true;
}


// =============================================
// Require admin authentication
// =============================================

function requireAdmin() {

    const token = sessionStorage.getItem('Atoken');

    if (!token) {

        window.location.href = 'login.html';

        return false;
    }

    return true;
}


// =============================================
// Toast notifications
// =============================================

function showToast(message, type = 'info') {

    const container = document.getElementById('toast-container');

    if (!container) {
        return;
    }


    const icons = {

        success: '<i class="fas fa-check"></i>',
        error: '<i class="fas fa-xmark"></i>',
        warning: '<i class="fas fa-triangle-exclamation"></i>',
        info: '<i class="fas fa-circle-info"></i>'

    };


    const toast = document.createElement('div');

    toast.className = `toast toast-${type}`;

    toast.innerHTML = `
        <span>${icons[type] || '<i class="fas fa-circle-info"></i>'}</span>
        <span>${message}</span>
    `;


    container.appendChild(toast);


    setTimeout(() => {

        toast.style.animation =
            'slideOutToast 0.4s ease forwards';


        setTimeout(() => {

            toast.remove();

        }, 400);

    }, 3600);
}


// =============================================
// Update user name in navigation
// =============================================

document.addEventListener('DOMContentLoaded', () => {

    const nameEl =
        document.getElementById('user-name-nav');


    if (!nameEl) {
        return;
    }


    const user = getUserData();


    if (user.name) {

        nameEl.textContent =
            `Hi, ${user.name.split(' ')[0]}`;

    }

});