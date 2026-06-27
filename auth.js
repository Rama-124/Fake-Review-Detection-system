function getAuthToken() {
    return localStorage.getItem('token');
}

function getCurrentUser() {
    try {
        return JSON.parse(localStorage.getItem('user') || 'null');
    } catch (error) {
        return null;
    }
}

function requireLogin() {
    if (!getAuthToken()) {
        redirectToLogin();
        return false;
    }
    return true;
}

function redirectToLogin() {
    const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `login.html?returnTo=${returnTo}`;
}

function handleAuthFailure(response) {
    if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        redirectToLogin();
        return true;
    }
    return false;
}

function authHeaders(extraHeaders = {}) {
    const token = getAuthToken();
    return {
        ...extraHeaders,
        ...(token ? { Authorization: `Bearer ${token}` } : {})
    };
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

function renderUserNav() {
    const user = getCurrentUser();
    const authTargets = document.querySelectorAll('[data-auth-nav]');

    authTargets.forEach((target) => {
        if (!getAuthToken()) {
            target.innerHTML = '<a href="login.html" class="nav-pill">Login</a>';
            return;
        }

        target.innerHTML = `
            <span class="nav-pill">${user?.name || user?.email || 'Logged in'}</span>
            <button type="button" class="nav-pill nav-button" onclick="logout()">Logout</button>
        `;
    });
}
