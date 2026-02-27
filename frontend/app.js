/**
 * app.js - Shared Application Logic
 * ===================================
 * API client, chatbot, toast system, utility functions.
 * Loaded on every page.
 */

const API_BASE = '';  // Same origin

// ── API Client Helpers ──────────────────────────────────

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    };
}

async function apiGet(url) {
    const res = await fetch(API_BASE + url, {
        method: 'GET',
        headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || 'Request failed');
    }
    return data;
}

async function apiPost(url, body) {
    const res = await fetch(API_BASE + url, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || 'Request failed');
    }
    return data;
}

async function apiDelete(url) {
    const res = await fetch(API_BASE + url, {
        method: 'DELETE',
        headers: getAuthHeaders(),
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || 'Request failed');
    }
    return data;
}

// ── Auth Utilities ──────────────────────────────────────

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/';
}

function isAuthenticated() {
    return !!localStorage.getItem('token');
}

function getCurrentUser() {
    return JSON.parse(localStorage.getItem('user') || 'null');
}

// ── Toast Notification System ───────────────────────────

function showToast(message, type = 'info') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
        if (container.children.length === 0) {
            container.remove();
        }
    }, 3000);
}

// ── Chatbot ─────────────────────────────────────────────

function toggleChatbot() {
    const panel = document.getElementById('chatbotPanel');
    const fab = document.getElementById('chatbotFab');
    panel.classList.toggle('active');
    if (panel.classList.contains('active')) {
        fab.innerHTML = '<i class="fas fa-times"></i>';
        document.getElementById('chatInput')?.focus();
    } else {
        fab.innerHTML = '<i class="fas fa-robot"></i>';
    }
}

async function sendChatMessage(e) {
    e.preventDefault();
    const input = document.getElementById('chatInput');
    const messages = document.getElementById('chatMessages');
    const text = input.value.trim();
    if (!text) return;

    // Add user message
    const userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user';
    userMsg.innerHTML = `<p>${escapeHtml(text)}</p>`;
    messages.appendChild(userMsg);
    input.value = '';

    // Scroll to bottom
    messages.scrollTop = messages.scrollHeight;

    // Show typing indicator
    const typingMsg = document.createElement('div');
    typingMsg.className = 'chat-msg bot typing-indicator';
    typingMsg.innerHTML = '<p>Thinking</p>';
    messages.appendChild(typingMsg);
    messages.scrollTop = messages.scrollHeight;

    try {
        const res = await apiPost('/api/chatbot', { message: text });
        typingMsg.remove();

        const botMsg = document.createElement('div');
        botMsg.className = 'chat-msg bot';
        botMsg.innerHTML = `<p>${escapeHtml(res.response)}</p>`;
        messages.appendChild(botMsg);
    } catch (err) {
        typingMsg.remove();
        const errorMsg = document.createElement('div');
        errorMsg.className = 'chat-msg bot';
        errorMsg.innerHTML = '<p>Sorry, I had trouble processing that. Please try again.</p>';
        messages.appendChild(errorMsg);
    }

    messages.scrollTop = messages.scrollHeight;
}

// ── Utility Functions ───────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(isoStr) {
    if (!isoStr) return '';
    try {
        const d = new Date(isoStr + (isoStr.endsWith('Z') ? '' : 'Z'));
        const now = new Date();
        const diffMs = now - d;
        const diffMin = Math.floor(diffMs / 60000);
        const diffHr = Math.floor(diffMs / 3600000);

        if (diffMin < 1) return 'Just now';
        if (diffMin < 60) return `${diffMin}m ago`;
        if (diffHr < 24) return `${diffHr}h ago`;

        return d.toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        });
    } catch {
        return isoStr;
    }
}

// ── Intersection Observer for Scroll Animations ─────────

if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.style.animationPlayState = 'running';
                    observer.unobserve(entry.target);
                }
            });
        },
        { threshold: 0.1 }
    );

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.animate-fade-up').forEach((el) => {
            el.style.animationPlayState = 'paused';
            observer.observe(el);
        });
    });
}

console.log('%c🔒 Zero-Trust Campus Club Vault', 'font-size: 16px; font-weight: bold; color: #63b3ed;');
console.log('%cNever trust, always verify.', 'font-size: 12px; color: #94a3b8;');
