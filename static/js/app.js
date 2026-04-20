'use strict';
const socket = io();

socket.on('new_alert', (alert) => {
    const badge = document.getElementById('alert-badge');
    if (badge) badge.textContent = parseInt(badge.textContent || '0') + 1;
    showToast(`${alert.severity}: ${alert.title}`);
});

function showToast(msg) {
    const t = document.createElement('div');
    t.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--red);color:#fff;padding:12px 20px;border-radius:6px;font-size:.88em;font-weight:600;z-index:9999;max-width:350px;';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 5000);
}

async function dismissAlert(alertId) {
    await fetch(`/api/alert/${alertId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'closed' }),
    });
    location.reload();
}
