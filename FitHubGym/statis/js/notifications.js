(function () {
    var csrf = document.currentScript.dataset.csrf;
    var baseTitle = document.title, lastId = null;
    var btn = document.getElementById('bellBtn'), panel = document.getElementById('bellPanel');
    var badge = document.getElementById('bellBadge'), list = document.getElementById('bellList');
    function safeLink(l) { return (typeof l === 'string' && l.charAt(0) === '/' && l.charAt(1) !== '/') ? l : null; }
    function when(t) { return t ? t.slice(8, 10) + '/' + t.slice(5, 7) + ' ' + t.slice(11, 16) : ''; }
    function mark(id) {
        var b = new URLSearchParams(); if (id) { b.set('id', id); } else { b.set('all', '1'); }
        return fetch('/notifications/read', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf }, body: b });
    }
    function go(n) { mark(n.id).then(function () { var l = safeLink(n.link); if (l) { location.href = l; } else { load(); } }); }
    function render(d) {
        badge.hidden = !d.unread; badge.textContent = d.unread > 99 ? '99+' : d.unread;
        document.title = (d.unread ? '(' + d.unread + ') ' : '') + baseTitle;
        list.textContent = '';
        if (!d.items.length) { var e = document.createElement('div'); e.className = 'bell-empty'; e.textContent = 'Belum ada notifikasi.'; list.appendChild(e); return; }
        d.items.forEach(function (n) {
            var it = document.createElement('button'); it.type = 'button'; it.className = 'nitem' + (n.is_read ? '' : ' unread');
            var t = document.createElement('b'); t.textContent = n.title;
            var m = document.createElement('span'); m.textContent = n.message || '';
            var w = document.createElement('small'); w.textContent = when(n.created_at);
            it.appendChild(t); it.appendChild(m); it.appendChild(w);
            it.addEventListener('click', function () { go(n); });
            list.appendChild(it);
        });
    }
    function toast(n) {
        var box = document.getElementById('toasts'), el = document.createElement('div'); el.className = 'toast';
        var t = document.createElement('b'); t.textContent = n.title;
        var m = document.createElement('span'); m.textContent = n.message || '';
        el.appendChild(t); el.appendChild(m);
        el.addEventListener('click', function () { go(n); });
        box.appendChild(el); setTimeout(function () { el.remove(); }, 9000);
    }
    function load() {
        fetch('/notifications', { credentials: 'same-origin', cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d) { return; }
                if (lastId !== null) {
                    d.items.filter(function (i) { return i.id > lastId && !i.is_read; }).reverse().forEach(toast);
                }
                if (d.items.length) { lastId = Math.max(lastId || 0, d.items[0].id); } else if (lastId === null) { lastId = 0; }
                render(d);
            }).catch(function () {});
    }
    btn.addEventListener('click', function (e) {
        e.stopPropagation(); panel.hidden = !panel.hidden; btn.setAttribute('aria-expanded', String(!panel.hidden));
    });
    document.addEventListener('click', function (e) { if (!panel.hidden && !panel.contains(e.target)) { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); } });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); } });
    document.getElementById('bellAll').addEventListener('click', function () { mark(null).then(load); });
    document.addEventListener('visibilitychange', function () { if (!document.hidden) { load(); } });
    load(); setInterval(load, 12000);
})();

const printReport = document.querySelector('[data-print-report]');
if (printReport) {
    printReport.addEventListener('click', function () { window.print(); });
}
