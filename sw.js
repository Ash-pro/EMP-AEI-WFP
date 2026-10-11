/* AEI–WFP HR service worker.
   - Pages: network first (always the latest index.html), cached copy only when offline.
   - Static files (icons, fonts, the Excel library): cache first, refreshed in the background.
   - Supabase requests are never touched: data always comes live from the server. */
const V = 'aei-hr-v1', SHELL = ['/', '/logo.png', '/icon-192.png', '/favicon-32.png', '/site.webmanifest'];
const STATIC_HOSTS = ['fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com'];
self.addEventListener('install', e => { e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const r = e.request; if (r.method !== 'GET') return;
  const u = new URL(r.url), same = u.origin === self.location.origin;
  if (r.mode === 'navigate' && same) {
    e.respondWith(fetch(r).then(res => { if (res.ok) { const cp = res.clone(); caches.open(V).then(c => c.put('/', cp)); } return res; })
      .catch(() => caches.match('/').then(m => m || new Response('<!doctype html><meta charset="utf-8"><body dir="rtl" style="font-family:sans-serif;padding:32px;text-align:center">لا يوجد اتصال بالإنترنت. أعد المحاولة عند توفر الاتصال.</body>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } }))));
    return;
  }
  const isStatic = (same && /\.(png|ico|webmanifest|svg|jpg|woff2?)$/.test(u.pathname)) || STATIC_HOSTS.includes(u.hostname);
  if (!isStatic) return;
  e.respondWith(caches.open(V).then(c => c.match(r).then(hit => {
    const net = fetch(r).then(res => { if (res && (res.ok || res.type === 'opaque')) c.put(r, res.clone()); return res; }).catch(() => hit);
    return hit || net;
  })));
});
