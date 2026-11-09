/* RBA 8.0.1 — Service Worker: chuyển các request "api/..." tới bộ xử lý Python chạy trong trang.
   Đồng thời lưu đệm giao diện để mở nhanh / dùng khi mất mạng.
   © NGUYỄN NGỌC NGÔN */
const BUILD = '__BUILD__';
const CACHE = 'rba-ehs-' + BUILD;
const SHELL = ['./', 'index.html', 'web-boot.js', 'engine-worker.js', 'bridge.py', 'app.zip', 'static/tailwind.css',
               'static/icon.svg', 'static/icon-192.png', 'static/icon-512.png', 'static/manifest.webmanifest'];
const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/';

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => Promise.all(SHELL.map(u => c.add(new Request(u + (u.includes('.') && u !== './' ? '?v=' + BUILD : ''), { cache: 'reload' })).catch(() => null)))));
});
self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith('rba-ehs-') && k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

const scope = () => self.registration.scope;

self.addEventListener('fetch', e => {
  const url = e.request.url;
  if (url.startsWith(scope()) && url.slice(scope().length).startsWith('api/')) {
    e.respondWith(forward(e));
    return;
  }
  if (e.request.method !== 'GET') return;
  // Pyodide (CDN): cache-first, phiên bản cố định nên không bao giờ thay đổi
  if (url.startsWith(PYODIDE)) {
    e.respondWith(caches.open('rba-pyodide').then(async c => {
      const hit = await c.match(e.request);
      if (hit) return hit;
      const res = await fetch(e.request);
      if (res.ok) c.put(e.request, res.clone());
      return res;
    }));
    return;
  }
  // Giao diện: mạng trước, mất mạng thì dùng bản lưu đệm
  if (url.startsWith(scope())) {
    e.respondWith(fetch(e.request).then(res => {
      if (res.ok && e.request.url.split('?')[0].match(/(\/|\.html|\.js|\.css|\.py|\.zip|\.png|\.svg|\.webmanifest)$/)) {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
      }
      return res;
    }).catch(async () => (await caches.match(e.request, { ignoreSearch: true })) || (await caches.match('index.html', { ignoreSearch: true })) || Response.error()));
  }
});

async function pickClient(e) {
  let c = e.clientId ? await self.clients.get(e.clientId) : null;
  if (c && c.type === 'window') return c;
  const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  return all.find(x => x.id !== e.resultingClientId) || all[0] || null;
}

async function forward(e) {
  const req = e.request;
  const client = await pickClient(e);
  if (!client) return json({ status: 'error', message: 'Hệ thống chưa sẵn sàng — hãy mở lại trang.' }, 503);
  const headers = {};
  req.headers.forEach((v, k) => { headers[k] = v; });
  const body = (req.method === 'GET' || req.method === 'HEAD') ? null : await req.arrayBuffer();
  const rel = req.url.slice(scope().length);
  const ch = new MessageChannel();
  const reply = new Promise(res => { ch.port1.onmessage = m => res(m.data); });
  client.postMessage({ type: 'rba-req', method: req.method, path: '/' + rel, headers, body }, body ? [ch.port2, body] : [ch.port2]);
  const r = await reply;
  const nullBody = [101, 204, 205, 304].includes(r.status) || req.method === 'HEAD';
  return new Response(nullBody ? null : r.body, { status: r.status, headers: r.headers });
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
