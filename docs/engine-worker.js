/* RBA 8.0.1 — Engine worker: chạy mã Python của hệ thống trong trình duyệt (Pyodide).
   Dữ liệu (database, storage, backups, templates) lưu trong IndexedDB của trình duyệt.
   © NGUYỄN NGỌC NGÔN */
const BUILD = '100b1a43fd';
const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/v0.26.4/full/';
importScripts(PYODIDE + 'pyodide.js');

const PERSIST = ['database', 'storage', 'backups', 'templates'];
let py = null, handle = null, syncTimer = null, syncing = false, syncAgain = false;
const queue = [];

const post = (type, extra) => self.postMessage(Object.assign({ type }, extra || {}));

function syncfs(populate) {
  return new Promise((res, rej) => py.FS.syncfs(populate, e => e ? rej(e) : res()));
}
async function flush() {
  if (!py) return;
  if (syncing) { syncAgain = true; return; }
  syncing = true;
  try { await syncfs(false); } catch (e) { console.warn('syncfs', e); }
  syncing = false;
  if (syncAgain) { syncAgain = false; flush(); }
}
function scheduleSync() { clearTimeout(syncTimer); syncTimer = setTimeout(flush, 400); }

async function init() {
  post('progress', { step: 1 });
  py = await loadPyodide({ indexURL: PYODIDE });
  post('progress', { step: 2 });
  await py.loadPackage(['ssl', 'hashlib']);
  const FS = py.FS;
  FS.mkdirTree('/app');
  for (const d of PERSIST) { FS.mkdirTree('/app/' + d); FS.mount(FS.filesystems.IDBFS, {}, '/app/' + d); }
  await syncfs(true);
  post('progress', { step: 3 });
  const res = await fetch('app.zip?v=' + BUILD);
  if (!res.ok) throw new Error('Không tải được app.zip (HTTP ' + res.status + ')');
  FS.writeFile('/tmp/app.zip', new Uint8Array(await res.arrayBuffer()));
  const bridgeSrc = await (await fetch('bridge.py?v=' + BUILD)).text();
  FS.writeFile('/app/web_bridge.py', bridgeSrc);
  py.runPython(`
import sys
sys.path.insert(0, '/app')
import web_bridge
web_bridge.unpack_app('/tmp/app.zip')
`);
  post('progress', { step: 4 });
  const bridge = py.pyimport('web_bridge');
  bridge.boot();
  handle = bridge.handle;
  await flush();
  post('ready', { build: BUILD });
  while (queue.length) serve(queue.shift());
}

function serve(msg) {
  const port = msg.port;
  let out;
  try {
    const body = msg.body ? new Uint8Array(msg.body) : null;
    const r = handle(msg.method, msg.path, JSON.stringify(msg.headers || {}), body);
    const status = r.get(0), headers = JSON.parse(r.get(1));
    const pyBody = r.get(2);
    const u8 = pyBody.toJs();
    pyBody.destroy(); r.destroy();
    out = { status, headers, body: u8.buffer };
    port.postMessage(out, [u8.buffer]);
  } catch (e) {
    const b = new TextEncoder().encode(JSON.stringify({ status: 'error', message: String(e && e.message || e) }));
    port.postMessage({ status: 500, headers: [['Content-Type', 'application/json; charset=utf-8']], body: b.buffer }, [b.buffer]);
  }
  if (!/\/api\/photo/.test(msg.path)) scheduleSync();
}

self.onmessage = ev => {
  const m = ev.data || {};
  if (m.type === 'req') {
    m.port = ev.ports[0];
    if (handle) serve(m); else queue.push(m);
  } else if (m.type === 'flush') {
    flush();
  }
};

init().catch(e => { console.error(e); post('error', { message: String(e && e.message || e) }); });
