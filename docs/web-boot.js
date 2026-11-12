/* RBA 8.0.1 — Khởi động bản web (GitHub Pages).
   - Khởi chạy bộ xử lý Python (engine-worker.js) và Service Worker (sw.js)
   - Chuyển request "api/..." từ Service Worker tới bộ xử lý
   - PDF: mở bản in A4 và gọi hộp thoại In (Lưu thành PDF)
   © NGUYỄN NGỌC NGÔN */
(function () {
  'use strict';
  const BUILD = 'd8036a42ff';
  window.RBA_WEB = true;
  const LANG = localStorage.getItem('RBA_LANG') || 'vi';
  const ALL = {
    vi: { title: 'Đang khởi động hệ thống…', steps: ['Chuẩn bị…', 'Tải bộ xử lý Python', 'Nạp dữ liệu trên thiết bị', 'Tải mẫu & quy tắc RBA', 'Hoàn tất'],
          sub: 'Lần đầu có thể mất 10–30 giây. Các lần sau sẽ nhanh hơn.', err: 'Không khởi động được hệ thống', retry: 'Thử lại',
          nosw: 'Trình duyệt này không hỗ trợ Service Worker (hoặc đang ở chế độ ẩn danh). Hãy dùng Chrome, Edge, Safari hoặc Firefox bản mới ở chế độ thường.' },
    en: { title: 'Starting the system…', steps: ['Preparing…', 'Loading Python engine', 'Loading on-device data', 'Loading RBA templates & rules', 'Done'],
          sub: 'First start may take 10–30 seconds. Later starts are faster.', err: 'Could not start the system', retry: 'Retry',
          nosw: 'This browser does not support Service Workers (or is in private mode). Please use an up-to-date Chrome, Edge, Safari or Firefox.' },
    ko: { title: '시스템 시작 중…', steps: ['준비 중…', 'Python 엔진 로드', '기기 데이터 로드', 'RBA 양식 및 규칙 로드', '완료'],
          sub: '처음에는 10–30초 정도 걸릴 수 있습니다.', err: '시스템을 시작할 수 없습니다', retry: '다시 시도',
          nosw: '이 브라우저는 Service Worker를 지원하지 않습니다(또는 시크릿 모드). 최신 Chrome, Edge, Safari, Firefox를 사용하세요.' },
  };
  const T = ALL[LANG] || ALL.vi;

  let readyResolve;
  window.__rbaReady = new Promise(r => { readyResolve = r; });

  /* ---------- loading overlay ---------- */
  let ov, ovStep, ovBar;
  function overlay() {
    if (ov || !document.body) return;
    ov = document.createElement('div');
    ov.id = 'webBoot';
    ov.setAttribute('style', 'position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;padding:24px;' +
      'background:linear-gradient(120deg,#0b1220 0%,#111c35 55%,#1a2350 100%);color:#fff;font-family:Inter,-apple-system,Segoe UI,Roboto,Arial,sans-serif');
    ov.innerHTML = `<div style="max-width:340px;width:100%;text-align:center">
      <img src="static/icon-192.png" alt="" style="width:72px;height:72px;border-radius:18px;margin:0 auto 18px;display:block;box-shadow:0 10px 30px rgba(0,0,0,.4)"/>
      <div style="font-weight:900;font-size:17px">${T.title}</div>
      <div id="webBootStep" style="font-size:13px;color:#cbd5e1;margin-top:6px;min-height:18px">${T.steps[0]}</div>
      <div style="height:6px;border-radius:9px;background:rgba(255,255,255,.12);margin:16px 0 10px;overflow:hidden">
        <div id="webBootBar" style="height:100%;width:6%;background:linear-gradient(90deg,#60a5fa,#a78bfa);border-radius:9px;transition:width .5s"></div></div>
      <div style="font-size:11.5px;color:#94a3b8">${T.sub}</div>
      <div style="font-size:11px;color:#fcd34d;margin-top:22px;font-weight:600">© NGUYỄN NGỌC NGÔN · RBA 8.0.1</div></div>`;
    document.body.appendChild(ov);
    ovStep = ov.querySelector('#webBootStep'); ovBar = ov.querySelector('#webBootBar');
  }
  function progress(step) {
    overlay();
    if (!ov) return;
    ovStep.textContent = T.steps[Math.min(step, T.steps.length - 1)];
    ovBar.style.width = [6, 30, 62, 80, 100][Math.min(step, 4)] + '%';
  }
  function fail(msg) {
    overlay();
    if (!ov) return;
    ov.querySelector('div').innerHTML = `<div style="font-size:40px">⚠️</div><div style="font-weight:900;font-size:17px;margin-top:10px">${T.err}</div>
      <div style="font-size:13px;color:#fecaca;margin-top:8px;word-break:break-word">${String(msg).replace(/</g, '&lt;')}</div>
      <button onclick="location.reload()" style="margin-top:18px;padding:10px 22px;border-radius:12px;background:#fff;color:#0f172a;font-weight:800;border:0">${T.retry}</button>`;
  }
  function done() {
    progress(4);
    if (ov) { ov.style.transition = 'opacity .35s'; ov.style.opacity = '0'; setTimeout(() => ov && ov.remove(), 400); }
  }
  document.addEventListener('DOMContentLoaded', () => progress(0));

  if (!('serviceWorker' in navigator) || !window.Worker) {
    document.addEventListener('DOMContentLoaded', () => fail(T.nosw));
    return;
  }
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});

  /* ---------- engine worker ---------- */
  const worker = new Worker('engine-worker.js?v=' + BUILD);
  let engineReady = false;
  const pending = [];
  function toWorker(d, port) {
    const tr = d.body ? [port, d.body] : [port];
    worker.postMessage({ type: 'req', method: d.method, path: d.path, headers: d.headers, body: d.body }, tr);
  }
  worker.onmessage = ev => {
    const m = ev.data || {};
    if (m.type === 'progress') progress(m.step);
    else if (m.type === 'error') fail(m.message);
    else if (m.type === 'ready') {
      engineReady = true;
      while (pending.length) { const p = pending.shift(); toWorker(p.d, p.port); }
      swReady.then(() => { readyResolve(); done(); });
    }
  };
  worker.onerror = e => fail(e.message || 'Worker error');
  const flush = () => worker.postMessage({ type: 'flush' });
  addEventListener('pagehide', flush);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') flush(); });

  /* ---------- service worker ---------- */
  navigator.serviceWorker.onmessage = ev => {
    const d = ev.data || {};
    if (d.type !== 'rba-req') return;
    const port = ev.ports[0];
    if (engineReady) toWorker(d, port); else pending.push({ d, port });
  };
  const swReady = (async () => {
    await navigator.serviceWorker.register('sw.js?v=' + BUILD, { scope: './' });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise(res => {
        navigator.serviceWorker.addEventListener('controllerchange', res, { once: true });
        setTimeout(() => {
          if (!navigator.serviceWorker.controller) {
            if (!sessionStorage.getItem('rba_sw_reload')) { sessionStorage.setItem('rba_sw_reload', '1'); location.reload(); }
            else res();
          }
        }, 4000);
      });
    }
    sessionStorage.removeItem('rba_sw_reload');
  })().catch(e => fail(e.message || e));

  /* ---------- patches applied after the main script ---------- */
  document.addEventListener('DOMContentLoaded', () => {
    /* Điện thoại hay tải lại trang khi chuyển ứng dụng: tự mở lại phiên đang làm + lưu nháp thường xuyên hơn */
    if (typeof afterLogin === 'function') {
      const origAfter = afterLogin;
      window.afterLogin = afterLogin = async function () {
        const r = await origAfter.apply(this, arguments);
        try { if (STATE && STATE.empty && STATE.autosave && typeof restoreAutosave === 'function') await restoreAutosave(); } catch (e) {}
        return r;
      };
    }
    if (typeof markDirty === 'function' && typeof autosaveNow === 'function') {
      const origDirty = markDirty;
      let tmr = null;
      window.markDirty = markDirty = function () {
        const r = origDirty.apply(this, arguments);
        clearTimeout(tmr); tmr = setTimeout(() => autosaveNow(true), 4000);
        return r;
      };
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && STATE && !STATE.empty && STATE._ws && STATE._ws.dirty) autosaveNow(true);
      });
    }
    if (typeof downloadBlob !== 'function') return;
    const origDownload = downloadBlob;
    const tt = (k, fb) => { try { const v = t(k); return v && v !== k ? v : fb; } catch (e) { return fb; } };
    window.downloadBlob = downloadBlob = function (url) {
      const m = url.match(/api\/(download|storage)\/pdf(\?.*)?$/);
      if (!m) return origDownload(url);
      return webPrint('api/web/pdf_html' + (m[2] || ''));
    };
    async function webPrint(url) {
      let w = null;
      try { w = window.open('', '_blank'); } catch (e) { w = null; }
      if (w) { try { w.document.write('<p style="font-family:sans-serif;padding:24px">⏳ …</p>'); } catch (e) {} }
      let res;
      try { res = await fetch(url, { headers: typeof H === 'function' ? H() : {} }); } catch (e) { if (w) w.close(); return toast(e.message, 'err'); }
      if (!res.ok) { if (w) w.close(); const j = await res.json().catch(() => ({ message: 'HTTP ' + res.status })); return toast(j.message, 'err'); }
      const html = (await res.text()).replace('</body>', '<script>window.addEventListener("load",function(){setTimeout(function(){window.focus();window.print();},350)});<\/script></body>');
      if (w && !w.closed) {
        w.document.open(); w.document.write(html); w.document.close();
        toast(tt('web_pdf_print', 'Print → Save as PDF'));
        return;
      }
      toast(tt('web_popup', 'Printing…'));
      const f = document.createElement('iframe');
      f.setAttribute('style', 'position:fixed;right:0;bottom:0;width:0;height:0;border:0');
      document.body.appendChild(f);
      f.contentDocument.open(); f.contentDocument.write(html.replace(/<script>window\.addEventListener[\s\S]*?<\/script>/, '')); f.contentDocument.close();
      setTimeout(() => { try { f.contentWindow.focus(); f.contentWindow.print(); } catch (e) {} setTimeout(() => f.remove(), 60000); }, 500);
    }
  });
})();
