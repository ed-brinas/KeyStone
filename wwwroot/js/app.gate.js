// Reusable Splash Gate with Matrix-esque background (blue)
// Usage: Gate.init({ rememberSession: true, scopeKey: '/admin' });
// If rememberSession = true, the page won't re-prompt in the same tab until reload.

window.Gate = (function () {
  const glyphs = '01░▒▓█▌▐◼◻◾◽◧◩◰◱◲◳▙▚▞▟';
  const palette = ['#68d7ff', '#3ec7ff', '#15baff', '#0aa7e6', '#0892c7'];
  let cfg = {
    rememberSession: true,
    scopeKey: window.location.pathname || '/',
    exitTo: 'about:blank',
    proceedText: 'Proceed',
    exitText: 'Exit',
    title: 'Authorized Use Notice',
    messageHtml:
      '<strong>Warning:</strong> Access to this page is <em>strictly monitored</em>. ' +
      'If you accessed this page by mistake, please close your browser now. ' +
      'To continue, press <strong>Proceed</strong> to accept the site’s terms and conditions.',
    footnoteHtml:
      'By clicking <em>Proceed</em>, you acknowledge your actions may be logged and reviewed by the security team.'
  };

  function acceptedKey() {
    return 'gateAccepted:' + cfg.scopeKey;
  }

  function createBackground() {
    if (document.getElementById('gate-matrix')) return; // already created
    const canvas = document.createElement('canvas');
    canvas.id = 'gate-matrix';
    const overlay = document.createElement('div');
    overlay.className = 'gate-overlay-grad';
    const scan = document.createElement('div');
    scan.className = 'gate-scan';

    document.body.appendChild(canvas);
    document.body.appendChild(overlay);
    document.body.appendChild(scan);

    const ctx = canvas.getContext('2d');
    let w, h, cols, drops, fontSize;

    function resize() {
      w = canvas.width  = window.innerWidth;
      h = canvas.height = window.innerHeight;
      fontSize = Math.max(12, Math.floor(w / 120));
      cols = Math.floor(w / fontSize);
      drops = new Array(cols).fill(0).map(()=>Math.floor(Math.random()*h/fontSize));
      ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
    }
    function draw() {
      ctx.fillStyle = 'rgba(0, 30, 50, 0.12)';
      ctx.fillRect(0, 0, w, h);
      for (let i = 0; i < drops.length; i++) {
        const char = glyphs[Math.floor(Math.random()*glyphs.length)];
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        const color = palette[Math.floor(Math.random()*palette.length)];
        ctx.shadowColor = color; ctx.shadowBlur = 8;
        ctx.fillStyle = color; ctx.fillText(char, x, y);
        if (y > h && Math.random() > 0.975) drops[i] = 0;
        drops[i] += (Math.random() * 0.8) + 0.6;
      }
      requestAnimationFrame(draw);
    }
    window.addEventListener('resize', resize);
    resize(); draw();
  }

  function createSplash() {
    if (document.getElementById('gate-splash')) return;
    const splash = document.createElement('div');
    splash.id = 'gate-splash';
    splash.innerHTML = `
      <div class="gate-center">
        <div class="gate-card card shadow-lg">
          <div class="card-body p-4 p-md-5">
            <h2 class="mb-3">${cfg.title}</h2>
            <p class="gate-warning mb-3">${cfg.messageHtml}</p>
            <div class="d-flex gap-2">
              <button id="gate-exit" class="btn btn-outline-warning">${cfg.exitText}</button>
              <button id="gate-proceed" class="btn gate-btn-accent">${cfg.proceedText}</button>
            </div>
            <p class="mt-3 text-muted small mb-0">${cfg.footnoteHtml}</p>
          </div>
        </div>
      </div>`;
    document.body.appendChild(splash);

    const exitBtn = document.getElementById('gate-exit');
    const proceedBtn = document.getElementById('gate-proceed');
    exitBtn.addEventListener('click', () => {
      try { window.close(); } catch(_) {}
      window.location.href = cfg.exitTo || 'about:blank';
    });
    proceedBtn.addEventListener('click', () => {
      hide();
      if (cfg.rememberSession) {
        try { sessionStorage.setItem(acceptedKey(), '1'); } catch {}
      }
    });
  }

  function show() {
    createBackground();
    createSplash();
    const splash = document.getElementById('gate-splash');
    if (splash) {
      splash.style.display = 'block';
      document.body.classList.add('gate-locked');
    }
  }

  function hide() {
    const splash = document.getElementById('gate-splash');
    if (splash) {
      splash.style.display = 'none';
      document.body.classList.remove('gate-locked');
    }
  }

  function shouldPrompt() {
    if (!cfg.rememberSession) return true;
    try { return sessionStorage.getItem(acceptedKey()) !== '1'; }
    catch { return true; }
  }

  function init(options) {
    cfg = Object.assign({}, cfg, options || {});
    if (shouldPrompt()) {
      show();
    } else {
      // ensure background is present (optional). Comment next line to skip bg when already accepted
      createBackground();
    }
  }

  return { init, show, hide };
})();
