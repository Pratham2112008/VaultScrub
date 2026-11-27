/**
 * @module landing
 * @description VaultScrub Monochrome 3D Fibonacci Sphere Archive (Landing Page)
 * Implements Splash + Intro Film, Fibonacci 21-card 3D Sphere,
 * Drag-to-rotate + Scroll Dolly, Flat Grid, FLIP Lightbox,
 * Full-Screen Menu, and Custom Cursor. Zero breaking coupling to workbench.html.
 */

const AVATAR_FILE = 'photo-vault.jpg';

const SHOTS = [
  { file: 'frame-01.svg', title: 'Verhoeff Aadhaar Shield', place: 'Module 01 · Checksum Guard', note: 'Validates 12-digit Indian Aadhaar numbers using the exact d, p, and inv Verhoeff tables—rejecting random 12-digit noise without sending a single byte.', href: './workbench.html?sample=india' },
  { file: 'frame-02.svg', title: 'PAN & GSTIN Precision', place: 'Module 02 · Tax & Identity', note: 'Detects 10-character Indian PAN and 15-character state-validated GSTIN identifiers across logs, spreadsheets, and documents.', href: './workbench.html?sample=india' },
  { file: 'photo-code.jpg', title: 'Developer Workspace Scrub', place: 'Module 03 · Source Guard', note: 'Scrub secrets, API tokens, and credentials straight from engineering logs and source snippets before pasting anywhere.', href: './workbench.html?sample=logs' },
  { file: 'frame-03.svg', title: 'UPI & IFSC Scrubbing', place: 'Module 04 · Payment Rails', note: 'Captures UPI VPA handles and 11-character IFSC bank codes seamlessly across Tokenize, Partial Mask, and Full Redaction modes.', href: './workbench.html?sample=india' },
  { file: 'frame-04.svg', title: 'Luhn Card Validation', place: 'Module 05 · Payment Cards', note: 'Verifies 13-to-19-digit credit card numbers via Luhn checksum before flagging or masking, eliminating false positives on order IDs.', href: './workbench.html?sample=logs' },
  { file: 'photo-vault.jpg', title: 'AES-GCM Key Vault', place: 'Module 06 · Web Crypto', note: 'Encrypts bidirectional pseudonym maps locally with PBKDF2 (250k iterations) and AES-GCM-256 into downloadable .vault.json keys.', href: './workbench.html?view=rehydrate' },
  { file: 'frame-05.svg', title: 'PBKDF2 Key Derivation', place: 'Module 07 · Client Crypto', note: '250,000-round PBKDF2-SHA256 key derivation with random 16-byte salts and 12-byte GCM IVs inside crypto.subtle.', href: './workbench.html?view=rehydrate' },
  { file: 'frame-06.svg', title: 'AI Prompt Re-hydration', place: 'Module 08 · Safe AI Loop', note: 'Send sanitized [EMAIL_1] and [PAN_1] tokens to any AI model, then decrypt and restore original values offline in browser memory.', href: './workbench.html?view=rehydrate' },
  { file: 'frame-07.svg', title: 'Interactive CSV Table', place: 'Module 09 · Tabular Policy', note: 'RFC-4180 client-side CSV parsing with per-column Redact/Keep switches and valid CSV export preserving quoted fields.', href: './workbench.html?sample=csv' },
  { file: 'frame-08.svg', title: 'Selective Whitelisting', place: 'Module 10 · Fine Control', note: 'Click any detected PII chip in Text or Table view to ignore one occurrence or whitelist all matching values live.', href: './workbench.html?sample=csv' },
  { file: 'photo-terminal.jpg', title: 'Local CLI & Log Hygiene', place: 'Module 11 · Terminal Feed', note: 'Paste raw terminal traces, .env dumps, or JSON payloads and inspect highlighted diffs side by side.', href: './workbench.html?sample=logs' },
  { file: 'frame-09.svg', title: 'Local PDF Extraction', place: 'Module 12 · PDF.js Worker', note: 'Extracts text from uploaded PDFs and resumes using a locally bundled pdfjs-dist worker—zero external CDN calls.', href: './workbench.html' },
  { file: 'frame-10.svg', title: 'Sanitized PDF Export', place: 'Module 13 · jsPDF Output', note: 'Generates clean multi-page sanitized PDF documents locally after scrubbing resumes, contracts, and incident reports.', href: './workbench.html' },
  { file: 'frame-11.svg', title: 'SHA-256 Integrity Proof', place: 'Module 14 · Web Crypto', note: 'Computes real SHA-256 digests for both raw input and sanitized output directly via crypto.subtle.digest.', href: './workbench.html?sample=logs' },
  { file: 'frame-12.svg', title: 'Audit Certificates', place: 'Module 15 · Compliance', note: 'Exports JSON and PDF Sanitization Audit Certificates with risk scores, category counts, and hashes—never raw PII.', href: './workbench.html?sample=logs' },
  { file: 'photo-server.jpg', title: 'Zero-Egress Architecture', place: 'Module 16 · No Backend', note: 'No remote servers, no telemetry, no uploads—all processing remains strictly inside local browser memory.', href: './workbench.html' },
  { file: 'frame-13.svg', title: 'Privacy Risk Gauge', place: 'Module 17 · Exposure Score', note: 'Weighted 0–100 exposure risk scoring across Critical, High, Medium, and Low tiers with before/after scrub tracking.', href: './workbench.html?sample=india' },
  { file: 'frame-14.svg', title: 'Offline PWA Engine', place: 'Module 18 · Service Worker', note: 'Pre-caches HTML, JS, CSS, and the PDF.js worker so the entire workbench runs even with Wi-Fi disabled.', href: './workbench.html' },
  { file: 'frame-15.svg', title: 'Cloud & VCS Secrets', place: 'Module 19 · API Tokens', note: 'Catches AWS access keys, GitHub PATs, Stripe keys, Slack tokens, JWTs, and embedded URL credentials.', href: './workbench.html?sample=logs' },
  { file: 'frame-20.svg', title: 'Zero-Trust CSP', place: 'Module 20 · Policy Guard', note: 'Strict connect-src self policy on the Workbench guarantees 0 bytes transmitted over the network at all times.', href: './workbench.html', tall: true },
  { file: 'frame-16.svg', title: 'PEM Private Keys', place: 'Launch · Client-Side', note: 'Detects multi-line RSA, EC, OpenSSH, and PGP private key blocks and neutralizes them in one pass.', href: './workbench.html?sample=logs' },
];

const splash = document.getElementById('splash');
const bar = document.getElementById('bar');
const intro = document.getElementById('intro');
const introCanvas = document.getElementById('introCanvas');
const skipBtn = document.getElementById('skip');
const stage = document.getElementById('stage');
const world = document.getElementById('world');
const orb = document.getElementById('orb');
const headline = document.getElementById('headline');
const gridRows = document.getElementById('gridRows');
const gridBtn = document.getElementById('gridBtn');
const menuBtn = document.getElementById('menuBtn');
const menu = document.getElementById('menu');
const lit = document.getElementById('lit');
const litPlate = document.getElementById('litPlate');
const litImg = document.getElementById('litImg');
const litTitle = document.getElementById('litTitle');
const litWhere = document.getElementById('litWhere');
const litNote = document.getElementById('litNote');
const litAction = document.getElementById('litAction');
const avatarImg = document.getElementById('avatar');
const dot = document.getElementById('dot');

const cards = [];
const gridFigs = [];
const decodedUrls = new Array(SHOTS.length).fill('');

let R = 360;
let persp = 1150;
let lastW = 0;
let lastH = 0;

let spin = 0;
const tilt = -4;
let camZ = 0;
let dragX = 0;
let dragY = 0;
let velX = 0;
let velY = 0;
let focused = -1;
let litSource = null;
let litToken = 0;
let revealed = false;

const coarseQuery = window.matchMedia?.('(pointer: coarse)');
const fineQuery = window.matchMedia?.('(hover: hover) and (pointer: fine)');

function thumbUrl(file) {
  return `./cards/${file}`;
}

function fullUrl(file) {
  return `./cards/${file}`;
}

function decodeCap() {
  const w = window.innerWidth;
  if (w <= 380) return 420;
  if (w <= 640) return 520;
  if (w <= 900) return 640;
  return 760;
}

function downscaleImage(url, maxWidth) {
  if (url.endsWith('.svg')) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => resolve(url);
      img.onerror = () => resolve(url);
      img.src = url;
    });
  }
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => {
      try {
        if (!img.naturalWidth || img.naturalWidth <= maxWidth) {
          resolve(url);
          return;
        }
        const scale = maxWidth / img.naturalWidth;
        const c = document.createElement('canvas');
        c.width = Math.round(img.naturalWidth * scale);
        c.height = Math.round(img.naturalHeight * scale);
        const ctx = c.getContext('2d');
        ctx.drawImage(img, 0, 0, c.width, c.height);
        c.toBlob((blob) => {
          resolve(blob ? URL.createObjectURL(blob) : url);
        }, 'image/webp', 0.88);
      } catch {
        resolve(url);
      }
    };
    img.onerror = () => resolve(url);
    img.src = url;
  });
}

function buildSphereAndGrid() {
  const N = SHOTS.length;
  const GA = Math.PI * (3 - Math.sqrt(5));

  for (let i = 0; i < N; i += 1) {
    const shot = SHOTS[i];
    const y = 1 - (i / (N - 1)) * 2;
    const rad = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = i * GA;
    const x = Math.cos(theta) * rad;
    const z = Math.sin(theta) * rad;
    const lat = Math.asin(y) * (180 / Math.PI);
    const lon = Math.atan2(x, z) * (180 / Math.PI);

    const card = document.createElement('div');
    card.className = shot.tall ? 'card tall' : 'card';
    card.dataset.idx = String(i);
    card._vec = { x, y, z, lat, lon };
    card._lastOpacity = '';
    card._lastDim = '';

    const fig = document.createElement('figure');
    const img = document.createElement('img');
    img.alt = shot.title;
    img.decoding = 'async';
    fig.appendChild(img);
    card.appendChild(fig);
    orb.appendChild(card);
    cards.push(card);

    const gFig = document.createElement('figure');
    gFig.dataset.idx = String(i);
    const gImg = document.createElement('img');
    gImg.alt = shot.title;
    gImg.decoding = 'async';
    const gCap = document.createElement('figcaption');
    gCap.textContent = shot.title;
    gFig.append(gImg, gCap);
    gridRows.appendChild(gFig);
    gridFigs.push(gFig);
  }
}

function layoutSphere(force = false) {
  const w = window.innerWidth;
  const h = window.innerHeight;
  if (!force && Math.abs(w - lastW) < 20 && Math.abs(h - lastH) < 20) return;
  lastW = w;
  lastH = h;

  const hr = w <= 380 ? 0.38 : w <= 640 ? 0.42 : 0.46;
  const wr = w <= 380 ? 0.48 : w <= 640 ? 0.52 : 0.58;
  const floor = w <= 380 ? 108 : w <= 640 ? 120 : 155;
  R = Math.max(floor, Math.min(480, h * hr, w * wr));

  const scale = w <= 380 ? 0.44 : w <= 640 ? 0.46 : 0.47;
  const cw = Math.round(Math.max(72, R * scale));
  persp = w <= 380 ? 620 : w <= 640 ? 760 : w <= 900 ? 920 : 1150;

  document.documentElement.style.setProperty('--cw', `${cw}px`);
  document.documentElement.style.setProperty('--persp', `${persp}px`);

  for (const card of cards) {
    const { x, y, z, lat, lon } = card._vec;
    card.style.transform = `translate3d(${(x * R).toFixed(2)}px, ${(-y * R).toFixed(2)}px, ${(z * R).toFixed(2)}px) rotateY(${lon.toFixed(2)}deg) rotateX(${lat.toFixed(2)}deg)`;
  }
}

function clampScroll() {
  const max = window.innerHeight * 0.16;
  if (window.scrollY > max) {
    window.scrollTo(0, max);
  }
  const p = Math.max(0, Math.min(1, window.scrollY / Math.max(1, max)));
  document.body.classList.toggle('deep', p > 0.35);
  return p;
}

let dragging = false;

function renderFrame() {
  if (!dragging && focused === -1) {
    dragX += velX;
    dragY += velY;
    velX *= 0.94;
    velY *= 0.94;
    if (Math.abs(velX) < 0.002) velX = 0;
    if (Math.abs(velY) < 0.002) velY = 0;
  }

  const maxPitch = 32;
  if (tilt + dragY > maxPitch) dragY = maxPitch - tilt;
  if (tilt + dragY < -maxPitch) dragY = -maxPitch - tilt;

  const p = clampScroll();
  const camZTarget = p * Math.min(64, R * 0.12);
  camZ += (camZTarget - camZ) * 0.075;

  const sx = tilt + dragY;
  const sy = spin + dragX;

  world.style.transform = `translateZ(${camZ.toFixed(2)}px) rotateY(${sy.toFixed(3)}deg) rotateX(${sx.toFixed(3)}deg)`;
  headline.style.transform = `rotateX(${(-sx).toFixed(3)}deg) rotateY(${(-sy).toFixed(3)}deg) translateZ(${(R * 0.62).toFixed(2)}px)`;
  headline.style.opacity = String(Math.max(0, 1 - p * 0.55));

  const radY = (sy * Math.PI) / 180;
  const radX = (sx * Math.PI) / 180;
  const cosY = Math.cos(radY);
  const sinY = Math.sin(radY);
  const cosX = Math.cos(radX);
  const sinX = Math.sin(radX);

  const near = persp * 0.66;
  const shade = 1 - Math.min(1, p * 1.6);

  for (let i = 0; i < cards.length; i += 1) {
    const card = cards[i];
    const { x, y, z } = card._vec;
    // Rotate unit vector by yaw (sy) then pitch (sx) matching CSS rotateY(sy) rotateX(sx)
    const x1 = x * cosY + z * sinY;
    const z1 = -x * sinY + z * cosY;
    const y2 = (-y) * cosX - z1 * sinX;
    const zf = (-y) * sinX + z1 * cosX;
    void x1;
    void y2;

    const norm = Math.max(0, Math.min(1, (zf + 1) / 2));
    const base = 0.14 + 0.86 * (norm ** 0.85);
    let dim = shade * (1 - base);
    const absZ = zf * R + camZ;
    let fade = absZ > near ? Math.max(0, 1 - (absZ - near) / 190) : 1;

    if (focused !== -1) {
      dim = Math.min(1, dim + 0.78);
      if (i === focused) fade = 0;
    }

    const fadeStr = fade.toFixed(3);
    const dimStr = dim.toFixed(3);
    if (card._lastOpacity !== fadeStr) {
      card.style.opacity = fadeStr;
      card._lastOpacity = fadeStr;
    }
    if (card._lastDim !== dimStr) {
      card.style.setProperty('--d', dimStr);
      card._lastDim = dimStr;
    }
  }
}

function loop() {
  renderFrame();
  requestAnimationFrame(loop);
}

/* ==========================================================================
   Drag-to-Rotate & Click Handling
   ========================================================================== */

function setupDragAndClicks() {
  let downX = 0;
  let downY = 0;
  let prevX = 0;
  let prevY = 0;
  let moved = 0;
  let downCardIdx = -1;
  let pointerId = null;
  let pendingTouch = false;

  stage.addEventListener('pointerdown', (event) => {
    if (focused !== -1 || document.body.classList.contains('gridview')) return;
    const hitCard = event.target.closest('.card');
    downCardIdx = hitCard ? Number(hitCard.dataset.idx) : -1;
    downX = event.clientX;
    downY = event.clientY;
    prevX = event.clientX;
    prevY = event.clientY;
    moved = 0;
    pointerId = event.pointerId;

    if (event.pointerType === 'touch') {
      pendingTouch = true;
      dragging = false;
    } else {
      pendingTouch = false;
      dragging = true;
      velX = 0;
      velY = 0;
      stage.setPointerCapture(pointerId);
    }
  });

  stage.addEventListener('pointermove', (event) => {
    if (pointerId !== event.pointerId) return;
    const totalDx = event.clientX - downX;
    const totalDy = event.clientY - downY;
    moved = Math.max(moved, Math.hypot(totalDx, totalDy));

    if (pendingTouch) {
      if (moved < 10) return;
      if (Math.abs(totalDy) > Math.abs(totalDx) * 1.15) {
        pendingTouch = false;
        pointerId = null;
        return;
      }
      pendingTouch = false;
      dragging = true;
      velX = 0;
      velY = 0;
      try {
        stage.setPointerCapture(pointerId);
      } catch {
        // Ignore capture failure on touch edge.
      }
    }

    if (!dragging) return;
    const dx = event.clientX - prevX;
    const dy = event.clientY - prevY;
    prevX = event.clientX;
    prevY = event.clientY;

    dragX += dx * 0.13;
    dragY -= dy * 0.13;
    velX = dx * 0.13 * 0.55;
    velY = -dy * 0.13 * 0.55;
  });

  const endPointer = (event) => {
    if (pointerId !== event.pointerId) return;
    const slop = coarseQuery?.matches ? 14 : 6;
    const clickedIdx = moved <= slop ? downCardIdx : -1;
    dragging = false;
    pendingTouch = false;
    pointerId = null;
    try {
      if (stage.hasPointerCapture(event.pointerId)) stage.releasePointerCapture(event.pointerId);
    } catch {
      // Ignore release errors.
    }
    if (clickedIdx >= 0) {
      openLightbox(clickedIdx, cards[clickedIdx]);
    }
  };

  stage.addEventListener('pointerup', endPointer);
  stage.addEventListener('pointercancel', endPointer);

  gridRows.addEventListener('click', (event) => {
    const fig = event.target.closest('figure[data-idx]');
    if (!fig) return;
    openLightbox(Number(fig.dataset.idx), fig);
  });
}

/* ==========================================================================
   FLIP Lightbox
   ========================================================================== */

function openLightbox(idx, sourceEl) {
  const shot = SHOTS[idx];
  if (!shot) return;
  focused = idx;
  litSource = sourceEl || cards[idx];
  const token = ++litToken;

  litTitle.textContent = shot.title;
  litWhere.textContent = shot.place;
  litNote.textContent = shot.note;
  litAction.href = shot.href || './workbench.html';
  litImg.alt = shot.title;
  litImg.src = decodedUrls[idx] || thumbUrl(shot.file);

  const full = new Image();
  full.onload = () => {
    if (token === litToken && focused === idx) {
      litImg.src = full.src;
    }
  };
  full.src = fullUrl(shot.file);

  const srcRect = litSource.getBoundingClientRect();
  document.body.classList.add('lit');
  lit.setAttribute('aria-hidden', 'false');
  document.documentElement.style.overflow = 'hidden';

  const dstRect = litPlate.getBoundingClientRect();
  const scale = Math.max(0.04, srcRect.width / Math.max(1, dstRect.width));
  const dx = (srcRect.left + srcRect.width / 2) - (dstRect.left + dstRect.width / 2);
  const dy = (srcRect.top + srcRect.height / 2) - (dstRect.top + dstRect.height / 2);

  litPlate.style.transition = 'none';
  litPlate.style.transform = `translate(${dx.toFixed(1)}px, ${dy.toFixed(1)}px) scale(${scale.toFixed(4)})`;
  litPlate.style.opacity = '0';
  litPlate.getBoundingClientRect();
  litPlate.style.transition = '';
  litPlate.style.transform = '';
  litPlate.style.opacity = '';
}

function closeLightbox() {
  if (focused === -1) return;
  const targetEl = litSource || cards[focused];
  focused = -1;
  litToken += 1;

  const srcRect = targetEl?.getBoundingClientRect();
  const dstRect = litPlate.getBoundingClientRect();

  if (srcRect && dstRect.width > 0) {
    const scale = Math.max(0.04, srcRect.width / dstRect.width);
    const dx = (srcRect.left + srcRect.width / 2) - (dstRect.left + dstRect.width / 2);
    const dy = (srcRect.top + srcRect.height / 2) - (dstRect.top + dstRect.height / 2);
    litPlate.style.transform = `translate(${dx.toFixed(1)}px, ${dy.toFixed(1)}px) scale(${scale.toFixed(4)})`;
    litPlate.style.opacity = '0';
  }

  document.body.classList.remove('lit');
  lit.setAttribute('aria-hidden', 'true');
  if (revealed) document.documentElement.style.overflow = '';

  window.setTimeout(() => {
    if (focused !== -1) return;
    litPlate.style.transition = 'none';
    litPlate.style.transform = '';
    litPlate.style.opacity = '';
    litPlate.getBoundingClientRect();
    litPlate.style.transition = '';
  }, 640);
}

/* ==========================================================================
   Menu, Grid Toggle & Custom Cursor
   ========================================================================== */

function toggleMenu(forceOpen) {
  const open = typeof forceOpen === 'boolean' ? forceOpen : !document.body.classList.contains('menu-open');
  document.body.classList.toggle('menu-open', open);
  menuBtn.setAttribute('aria-expanded', String(open));
  menu.setAttribute('aria-hidden', String(!open));
}

function setupControls() {
  lit.addEventListener('click', (event) => {
    if (event.target.closest('[data-close]')) closeLightbox();
  });

  gridBtn.addEventListener('click', () => {
    document.body.classList.toggle('gridview');
  });

  menuBtn.addEventListener('click', () => toggleMenu());

  menu.addEventListener('click', (event) => {
    const link = event.target.closest('a');
    if (!link) return;
    if (link.hasAttribute('data-grid')) {
      event.preventDefault();
      document.body.classList.add('gridview');
      toggleMenu(false);
    } else if (link.hasAttribute('data-close-menu')) {
      toggleMenu(false);
    } else {
      toggleMenu(false);
    }
  });

  window.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (document.body.classList.contains('lit')) {
      closeLightbox();
    } else if (document.body.classList.contains('menu-open')) {
      toggleMenu(false);
    } else if (document.body.classList.contains('gridview')) {
      document.body.classList.remove('gridview');
    }
  });
}

function setupCursor() {
  if (!fineQuery?.matches || !dot) return;
  let tx = -100;
  let ty = -100;
  let cx = -100;
  let cy = -100;

  window.addEventListener('pointermove', (event) => {
    tx = event.clientX;
    ty = event.clientY;
    const hoverTarget = event.target.closest('.card, a, button, #grid figure');
    dot.classList.toggle('wide', Boolean(hoverTarget));
  }, { passive: true });

  const step = () => {
    cx += (tx - cx) * 0.2;
    cy += (ty - cy) * 0.2;
    dot.style.transform = `translate3d(${cx.toFixed(1)}px, ${cy.toFixed(1)}px, 0)`;
    requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* ==========================================================================
   Splash & Intro Film Reveal Sequence
   ========================================================================== */

function runLocalCodeIntro(onComplete) {
  if (!introCanvas) {
    window.setTimeout(onComplete, 900);
    return () => {};
  }
  const ctx = introCanvas.getContext('2d');
  const codeLines = [
    'VAULTSCRUB // ZERO-EGRESS CLIENT ENGINE v2.0',
    'init crypto.subtle -> AES-GCM-256 + PBKDF2(250k)',
    'load verhoeff.js   -> d[c][p[i%8][digit]] == 0',
    'load detectors.js  -> PAN | AADHAAR | UPI | GSTIN | LUHN',
    'load pdfExtractor  -> local pdf.worker.min.mjs (offline)',
    'verify CSP         -> connect-src self (0 bytes sent)',
    'status             -> MEMORY ONLY · ARCHIVE READY',
  ];

  const start = performance.now();
  const duration = 1450;
  let active = true;

  const draw = (now) => {
    if (!active) return;
    const t = Math.min(1, (now - start) / duration);
    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, 1280, 720);

    // Subtle monochrome grid
    ctx.strokeStyle = 'rgba(244,242,239,0.04)';
    ctx.lineWidth = 1;
    for (let x = 0; x < 1280; x += 64) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, 720); ctx.stroke();
    }
    for (let y = 0; y < 720; y += 64) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(1280, y); ctx.stroke();
    }

    // Scanning horizon line
    const scanY = t * 720;
    const grad = ctx.createLinearGradient(0, scanY - 40, 0, scanY + 40);
    grad.addColorStop(0, 'rgba(244,242,239,0)');
    grad.addColorStop(0.5, 'rgba(244,242,239,0.16)');
    grad.addColorStop(1, 'rgba(244,242,239,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, scanY - 40, 1280, 80);

    // Terminal code reveal
    ctx.font = '400 18px ui-monospace, SFMono-Regular, Menlo, monospace';
    const visibleLines = Math.min(codeLines.length, Math.floor(t * (codeLines.length + 1.5)));
    for (let i = 0; i < visibleLines; i += 1) {
      ctx.fillStyle = i === visibleLines - 1 ? '#f4f2ef' : 'rgba(244,242,239,0.58)';
      ctx.fillText(codeLines[i], 140, 220 + i * 42);
    }

    if (t < 1) {
      requestAnimationFrame(draw);
    } else {
      onComplete();
    }
  };

  requestAnimationFrame(draw);
  return () => { active = false; };
}

function setupLoadingAndIntro() {
  const birth = performance.now();
  const totalAssets = SHOTS.length;
  let loadedCount = 0;
  let splashDone = false;
  let revealStarted = false;
  let stopIntroAnim = () => {};

  const bumpProgress = () => {
    loadedCount += 1;
    const ratio = Math.min(1, loadedCount / totalAssets);
    if (bar) bar.style.transform = `scaleX(${ratio.toFixed(3)})`;
  };

  const revealArchive = () => {
    if (revealStarted) return;
    revealStarted = true;
    stopIntroAnim();
    intro.classList.add('closing');
    document.body.classList.remove('locked');
    document.documentElement.style.overflow = '';

    layoutSphere(true);
    renderFrame();
    requestAnimationFrame(() => {
      layoutSphere(true);
      renderFrame();
    });

    window.setTimeout(() => {
      layoutSphere(true);
      renderFrame();
      revealed = true;
      document.body.classList.add('revealed');
      intro.classList.add('gone');
      window.setTimeout(() => intro.remove(), 700);
    }, 1000);
  };

  skipBtn.addEventListener('click', revealArchive);

  const startIntroSequence = () => {
    if (splashDone) return;
    splashDone = true;
    if (bar) bar.style.transform = 'scaleX(1)';
    splash.classList.add('out');
    window.setTimeout(() => splash.remove(), 950);
    stopIntroAnim = runLocalCodeIntro(revealArchive);
    window.setTimeout(revealArchive, 3200);
  };

  // Preload 21 local coding & security card assets + avatar
  const cap = decodeCap();
  const stillPromises = SHOTS.map((shot, idx) =>
    downscaleImage(thumbUrl(shot.file), cap).then((url) => {
      decodedUrls[idx] = url;
      const cardImg = cards[idx].querySelector('img');
      const gridImg = gridFigs[idx].querySelector('img');
      cardImg.src = url;
      gridImg.src = url;
      cardImg.classList.add('in');
      bumpProgress();
    }),
  );

  downscaleImage(thumbUrl(AVATAR_FILE), 160).then((url) => {
    if (avatarImg) avatarImg.src = url;
  });

  document.documentElement.style.overflow = 'hidden';
  window.setTimeout(startIntroSequence, 4500);

  Promise.all(stillPromises).then(() => {
    const elapsed = performance.now() - birth;
    const wait = Math.max(0, 950 - elapsed);
    window.setTimeout(startIntroSequence, wait);
  });
}

function init() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }

  buildSphereAndGrid();
  layoutSphere(true);
  renderFrame();
  requestAnimationFrame(loop);

  window.addEventListener('resize', () => layoutSphere(false));
  window.addEventListener('orientationchange', () => {
    window.setTimeout(() => layoutSphere(true), 220);
  });
  window.visualViewport?.addEventListener('resize', () => layoutSphere(true));
  window.visualViewport?.addEventListener('scroll', () => layoutSphere(true));

  setupDragAndClicks();
  setupControls();
  setupCursor();
  setupLoadingAndIntro();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
