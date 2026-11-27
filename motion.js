/**
 * @module motion
 * @description VaultScrub Kinetic Motion Engine — visual micro-interactions only.
 *
 * Manages pointer spotlight, scroll reveals, scan sweep animations, token
 * decode scramble, eased numeric counter interpolation, split-diff hover
 * linking with SVG connector, and sliding toast notifications.
 *
 * Zero coupling to detection/redaction/classification/report business logic.
 * Zero inline styles: uses CSS custom properties via CSSOM sheet and `data-*` hooks.
 *
 * Respects `prefers-reduced-motion: reduce` throughout — all animations are
 * skipped or resolved instantly when the user has enabled reduced motion.
 */

/** @constant {string} Character set for the token decode scramble animation. */
const SCRAMBLE_GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#*';

/** @constant {number} Maximum number of tokens to animate during decode scramble. */
const MAX_SCRAMBLE_TOKENS = 40;

/** @constant {number} Detection count above which per-finding animations are skipped. */
const PER_FINDING_CAP = 200;

function prefersReducedMotion() {
  return typeof window !== 'undefined'
    && Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
}

/**
 * Cursor-following spotlight via CSSOM stylesheet (--mx/--my) throttled by rAF.
 * Only active on fine-pointer devices and when reduced motion is off.
 */
function setupPointerSpotlight() {
  if (prefersReducedMotion()) return;
  if (!window.matchMedia?.('(hover: hover) and (pointer: fine)').matches) return;
  if (!('adoptedStyleSheets' in document) || typeof CSSStyleSheet === 'undefined') return;

  const sheet = new CSSStyleSheet();
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];

  let nextX = 0;
  let nextY = 0;
  let scheduled = false;

  const commit = () => {
    scheduled = false;
    sheet.replaceSync(`:root { --mx: ${nextX}px; --my: ${nextY}px; }`);
  };

  window.addEventListener('pointermove', (event) => {
    nextX = Math.round(event.clientX);
    nextY = Math.round(event.clientY);
    if (!scheduled) {
      scheduled = true;
      requestAnimationFrame(commit);
    }
  }, { passive: true });
}

/**
 * IntersectionObserver scroll reveals for below-the-fold insight cards.
 */
function setupScrollReveals() {
  const directionalItems = Array.from(document.querySelectorAll('[data-reveal][data-slide-dir]'));
  const standardCards = Array.from(document.querySelectorAll('[data-reveal]:not([data-slide-dir])'));

  if (prefersReducedMotion() || typeof IntersectionObserver === 'undefined') {
    [...directionalItems, ...standardCards].forEach((el) => { el.dataset.reveal = 'visible'; });
    return;
  }

  if (standardCards.length > 0) {
    const standardObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.dataset.reveal = 'visible';
          standardObserver.unobserve(entry.target);
        }
      }
    }, { rootMargin: '220px 0px', threshold: 0.01 });

    standardCards.forEach((el) => standardObserver.observe(el));
  }

  if (directionalItems.length > 0) {
    const slideObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.dataset.reveal = 'visible';
        } else if (entry.boundingClientRect.top > window.innerHeight * 0.92) {
          // Reset only when scrolled back above so scrolling downward replays the slide-in cleanly
          entry.target.dataset.reveal = 'hidden';
        }
      }
    }, { rootMargin: '0px 0px -36px 0px', threshold: 0.12 });

    directionalItems.forEach((el) => slideObserver.observe(el));
  }
}

/**
 * Trigger the glowing scan sweep beam over the diff viewer.
 */
function triggerScanSweep(detectionsCount) {
  const viewer = document.querySelector('[data-testid="diff-viewer"]');
  if (!viewer || prefersReducedMotion() || detectionsCount === 0 || detectionsCount > PER_FINDING_CAP) return;

  viewer.dataset.scanning = 'false';
  // Force single frame reset before toggling back on
  requestAnimationFrame(() => {
    viewer.dataset.scanning = 'true';
    window.setTimeout(() => {
      viewer.dataset.scanning = 'false';
    }, 700);
  });
}

/**
 * Brief (~300ms) decode/scramble animation on visible pseudonym tokens.
 */
function triggerTokenDecode(redactionMode) {
  if (prefersReducedMotion()) return;
  if (redactionMode !== 'token' && redactionMode !== 'hash') return;

  const tokens = Array.from(document.querySelectorAll('.diff-segment[data-segment-type="redacted"]'))
    .slice(0, MAX_SCRAMBLE_TOKENS);
  if (tokens.length === 0) return;

  const targets = tokens.map((el) => ({ el, finalText: el.textContent || '' }));
  const duration = 290;
  const start = performance.now();

  const frame = (now) => {
    const progress = Math.min(1, (now - start) / duration);
    for (const { el, finalText } of targets) {
      if (progress >= 1) {
        el.textContent = finalText;
        continue;
      }
      const settledChars = Math.floor(finalText.length * progress);
      let out = '';
      for (let i = 0; i < finalText.length; i += 1) {
        if (i < settledChars || finalText[i] === '[' || finalText[i] === ']' || finalText[i] === '_') {
          out += finalText[i];
        } else {
          out += SCRAMBLE_GLYPHS[(i * 7 + Math.floor(now / 35)) % SCRAMBLE_GLYPHS.length];
        }
      }
      el.textContent = out;
    }
    if (progress < 1) {
      requestAnimationFrame(frame);
    }
  };

  requestAnimationFrame(frame);
}

/**
 * Smoothly count numeric KPIs up/down (~400ms eased interpolation).
 */
const activeCounters = new WeakMap();
const previousCounts = new WeakMap();

function animateCounters() {
  const els = document.querySelectorAll('[data-target-count]');
  if (els.length === 0 || prefersReducedMotion()) return;

  els.forEach((el) => {
    const target = Number(el.dataset.targetCount || '0');
    const suffix = el.dataset.countSuffix || '';
    const from = previousCounts.has(el) ? previousCounts.get(el) : target;
    previousCounts.set(el, target);

    if (from === target) return;
    if (activeCounters.has(el)) cancelAnimationFrame(activeCounters.get(el));

    const duration = 380;
    const start = performance.now();

    const step = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - t) ** 3;
      const val = Math.round(from + (target - from) * eased);
      el.textContent = `${val}${suffix}`;
      if (t < 1) {
        activeCounters.set(el, requestAnimationFrame(step));
      } else {
        activeCounters.delete(el);
        el.textContent = `${target}${suffix}`;
      }
    };

    activeCounters.set(el, requestAnimationFrame(step));
  });
}

/**
 * Synchronized scrolling + hover entity pairing + SVG connector line in Split View.
 */
function setupSplitDiffLinking() {
  const stage = document.querySelector('[data-testid="output-stage"]');
  const left = document.querySelector('[data-testid="original-preview"]');
  const right = document.querySelector('[data-testid="diff-viewer"]');
  const svg = document.querySelector('[data-testid="diff-connector-svg"]');
  const path = document.querySelector('[data-testid="diff-connector-path"]');
  if (!stage || !left || !right || !svg || !path) return;

  let syncingLeft = false;
  let syncingRight = false;

  left.addEventListener('scroll', () => {
    if (syncingLeft) return;
    syncingRight = true;
    const ratio = left.scrollTop / Math.max(1, left.scrollHeight - left.clientHeight);
    right.scrollTop = ratio * Math.max(0, right.scrollHeight - right.clientHeight);
    requestAnimationFrame(() => { syncingRight = false; });
  }, { passive: true });

  right.addEventListener('scroll', () => {
    if (syncingRight) return;
    syncingLeft = true;
    const ratio = right.scrollTop / Math.max(1, right.scrollHeight - right.clientHeight);
    left.scrollTop = ratio * Math.max(0, left.scrollHeight - left.clientHeight);
    requestAnimationFrame(() => { syncingLeft = false; });
  }, { passive: true });

  const clearLinks = () => {
    stage.querySelectorAll('[data-linked="true"]').forEach((el) => {
      el.dataset.linked = 'false';
    });
    svg.dataset.active = 'false';
  };

  const linkFinding = (findingId) => {
    clearLinks();
    if (!findingId) return;

    const leftEl = left.querySelector(`[data-finding-id="${findingId}"]`);
    const rightEl = right.querySelector(`[data-finding-id="${findingId}"]`);
    if (leftEl) leftEl.dataset.linked = 'true';
    if (rightEl) rightEl.dataset.linked = 'true';

    if (leftEl && rightEl) {
      const stageRect = stage.getBoundingClientRect();
      const lRect = leftEl.getBoundingClientRect();
      const rRect = rightEl.getBoundingClientRect();

      const x1 = lRect.right - stageRect.left;
      const y1 = lRect.top + lRect.height / 2 - stageRect.top;
      const x2 = rRect.left - stageRect.left;
      const y2 = rRect.top + rRect.height / 2 - stageRect.top;
      const cx = (x1 + x2) / 2;

      path.setAttribute('d', `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`);
      svg.dataset.active = 'true';
    }
  };

  stage.addEventListener('pointerover', (event) => {
    const seg = event.target.closest('[data-finding-id]');
    if (seg) linkFinding(seg.dataset.findingId);
  });

  stage.addEventListener('pointerleave', clearLinks);
}

/**
 * Sliding toast notification stack (aria-live polite).
 */
function setupToasts() {
  const region = document.querySelector('[data-testid="toast-region"]');
  if (!region) return;

  window.addEventListener('vaultscrub:toast', (event) => {
    const msg = event.detail?.message;
    if (!msg) return;

    const toast = document.createElement('div');
    toast.className = 'toast-item';
    toast.textContent = msg;
    region.appendChild(toast);

    window.setTimeout(() => {
      toast.dataset.leaving = 'true';
      window.setTimeout(() => toast.remove(), 220);
    }, 2400);
  });
}

function setupMotion() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  setupPointerSpotlight();
  setupScrollReveals();
  setupSplitDiffLinking();
  setupToasts();

  window.addEventListener('vaultscrub:render', (event) => {
    const { reason, detectionsCount = 0, redactionMode = 'token' } = event.detail || {};
    animateCounters();
    if (reason === 'scan') {
      triggerScanSweep(detectionsCount);
    }
    if (reason === 'mode-change' && detectionsCount <= PER_FINDING_CAP) {
      triggerTokenDecode(redactionMode);
    }
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupMotion);
  } else {
    setupMotion();
  }
}
