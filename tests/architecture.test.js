import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  SELECTORS,
  createInitialState,
  computeState,
  renderInput,
  renderDiff,
  renderCounts,
  renderRisk,
  renderColumns,
  renderPrivacy,
  renderAll,
} from '../app.js';

const ROOT_DIR = path.resolve(import.meta.dirname, '..');
const LOGIC_FILES = ['verhoeff.js', 'csvParser.js', 'detectors.js', 'redact.js', 'classify.js', 'report.js'];

test('pure logic modules have zero DOM or network API references', async () => {
  const forbidden = /\b(document|window|HTMLElement|localStorage|sessionStorage|fetch|XMLHttpRequest|navigator)\b/;
  for (const file of LOGIC_FILES) {
    const content = await fs.readFile(path.join(ROOT_DIR, file), 'utf8');
    assert.equal(forbidden.test(content), false, `${file} must not access DOM or browser APIs`);
  }
});

test('styles.css keeps all color values inside :root design tokens', async () => {
  const css = await fs.readFile(path.join(ROOT_DIR, 'styles.css'), 'utf8');
  const rootEnd = css.indexOf('}');
  assert.ok(css.startsWith('/*') && css.includes(':root {'));
  const rootStart = css.indexOf(':root {');
  const rootBlockEnd = css.indexOf('}', rootStart);
  const outsideRoot = css.slice(0, rootStart) + css.slice(rootBlockEnd + 1);

  const colorLiteral = /(#[0-9a-fA-F]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(|\boklch\s*\()/;
  assert.equal(colorLiteral.test(outsideRoot), false, 'Found hardcoded color outside :root in styles.css');

  for (const tokenPrefix of ['--color-', '--radius-', '--shadow-', '--space-', '--duration-', '--ease-']) {
    assert.ok(css.slice(rootStart, rootBlockEnd).includes(tokenPrefix), `Missing ${tokenPrefix} token in :root`);
  }
});

test('no inline styles appear in index.html, workbench.html, app.js, or motion.js', async () => {
  for (const file of ['index.html', 'workbench.html', 'app.js', 'motion.js']) {
    const content = await fs.readFile(path.join(ROOT_DIR, file), 'utf8');
    assert.equal(/\sstyle=/.test(content), false, `${file} must not contain inline style= attributes`);
    assert.equal(/\.style\./.test(content), false, `${file} must not mutate element.style directly`);
    assert.equal(/setAttribute\(\s*['"]style['"]/.test(content), false, `${file} must not set style attributes`);
  }
});

test('every stable data-testid selector used by app.js exists in workbench.html and landing links there', async () => {
  const workbenchHtml = await fs.readFile(path.join(ROOT_DIR, 'workbench.html'), 'utf8');
  for (const [key, selector] of Object.entries(SELECTORS)) {
    const match = selector.match(/\[data-testid="([^"]+)"\]/);
    assert.ok(match, `Selector ${key} should target data-testid`);
    const testId = match[1];
    assert.ok(workbenchHtml.includes(`data-testid="${testId}"`), `workbench.html missing data-testid="${testId}"`);
  }

  const landingHtml = await fs.readFile(path.join(ROOT_DIR, 'index.html'), 'utf8');
  assert.ok(landingHtml.includes('href="./workbench.html"'), 'index.html must link to ./workbench.html');
  assert.ok(workbenchHtml.includes('href="./index.html"'), 'workbench.html must link back to ./index.html');

  const manifestRaw = await fs.readFile(path.join(ROOT_DIR, 'public/manifest.json'), 'utf8');
  const manifest = JSON.parse(manifestRaw);
  assert.equal(manifest.short_name, 'VaultScrub');
  const swContent = await fs.readFile(path.join(ROOT_DIR, 'public/sw.js'), 'utf8');
  assert.ok(swContent.includes('PRECACHE_URLS'));
});

function createFakeDom() {
  const elementsByTestId = new Map();

  function makeNode(tagName = 'div') {
    const children = [];
    const attrs = {};
    const dataset = {};
    const node = {
      tagName: tagName.toUpperCase(),
      className: '',
      value: '',
      disabled: false,
      title: '',
      _textContent: '',
      dataset,
      children,
      set textContent(v) {
        this._textContent = String(v);
      },
      get textContent() {
        if (children.length === 0) return this._textContent;
        return children.map((c) => c.textContent).join('');
      },
      setAttribute(name, val) {
        attrs[name] = String(val);
        if (name === 'data-testid') elementsByTestId.set(String(val), node);
      },
      getAttribute(name) {
        return attrs[name];
      },
      appendChild(child) {
        if (child.isFragment) {
          for (const c of child.children) children.push(c);
        } else {
          children.push(child);
        }
        return child;
      },
      append(...items) {
        for (const item of items) this.appendChild(item);
      },
      replaceChildren(...items) {
        children.length = 0;
        for (const item of items) this.appendChild(item);
      },
    };

    const datasetProxy = new Proxy(dataset, {
      set(target, prop, val) {
        target[prop] = String(val);
        if (prop === 'testid') elementsByTestId.set(String(val), node);
        return true;
      },
    });
    node.dataset = datasetProxy;
    return node;
  }

  for (const selector of Object.values(SELECTORS)) {
    const testId = selector.match(/\[data-testid="([^"]+)"\]/)[1];
    const node = makeNode('div');
    node.setAttribute('data-testid', testId);
  }

  return {
    querySelector(selector) {
      const m = selector.match(/\[data-testid="([^"]+)"\]/);
      return m ? elementsByTestId.get(m[1]) || null : null;
    },
    createElement(tag) {
      return makeNode(tag);
    },
    createDocumentFragment() {
      return { isFragment: true, children: [], appendChild(c) { this.children.push(c); } };
    },
    getByTestId(id) {
      return elementsByTestId.get(id);
    },
  };
}

test('the six render functions populate the DOM cleanly from a single state object', () => {
  const fakeDoc = createFakeDom();
  const base = createInitialState();
  base.rawText = 'email,token\nalice@example.com,ghp_1234567890abcdef1234567890abcdef';
  const state = computeState(base);

  assert.equal(typeof renderInput, 'function');
  assert.equal(typeof renderDiff, 'function');
  assert.equal(typeof renderCounts, 'function');
  assert.equal(typeof renderRisk, 'function');
  assert.equal(typeof renderColumns, 'function');
  assert.equal(typeof renderPrivacy, 'function');

  renderAll(state, fakeDoc);

  assert.equal(fakeDoc.getByTestId('input-format-badge').dataset.format, 'csv');
  assert.equal(fakeDoc.getByTestId('risk-panel').dataset.riskLevel, 'critical');
  assert.equal(fakeDoc.getByTestId('counts-panel').dataset.empty, 'false');
  assert.equal(fakeDoc.getByTestId('columns-panel').dataset.hasColumns, 'true');
  assert.equal(fakeDoc.getByTestId('privacy-panel').dataset.localOnly, 'true');
  assert.ok(fakeDoc.getByTestId('diff-viewer').children.some((c) => c.dataset.segmentType === 'redacted'));
});
