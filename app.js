/**
 * @module app
 * @description VaultScrub UI Wiring & State Orchestrator.
 *
 * Connects stable `data-testid` DOM elements to pure logic modules
 * (`detectors`, `redact`, `classify`, `report`, `cryptoVault`, `auditReport`)
 * and renders via six focused render functions driven from a single immutable
 * state snapshot. No inline styles — all visual changes go through CSS custom
 * properties, `data-*` attributes, and class names.
 *
 * @architecture
 * - `createInitialState()` → initial state object
 * - `computeState(state)` → derived state with detections, redactions, risk, report
 * - `renderAll(state, root)` → six render functions update the DOM
 * - `initApp(root)` → wires DOM events, maintains state loop, returns `{ getState }`
 */

import { DETECTOR_CATALOG, detectSensitiveData, detectStructuredFormat } from './detectors.js';
import { redactText, redactStructuredDataset, maskValue } from './redact.js';
import { classifyRisk, classifyColumns } from './classify.js';
import { buildReport, formatReportAsJson, formatReportAsMarkdown } from './report.js';
import {
  encryptVaultMapping,
  decryptVaultMapping,
  rehydrateText,
  computeSha256Hex,
} from './cryptoVault.js';

/**
 * Frozen map of all `data-testid`-based CSS selectors used by the workbench.
 * Tests verify every selector has a matching element in `workbench.html`.
 * @type {Readonly<Record<string, string>>}
 */
export const SELECTORS = Object.freeze({
  appShell: '[data-testid="app-shell"]',
  inputSection: '[data-testid="input-section"]',
  inputTextarea: '[data-testid="input-textarea"]',
  inputFormatBadge: '[data-testid="input-format-badge"]',
  inputStats: '[data-testid="input-stats"]',
  inputModeSelect: '[data-testid="input-mode-select"]',
  redactionModeSelect: '[data-testid="redaction-mode-select"]',
  categoryFilters: '[data-testid="category-filters"]',

  fileUploadInput: '[data-testid="file-upload-input"]',
  fileUploadBtn: '[data-testid="file-upload-btn"]',
  fileDropStatus: '[data-testid="file-drop-status"]',
  fileDropLabel: '[data-testid="file-drop-label"]',
  parseProgressLabel: '[data-testid="parse-progress-label"]',

  sampleLogsBtn: '[data-testid="sample-logs-btn"]',
  sampleIndiaBtn: '[data-testid="sample-india-btn"]',
  sampleCsvBtn: '[data-testid="sample-csv-btn"]',
  sampleJsonBtn: '[data-testid="sample-json-btn"]',
  clearInputBtn: '[data-testid="clear-input-btn"]',

  themeSwitcher: '[data-testid="theme-switcher"]',
  themeBtnAuto: '[data-testid="theme-btn-auto"]',
  themeBtnLight: '[data-testid="theme-btn-light"]',
  themeBtnDark: '[data-testid="theme-btn-dark"]',

  diffSection: '[data-testid="diff-section"]',
  outputStage: '[data-testid="output-stage"]',
  diffConnectorSvg: '[data-testid="diff-connector-svg"]',
  diffConnectorPath: '[data-testid="diff-connector-path"]',
  originalPreview: '[data-testid="original-preview"]',
  diffViewer: '[data-testid="diff-viewer"]',
  cleanOutput: '[data-testid="clean-output"]',
  tableViewer: '[data-testid="table-viewer"]',
  rehydratePanel: '[data-testid="rehydrate-panel"]',
  rehydrateInput: '[data-testid="rehydrate-input"]',
  vaultFileInput: '[data-testid="vault-file-input"]',
  vaultFileBtn: '[data-testid="vault-file-btn"]',
  vaultFileLabel: '[data-testid="vault-file-label"]',
  rehydratePassphrase: '[data-testid="rehydrate-passphrase"]',
  rehydrateRunBtn: '[data-testid="rehydrate-run-btn"]',
  rehydrateOutput: '[data-testid="rehydrate-output"]',
  rehydrateCopyBtn: '[data-testid="rehydrate-copy-btn"]',
  rehydrateStatus: '[data-testid="rehydrate-status"]',

  viewTabDiff: '[data-testid="view-tab-diff"]',
  viewTabSplit: '[data-testid="view-tab-split"]',
  viewTabClean: '[data-testid="view-tab-clean"]',
  viewTabTable: '[data-testid="view-tab-table"]',
  viewTabRehydrate: '[data-testid="view-tab-rehydrate"]',

  whitelistBar: '[data-testid="whitelist-bar"]',
  whitelistTargetLabel: '[data-testid="whitelist-target-label"]',
  whitelistOneBtn: '[data-testid="whitelist-one-btn"]',
  whitelistAllBtn: '[data-testid="whitelist-all-btn"]',
  whitelistDismissBtn: '[data-testid="whitelist-dismiss-btn"]',
  whitelistResetBtn: '[data-testid="whitelist-reset-btn"]',

  copyOutputBtn: '[data-testid="copy-output-btn"]',
  exportCleanBtn: '[data-testid="export-clean-btn"]',
  exportPdfBtn: '[data-testid="export-pdf-btn"]',
  exportVaultBtn: '[data-testid="export-vault-btn"]',
  exportCertJsonBtn: '[data-testid="export-cert-json-btn"]',
  exportCertPdfBtn: '[data-testid="export-cert-pdf-btn"]',
  exportReportMdBtn: '[data-testid="export-report-md-btn"]',
  exportReportJsonBtn: '[data-testid="export-report-json-btn"]',
  actionFeedback: '[data-testid="action-feedback"]',
  toastRegion: '[data-testid="toast-region"]',

  vaultModal: '[data-testid="vault-modal"]',
  vaultPassphraseInput: '[data-testid="vault-passphrase-input"]',
  vaultModalError: '[data-testid="vault-modal-error"]',
  vaultCancelBtn: '[data-testid="vault-cancel-btn"]',
  vaultConfirmBtn: '[data-testid="vault-confirm-btn"]',

  zeroTrustInfoBtn: '[data-testid="zero-trust-info-btn"]',
  zeroTrustModal: '[data-testid="zero-trust-modal"]',
  zeroTrustOnlineDetail: '[data-testid="zero-trust-online-detail"]',
  zeroTrustCloseBtn: '[data-testid="zero-trust-close-btn"]',

  riskPanel: '[data-testid="risk-panel"]',
  riskBadge: '[data-testid="risk-badge"]',
  riskScore: '[data-testid="risk-score"]',
  riskDeltaPill: '[data-testid="risk-delta-pill"]',
  riskGaugeArc: '[data-testid="risk-gauge-arc"]',
  riskMeter: '[data-testid="risk-meter"]',
  riskSeverities: '[data-testid="risk-severities"]',
  riskReasons: '[data-testid="risk-reasons"]',
  hashOriginal: '[data-testid="hash-original"]',
  hashSanitized: '[data-testid="hash-sanitized"]',

  countsPanel: '[data-testid="counts-panel"]',
  countsTotal: '[data-testid="counts-total"]',
  countsUnique: '[data-testid="counts-unique"]',
  countsCategories: '[data-testid="counts-categories"]',
  countsList: '[data-testid="counts-list"]',

  columnsPanel: '[data-testid="columns-panel"]',
  columnsFormatHint: '[data-testid="columns-format-hint"]',
  columnsList: '[data-testid="columns-list"]',

  privacyPanel: '[data-testid="privacy-panel"]',
  privacyStatus: '[data-testid="privacy-status"]',
  privacyNetwork: '[data-testid="privacy-network"]',
  privacyStorage: '[data-testid="privacy-storage"]',
  privacyBytes: '[data-testid="privacy-bytes"]',
  privacyOnlineBadge: '[data-testid="privacy-online-badge"]',
});

/** @constant {string} localStorage key for persisted theme preference. */
const THEME_STORAGE_KEY = 'vaultscrub-theme';

/** @constant {number} Threshold above which per-finding animations are skipped for performance. */
const PER_FINDING_ANIMATION_CAP = 200;

/**
 * Pre-built sample datasets for one-click demo loading.
 * Each key maps to a formatted string ready for the input textarea.
 * @type {Readonly<Record<string, string>>}
 */
const SAMPLE_DATA = Object.freeze({
  logs: [
    '2026-11-27T09:14:22Z INFO auth-gateway user=maya.lin@acme-corp.io ip=192.168.14.22',
    '2026-11-27T09:14:23Z WARN billing-worker card=4532-0151-1283-0366 phone=(415) 555-0194',
    '2026-11-27T09:14:24Z ERROR deploy-hook url=https://ci_bot:SuperSecretPass99@git.internal/repo?token=ghp_1234567890abcdef1234567890abcdef',
    '2026-11-27T09:14:25Z DEBUG jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzQyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
  ].join('\n'),
  india: [
    'Customer Onboarding KYC Record (Synthetic Demo)',
    'Name: Aarav Sharma | PAN: ABCDE1234F | Aadhaar: 2341 5678 9014',
    'UPI Handle: aarav.sharma@okhdfcbank | Backup UPI: 9876543210@paytm',
    'Business GSTIN: 27ABCDE1234F1Z5 | Bank IFSC: HDFC0001234',
    'Phone: +91 98765 43210 | Email: aarav.sharma@example.in | IP: 103.21.244.10',
    'Invalid 12-digit noise (must NOT match Aadhaar): 999999999999 and 234156789013',
  ].join('\n'),
  csv: [
    'customer_id,full_name,email,ssn,phone,plan',
    '1001,Elena Rostova,elena.rostova@example.org,123-45-6789,415-555-0132,enterprise',
    '1002,Marcus Vance,marcus.vance@example.org,987-65-4321,212-555-0188,pro',
    '1003,Aria Chen,aria.chen@example.net,234-56-7890,650-555-0147,starter',
  ].join('\n'),
  json: JSON.stringify(
    [
      {
        service: 'payments-api',
        owner_email: 'oncall-payments@vaultscrub.test',
        stripe_key: 'sk_test_51N9xYzAbCdEfGhIjKlMnOpQr',
        source_ip: '10.24.8.15',
      },
      {
        service: 'partner-sync',
        owner_email: 'integrations@vaultscrub.test',
        iban: 'DE89370400440532013000',
        source_ip: '172.16.4.9',
      },
    ],
    null,
    2,
  ),
});

/**
 * Create the initial single application state object with defaults.
 * @returns {AppState} Fresh state with empty input, all detectors enabled, and token redaction mode.
 * @typedef {Object} AppState
 * @property {string} rawText - Current raw input text.
 * @property {'auto'|'text'|'csv'|'json'} inputMode - Input format override.
 * @property {'token'|'mask'|'hash'|'remove'} redactionMode - Active redaction strategy.
 * @property {'diff'|'split'|'clean'|'table'|'rehydrate'} activeView - Active output tab.
 * @property {'auto'|'light'|'dark'} theme - Current theme preference.
 * @property {Set<string>} enabledCategories - Active detector category IDs.
 * @property {Record<string, 'redact'|'keep'>} columnOverrides - Per-column action overrides.
 * @property {Set<string>} suppressedFindingIds - Single-finding ignore IDs.
 * @property {Set<string>} whitelistedValues - Globally whitelisted raw values.
 * @property {Object} privacy - Zero-trust privacy telemetry.
 */
export function createInitialState() {
  const enabledCategories = new Set(
    DETECTOR_CATALOG.filter((c) => c.defaultEnabled).map((c) => c.id),
  );
  return {
    rawText: '',
    inputMode: 'auto',
    redactionMode: 'token',
    activeView: 'diff',
    theme: 'auto',
    enabledCategories,
    columnOverrides: {},
    suppressedFindingIds: new Set(),
    whitelistedValues: new Set(),
    selectedWhitelistTarget: null,
    structured: { format: 'text', headers: [], rows: [], valid: true },
    detections: [],
    redacted: {
      originalText: '',
      scrubbedText: '',
      segments: [],
      replacements: [],
      mappingEntries: [],
      stats: { totalApplied: 0, uniqueValues: 0, originalLength: 0, scrubbedLength: 0 },
    },
    classification: {
      level: 'none',
      score: 0,
      countsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      reasons: ['Paste or load data to evaluate exposure risk.'],
    },
    columnReport: { format: 'text', columns: [] },
    report: null,
    hashes: { originalSha256: '—', sanitizedSha256: '—' },
    rehydrate: {
      vaultJsonText: '',
      vaultFileName: '',
      restoredText: '',
      statusMessage: '',
    },
    privacy: {
      localOnly: true,
      networkRequests: 0,
      persistence: 'memory-only',
      bytesProcessed: 0,
      isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true,
    },
    feedbackMessage: '',
    lastChangeReason: 'init',
  };
}

/**
 * Run all pure-logic modules to derive a fully computed state snapshot.
 *
 * Pipeline: detect → classify columns → redact → classify risk → build report.
 * This function is pure: given the same input state, it always returns
 * the same derived state (excluding object identity).
 *
 * @param {AppState} currentState - Current application state with rawText and config.
 * @returns {AppState} New state with computed detections, redacted output, risk, and report.
 */
export function computeState(currentState) {
  const structured = detectStructuredFormat(currentState.rawText, currentState.inputMode);
  const allDetections = detectSensitiveData(currentState.rawText, {
    enabledCategories: currentState.enabledCategories,
  });

  const suppressed = currentState.suppressedFindingIds instanceof Set
    ? currentState.suppressedFindingIds
    : new Set();
  const whitelisted = currentState.whitelistedValues instanceof Set
    ? currentState.whitelistedValues
    : new Set();

  const activeDetections = allDetections.filter(
    (item) => !suppressed.has(item.id) && !whitelisted.has(item.value),
  );

  const columnReport = classifyColumns(
    structured,
    detectSensitiveData,
    currentState.columnOverrides,
    { enabledCategories: currentState.enabledCategories },
  );

  const hasKeepOverride = columnReport.columns.some((col) => col.activeAction === 'keep');
  let redacted;
  if (structured.format !== 'text' && (hasKeepOverride || suppressed.size > 0 || whitelisted.size > 0)) {
    const effectiveOverrides = {};
    for (const col of columnReport.columns) {
      effectiveOverrides[col.name] = col.activeAction;
    }
    redacted = redactStructuredDataset(
      structured,
      effectiveOverrides,
      detectSensitiveData,
      {
        mode: currentState.redactionMode,
        enabledCategories: currentState.enabledCategories,
        suppressedFindingIds: suppressed,
        whitelistedValues: whitelisted,
      },
    ) || redactText(currentState.rawText, allDetections, {
      mode: currentState.redactionMode,
      suppressedFindingIds: suppressed,
      whitelistedValues: whitelisted,
    });
  } else {
    redacted = redactText(currentState.rawText, allDetections, {
      mode: currentState.redactionMode,
      suppressedFindingIds: suppressed,
      whitelistedValues: whitelisted,
    });
  }

  const classification = classifyRisk(activeDetections, currentState.rawText.length);
  const privacy = {
    ...currentState.privacy,
    bytesProcessed: currentState.rawText.length,
  };

  const nextState = {
    ...currentState,
    structured,
    detections: activeDetections,
    allDetections,
    redacted,
    classification,
    columnReport,
    privacy,
  };

  nextState.report = buildReport({
    rawText: nextState.rawText,
    detections: activeDetections,
    redacted: nextState.redacted,
    classification: nextState.classification,
    columnReport: nextState.columnReport,
    format: nextState.structured.format,
    redactionMode: nextState.redactionMode,
    privacy: nextState.privacy,
  });

  return nextState;
}

/**
 * Shorthand DOM query that delegates to `root.querySelector`.
 * @param {string} selector - CSS selector string.
 * @param {Document|DocumentFragment} [root=document] - Query root.
 * @returns {Element|null}
 */
function query(selector, root = document) {
  return root.querySelector(selector);
}

/**
 * Format a byte count into a human-readable string with units.
 * @param {number} bytes - Raw byte count.
 * @returns {string} Formatted string like "1.5 KB processed".
 */
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B processed`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB processed`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB processed`;
}

function createEmptyIllustration(root, message) {
  const wrap = root.createElement('div');
  wrap.className = 'empty-illustration-wrap';

  if (typeof root.createElementNS === 'function') {
    const svg = root.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'empty-shield-svg');
    svg.setAttribute('viewBox', '0 0 48 48');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('aria-hidden', 'true');

    const shield = root.createElementNS('http://www.w3.org/2000/svg', 'path');
    shield.setAttribute('d', 'M24 5L8 12v11c0 10.5 6.8 18.8 16 21 9.2-2.2 16-10.5 16-21V12L24 5z');
    shield.setAttribute('stroke', 'currentColor');
    shield.setAttribute('stroke-width', '2.5');
    shield.setAttribute('stroke-linejoin', 'round');

    const check = root.createElementNS('http://www.w3.org/2000/svg', 'path');
    check.setAttribute('d', 'M17 24l5 5 9-10');
    check.setAttribute('stroke', 'currentColor');
    check.setAttribute('stroke-width', '2.5');
    check.setAttribute('stroke-linecap', 'round');
    check.setAttribute('stroke-linejoin', 'round');

    svg.appendChild(shield);
    svg.appendChild(check);
    wrap.appendChild(svg);
  }

  const label = root.createElement('span');
  label.className = 'diff-empty';
  label.textContent = message;
  wrap.appendChild(label);
  return wrap;
}

function createSpan(root, className, text) {
  const span = root.createElement('span');
  span.className = className;
  span.textContent = text;
  return span;
}

/**
 * Render input controls, format badge, stats, and category filter toggles.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderInput(state, root = document) {
  const textarea = query(SELECTORS.inputTextarea, root);
  if (textarea && textarea.value !== state.rawText) {
    textarea.value = state.rawText;
  }

  const inputModeSelect = query(SELECTORS.inputModeSelect, root);
  if (inputModeSelect) inputModeSelect.value = state.inputMode;

  const redactionSelect = query(SELECTORS.redactionModeSelect, root);
  if (redactionSelect) redactionSelect.value = state.redactionMode;

  const formatBadge = query(SELECTORS.inputFormatBadge, root);
  if (formatBadge) {
    formatBadge.dataset.format = state.structured.format;
    formatBadge.textContent = state.structured.format.toUpperCase();
  }

  const statsEl = query(SELECTORS.inputStats, root);
  if (statsEl) {
    const lineCount = state.rawText.length === 0 ? 0 : state.rawText.split(/\r?\n/).length;
    statsEl.textContent = `${lineCount} lines · ${state.rawText.length} chars`;
  }

  const filtersContainer = query(SELECTORS.categoryFilters, root);
  if (filtersContainer) {
    const fragment = root.createDocumentFragment();
    for (const cat of DETECTOR_CATALOG) {
      const enabled = state.enabledCategories.has(cat.id);
      const button = root.createElement('button');
      button.type = 'button';
      button.className = 'category-chip';
      button.dataset.testid = `category-toggle-${cat.id}`;
      button.dataset.category = cat.id;
      button.dataset.severity = cat.severity;
      button.dataset.enabled = String(enabled);
      button.setAttribute('aria-pressed', String(enabled));
      button.textContent = cat.label;
      fragment.appendChild(button);
    }
    filtersContainer.replaceChildren(fragment);
  }
}

function renderInteractiveTable(state, root) {
  const tableViewer = query(SELECTORS.tableViewer, root);
  if (!tableViewer) return;

  const { format, headers, rows } = state.structured;
  if (format === 'text' || headers.length === 0) {
    tableViewer.replaceChildren(
      createEmptyIllustration(root, 'Load or paste CSV/JSON data to inspect it in Interactive Table View.'),
    );
    return;
  }

  const table = root.createElement('table');
  table.className = 'csv-table';

  const thead = root.createElement('thead');
  const headRow = root.createElement('tr');

  const colMap = new Map((state.columnReport.columns || []).map((c) => [c.name, c]));

  headers.forEach((header, idx) => {
    const th = root.createElement('th');
    th.className = 'csv-th';
    const colMeta = colMap.get(header);
    const activeAction = colMeta ? colMeta.activeAction : 'redact';

    const wrap = root.createElement('div');
    wrap.className = 'csv-th-inner';

    const title = root.createElement('span');
    title.textContent = header;

    const toggle = root.createElement('button');
    toggle.type = 'button';
    toggle.className = 'column-toggle-btn';
    toggle.dataset.testid = `table-col-toggle-${idx}`;
    toggle.dataset.action = 'toggle-column';
    toggle.dataset.column = header;
    toggle.dataset.columnAction = activeAction;
    toggle.textContent = activeAction === 'redact' ? 'Redact' : 'Keep';

    wrap.append(title, toggle);
    th.appendChild(wrap);
    headRow.appendChild(th);
  });

  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = root.createElement('tbody');
  const maxPreviewRows = Math.min(rows.length, 250);

  for (let rowIdx = 0; rowIdx < maxPreviewRows; rowIdx += 1) {
    const row = rows[rowIdx];
    const tr = root.createElement('tr');
    tr.className = 'csv-tr';

    for (const header of headers) {
      const td = root.createElement('td');
      td.className = 'csv-td';
      const cellValue = row[header] ?? '';
      const colAction = colMap.get(header)?.activeAction || 'redact';

      const findings = detectSensitiveData(cellValue, {
        enabledCategories: state.enabledCategories,
      }).filter((f) => {
        const scopedId = `${f.id}-r${rowIdx + 1}-${header}`;
        return !state.suppressedFindingIds.has(f.id)
          && !state.suppressedFindingIds.has(scopedId)
          && !state.whitelistedValues.has(f.value);
      });

      if (findings.length === 0 || colAction === 'keep') {
        td.textContent = cellValue;
      } else {
        td.dataset.hasPii = 'true';
        let cursor = 0;
        for (const f of findings) {
          if (f.start > cursor) {
            td.appendChild(createSpan(root, 'plain-cell-text', cellValue.slice(cursor, f.start)));
          }
          const chip = root.createElement('button');
          chip.type = 'button';
          chip.className = 'diff-segment table-pii-chip';
          chip.dataset.segmentType = 'redacted';
          chip.dataset.category = f.category;
          chip.dataset.severity = f.severity;
          chip.dataset.findingId = `${f.id}-r${rowIdx + 1}-${header}`;
          chip.dataset.rawValue = f.value;
          chip.dataset.label = f.label;
          chip.title = `${f.label}: click to ignore or whitelist`;
          chip.textContent = maskValue(f.value, f.category);
          td.appendChild(chip);
          cursor = f.end;
        }
        if (cursor < cellValue.length) {
          td.appendChild(createSpan(root, 'plain-cell-text', cellValue.slice(cursor)));
        }
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  tableViewer.replaceChildren(table);
}

/**
 * Render scrubbed output, highlighted diff segments, linked original segments, table view, and whitelist bar.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderDiff(state, root = document) {
  const diffSection = query(SELECTORS.diffSection, root);
  if (diffSection) {
    diffSection.dataset.view = state.activeView;
  }

  const tabMap = [
    [query(SELECTORS.viewTabDiff, root), 'diff'],
    [query(SELECTORS.viewTabSplit, root), 'split'],
    [query(SELECTORS.viewTabClean, root), 'clean'],
    [query(SELECTORS.viewTabTable, root), 'table'],
    [query(SELECTORS.viewTabRehydrate, root), 'rehydrate'],
  ];
  for (const [btn, viewName] of tabMap) {
    if (!btn) continue;
    const active = state.activeView === viewName;
    btn.dataset.active = String(active);
    btn.setAttribute('aria-pressed', String(active));
  }

  const tableTab = query(SELECTORS.viewTabTable, root);
  if (tableTab) {
    const isStructured = state.structured.format !== 'text' && state.structured.rows.length > 0;
    tableTab.disabled = !isStructured;
  }

  const whitelistBar = query(SELECTORS.whitelistBar, root);
  const whitelistCount = state.suppressedFindingIds.size + state.whitelistedValues.size;
  if (whitelistBar) {
    whitelistBar.dataset.open = String(Boolean(state.selectedWhitelistTarget) || whitelistCount > 0);
    whitelistBar.dataset.hasTarget = String(Boolean(state.selectedWhitelistTarget));
    whitelistBar.dataset.hasWhitelisted = String(whitelistCount > 0);
  }
  const whitelistLabel = query(SELECTORS.whitelistTargetLabel, root);
  if (whitelistLabel) {
    if (state.selectedWhitelistTarget) {
      const t = state.selectedWhitelistTarget;
      whitelistLabel.textContent = `Selected ${t.label} (${maskValue(t.value, t.category)}) — ignore this match or whitelist all occurrences?`;
    } else if (whitelistCount > 0) {
      whitelistLabel.textContent = `${whitelistCount} item(s) currently whitelisted from redaction.`;
    } else {
      whitelistLabel.textContent = 'Click any PII highlight to ignore or whitelist it.';
    }
  }
  const resetBtn = query(SELECTORS.whitelistResetBtn, root);
  if (resetBtn) {
    resetBtn.textContent = `Reset Whitelist (${whitelistCount})`;
    resetBtn.disabled = whitelistCount === 0;
  }

  const batchOnly = state.detections.length > PER_FINDING_ANIMATION_CAP;

  const originalPreview = query(SELECTORS.originalPreview, root);
  if (originalPreview) {
    if (!state.rawText) {
      originalPreview.replaceChildren(
        createEmptyIllustration(root, 'Original input preview will appear here.'),
      );
    } else if (batchOnly || state.detections.length === 0) {
      originalPreview.textContent = state.rawText;
    } else {
      const fragment = root.createDocumentFragment();
      let cursor = 0;
      for (const finding of state.detections) {
        if (finding.start < cursor || finding.end > state.rawText.length) continue;
        if (finding.start > cursor) {
          fragment.appendChild(createSpan(root, 'orig-segment', state.rawText.slice(cursor, finding.start)));
        }
        const mark = createSpan(root, 'orig-segment', finding.value);
        mark.dataset.findingId = finding.id;
        mark.dataset.category = finding.category;
        mark.dataset.severity = finding.severity;
        fragment.appendChild(mark);
        cursor = finding.end;
      }
      if (cursor < state.rawText.length) {
        fragment.appendChild(createSpan(root, 'orig-segment', state.rawText.slice(cursor)));
      }
      originalPreview.replaceChildren(fragment);
    }
  }

  const diffViewer = query(SELECTORS.diffViewer, root);
  if (diffViewer) {
    diffViewer.dataset.batchFade = String(batchOnly);
    if (!state.rawText) {
      diffViewer.replaceChildren(
        createEmptyIllustration(root, 'Scrubbed output will appear here as you type or upload a file.'),
      );
    } else {
      const fragment = root.createDocumentFragment();
      const isMorph = state.lastChangeReason === 'mode-change';
      for (const seg of state.redacted.segments) {
        const span = root.createElement('span');
        span.className = 'diff-segment';
        span.dataset.segmentType = seg.type;
        if (seg.type === 'redacted') {
          span.dataset.category = seg.category;
          span.dataset.severity = seg.severity;
          span.dataset.findingId = seg.findingId;
          span.dataset.rawValue = seg.originalText;
          span.dataset.label = seg.label;
          if (!batchOnly && isMorph) {
            span.dataset.morph = 'true';
          }
          span.title = `${seg.label} (${seg.severity}) — click to whitelist`;
        }
        span.textContent = seg.text;
        fragment.appendChild(span);
      }
      diffViewer.replaceChildren(fragment);
    }
  }

  const cleanOutput = query(SELECTORS.cleanOutput, root);
  if (cleanOutput) {
    cleanOutput.value = state.redacted.scrubbedText;
  }

  renderInteractiveTable(state, root);

  const rehydrateOutput = query(SELECTORS.rehydrateOutput, root);
  if (rehydrateOutput) rehydrateOutput.value = state.rehydrate.restoredText;

  const rehydrateStatus = query(SELECTORS.rehydrateStatus, root);
  if (rehydrateStatus) rehydrateStatus.textContent = state.rehydrate.statusMessage;

  const vaultFileLabel = query(SELECTORS.vaultFileLabel, root);
  if (vaultFileLabel) {
    vaultFileLabel.textContent = state.rehydrate.vaultFileName || 'No key file selected';
  }

  const hasText = state.rawText.length > 0;
  for (const selector of [
    SELECTORS.copyOutputBtn,
    SELECTORS.exportCleanBtn,
    SELECTORS.exportPdfBtn,
    SELECTORS.exportCertJsonBtn,
    SELECTORS.exportCertPdfBtn,
    SELECTORS.exportReportMdBtn,
    SELECTORS.exportReportJsonBtn,
  ]) {
    const btn = query(selector, root);
    if (btn) btn.disabled = !hasText;
  }

  const vaultBtn = query(SELECTORS.exportVaultBtn, root);
  if (vaultBtn) {
    const canExportVault = state.redactionMode === 'token' && (state.redacted.mappingEntries?.length || 0) > 0;
    vaultBtn.disabled = !canExportVault;
  }

  const feedback = query(SELECTORS.actionFeedback, root);
  if (feedback) {
    feedback.textContent = state.feedbackMessage;
  }
}

/**
 * Render detection count KPIs and per-category breakdown rows.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderCounts(state, root = document) {
  const report = state.report;
  const countsPanel = query(SELECTORS.countsPanel, root);
  const categories = report?.countsByCategory || [];

  if (countsPanel) {
    countsPanel.dataset.empty = String(categories.length === 0);
  }

  const totalEl = query(SELECTORS.countsTotal, root);
  if (totalEl) {
    const count = report?.summary.totalFindings ?? 0;
    totalEl.dataset.targetCount = String(count);
    totalEl.dataset.countSuffix = ' findings';
    totalEl.textContent = `${count} findings`;
  }

  const uniqueEl = query(SELECTORS.countsUnique, root);
  if (uniqueEl) {
    const count = report?.summary.uniqueValues ?? 0;
    uniqueEl.dataset.targetCount = String(count);
    uniqueEl.dataset.countSuffix = ' unique';
    uniqueEl.textContent = `${count} unique`;
  }

  const catEl = query(SELECTORS.countsCategories, root);
  if (catEl) {
    const count = categories.length;
    catEl.dataset.targetCount = String(count);
    catEl.dataset.countSuffix = ' types';
    catEl.textContent = `${count} types`;
  }

  const listEl = query(SELECTORS.countsList, root);
  if (!listEl) return;

  if (categories.length === 0) {
    const empty = root.createElement('li');
    empty.className = 'empty-state';
    empty.textContent = 'No sensitive patterns detected.';
    listEl.replaceChildren(empty);
    return;
  }

  const fragment = root.createDocumentFragment();
  for (const item of categories) {
    const li = root.createElement('li');
    li.className = 'count-row';
    li.dataset.category = item.category;
    li.dataset.severity = item.severity;
    li.dataset.count = String(item.count);

    const label = root.createElement('span');
    label.className = 'count-row-label';
    label.textContent = item.label;

    const meta = root.createElement('div');
    meta.className = 'count-row-meta';

    const sev = root.createElement('span');
    sev.className = 'severity-pill';
    sev.dataset.severity = item.severity;
    sev.textContent = item.severity;

    const count = root.createElement('span');
    count.textContent = String(item.count);

    meta.append(sev, count);
    li.append(label, meta);
    fragment.appendChild(li);
  }
  listEl.replaceChildren(fragment);
}

/**
 * Render overall exposure risk score, SVG arc gauge, severities, reasons, and SHA-256 hashes.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderRisk(state, root = document) {
  const { level, score, countsBySeverity, reasons } = state.classification;

  const panel = query(SELECTORS.riskPanel, root);
  if (panel) {
    panel.dataset.riskLevel = level;
    panel.dataset.score = String(score);
  }

  const badge = query(SELECTORS.riskBadge, root);
  if (badge) {
    badge.dataset.riskLevel = level;
    badge.textContent = level.toUpperCase();
  }

  const scoreEl = query(SELECTORS.riskScore, root);
  if (scoreEl) {
    scoreEl.dataset.targetCount = String(score);
    scoreEl.dataset.countSuffix = ' / 100';
    scoreEl.textContent = `${score} / 100`;
  }

  const deltaPill = query(SELECTORS.riskDeltaPill, root);
  if (deltaPill) {
    const residualFindings = state.detections.length - (state.redacted?.stats?.totalApplied ?? 0);
    const afterScore = residualFindings <= 0 ? 0 : Math.max(5, Math.round(score * (residualFindings / Math.max(1, state.detections.length))));
    deltaPill.textContent = `After scrub: ${afterScore} / 100`;
  }

  const gaugeArc = query(SELECTORS.riskGaugeArc, root);
  if (gaugeArc) {
    const clamped = Math.max(0, Math.min(100, score));
    gaugeArc.setAttribute('stroke-dashoffset', String(100 - clamped));
  }

  const meter = query(SELECTORS.riskMeter, root);
  if (meter) {
    meter.value = score;
    meter.dataset.riskLevel = level;
  }

  const sevContainer = query(SELECTORS.riskSeverities, root);
  if (sevContainer) {
    const fragment = root.createDocumentFragment();
    for (const sevName of ['critical', 'high', 'medium', 'low']) {
      const pill = root.createElement('span');
      pill.className = 'severity-pill';
      pill.dataset.severity = sevName;
      pill.textContent = `${sevName}: ${countsBySeverity[sevName] ?? 0}`;
      fragment.appendChild(pill);
    }
    sevContainer.replaceChildren(fragment);
  }

  const reasonsEl = query(SELECTORS.riskReasons, root);
  if (reasonsEl) {
    const fragment = root.createDocumentFragment();
    for (const reason of reasons) {
      const li = root.createElement('li');
      li.className = 'risk-reason-item';
      li.textContent = reason;
      fragment.appendChild(li);
    }
    reasonsEl.replaceChildren(fragment);
  }

  const hashOrig = query(SELECTORS.hashOriginal, root);
  if (hashOrig) hashOrig.textContent = state.hashes?.originalSha256 || '—';

  const hashClean = query(SELECTORS.hashSanitized, root);
  if (hashClean) hashClean.textContent = state.hashes?.sanitizedSha256 || '—';
}

/**
 * Render structured dataset columns (CSV/JSON) with per-column redact/keep controls.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderColumns(state, root = document) {
  const { format, columns } = state.columnReport;
  const panel = query(SELECTORS.columnsPanel, root);
  if (panel) {
    panel.dataset.format = format;
    panel.dataset.hasColumns = String(columns.length > 0);
  }

  const hint = query(SELECTORS.columnsFormatHint, root);
  if (hint) {
    hint.textContent = columns.length > 0
      ? `${format.toUpperCase()} · ${columns.length} columns`
      : 'Unstructured text';
  }

  const list = query(SELECTORS.columnsList, root);
  if (!list) return;

  if (columns.length === 0) {
    const empty = root.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'Paste or upload CSV / JSON data to classify and toggle individual columns.';
    list.replaceChildren(empty);
    return;
  }

  const fragment = root.createDocumentFragment();
  columns.forEach((col, index) => {
    const row = root.createElement('div');
    row.className = 'column-row';
    row.dataset.columnName = col.name;
    row.dataset.riskLevel = col.riskLevel;
    row.dataset.columnAction = col.activeAction;

    const nameSpan = root.createElement('span');
    nameSpan.className = 'column-name';
    nameSpan.textContent = col.name;

    const meta = root.createElement('div');
    meta.className = 'column-meta';

    const hitText = root.createElement('span');
    hitText.textContent = col.categories.length > 0
      ? `${col.hitRate}% (${col.categories.join(', ')})`
      : `${col.hitRate}%`;

    const sev = root.createElement('span');
    sev.className = 'severity-pill';
    sev.dataset.severity = col.riskLevel === 'none' ? 'low' : col.riskLevel;
    sev.textContent = col.riskLevel;

    const toggleBtn = root.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'column-toggle-btn';
    toggleBtn.dataset.testid = `column-toggle-${index}`;
    toggleBtn.dataset.action = 'toggle-column';
    toggleBtn.dataset.column = col.name;
    toggleBtn.textContent = col.activeAction === 'redact' ? 'Redact' : 'Keep';

    meta.append(hitText, sev, toggleBtn);
    row.append(nameSpan, meta);
    fragment.appendChild(row);
  });

  list.replaceChildren(fragment);
}

/**
 * Render local-only privacy guarantees, lock state, live online/offline status, and processed volume telemetry.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderPrivacy(state, root = document) {
  const { localOnly, networkRequests, persistence, bytesProcessed, isOnline } = state.privacy;
  const panel = query(SELECTORS.privacyPanel, root);
  if (panel) {
    panel.dataset.localOnly = String(localOnly);
    panel.dataset.networkCalls = String(networkRequests);
    panel.dataset.persistence = persistence;
    panel.dataset.scanLocked = String(bytesProcessed > 0);
  }

  const statusEl = query(SELECTORS.privacyStatus, root);
  if (statusEl) {
    statusEl.textContent = localOnly ? '0 Bytes Sent • 100% Local' : 'External Mode';
  }

  const netEl = query(SELECTORS.privacyNetwork, root);
  if (netEl) netEl.textContent = `Network requests: ${networkRequests}`;

  const storageEl = query(SELECTORS.privacyStorage, root);
  if (storageEl) storageEl.textContent = persistence === 'memory-only' ? 'Memory only' : persistence;

  const bytesEl = query(SELECTORS.privacyBytes, root);
  if (bytesEl) bytesEl.textContent = formatBytes(bytesProcessed);

  const onlineText = isOnline ? 'Online • Offline Ready' : 'Offline Mode';
  const onlineEl = query(SELECTORS.privacyOnlineBadge, root);
  if (onlineEl) onlineEl.textContent = onlineText;

  const onlineDetail = query(SELECTORS.zeroTrustOnlineDetail, root);
  if (onlineDetail) {
    onlineDetail.textContent = isOnline
      ? 'Browser reports Online — offline Service Worker cache is active.'
      : 'Browser is Offline (Wi-Fi disabled) — running 100% from local PWA cache.';
  }
}

/**
 * Run all six UI render functions from the single state object.
 * @param {object} state
 * @param {Document} [root=document]
 */
export function renderAll(state, root = document) {
  renderInput(state, root);
  renderDiff(state, root);
  renderCounts(state, root);
  renderRisk(state, root);
  renderColumns(state, root);
  renderPrivacy(state, root);
}

/**
 * Trigger a browser file download from in-memory content.
 * Creates a temporary object URL, clicks a hidden link, then cleans up.
 * @param {string} filename - Suggested download filename.
 * @param {string|Blob} content - File content (string or Blob).
 * @param {string} mimeType - MIME type for string content.
 */
function triggerDownload(filename, content, mimeType) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/**
 * Apply a theme choice to the document and persist it in localStorage.
 * @param {'auto'|'light'|'dark'} themeChoice - Theme to apply.
 * @param {Document} [root=document] - Document root for DOM queries.
 */
function applyTheme(themeChoice, root = document) {
  const valid = themeChoice === 'light' || themeChoice === 'dark' ? themeChoice : 'auto';
  root.documentElement.dataset.theme = valid;

  for (const [sel, val] of [
    [SELECTORS.themeBtnAuto, 'auto'],
    [SELECTORS.themeBtnLight, 'light'],
    [SELECTORS.themeBtnDark, 'dark'],
  ]) {
    const btn = query(sel, root);
    if (!btn) continue;
    const active = valid === val;
    btn.dataset.active = String(active);
    btn.setAttribute('aria-pressed', String(active));
  }

  try {
    localStorage.setItem(THEME_STORAGE_KEY, valid);
  } catch {
    // Ignore storage restriction errors cleanly.
  }
}

/**
 * Load the saved theme preference from localStorage.
 * Returns 'auto' if storage is unavailable or the saved value is invalid.
 * @returns {'auto'|'light'|'dark'}
 */
function loadSavedTheme() {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    return saved === 'light' || saved === 'dark' || saved === 'auto' ? saved : 'auto';
  } catch {
    return 'auto';
  }
}

/**
 * Wire DOM events and maintain the single state loop.
 * @param {Document} [root=document]
 * @returns {{ getState: () => object }}
 */
export function initApp(root = document) {
  const shell = query(SELECTORS.appShell, root);
  if (shell) shell.dataset.booted = 'true';

  if (typeof navigator !== 'undefined' && 'serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }

  let state = computeState(createInitialState());
  const savedTheme = loadSavedTheme();
  state.theme = savedTheme;
  applyTheme(savedTheme, root);
  renderAll(state, root);

  let cancelTypewriter = null;
  let hashSequence = 0;

  const refreshHashes = async (snapshot) => {
    const seq = ++hashSequence;
    if (!snapshot.rawText) {
      state = { ...state, hashes: { originalSha256: '—', sanitizedSha256: '—' } };
      renderRisk(state, root);
      return;
    }
    try {
      const [origHash, cleanHash] = await Promise.all([
        computeSha256Hex(snapshot.rawText),
        computeSha256Hex(snapshot.redacted.scrubbedText),
      ]);
      if (seq !== hashSequence) return;
      state = { ...state, hashes: { originalSha256: origHash, sanitizedSha256: cleanHash } };
      renderRisk(state, root);
    } catch {
      // Ignore if subtle crypto is unavailable in non-secure test contexts.
    }
  };

  const emitMotionSignal = (detail) => {
    if (typeof window !== 'undefined' && typeof CustomEvent === 'function') {
      window.dispatchEvent(new CustomEvent('vaultscrub:render', { detail }));
    }
  };

  const emitToast = (message) => {
    if (typeof window !== 'undefined' && typeof CustomEvent === 'function') {
      window.dispatchEvent(new CustomEvent('vaultscrub:toast', { detail: { message } }));
    }
  };

  const updateAndRender = (patch, options = {}) => {
    const merged = { ...state, ...patch };
    if (options.resetColumns) {
      merged.columnOverrides = {};
      merged.suppressedFindingIds = new Set();
      merged.whitelistedValues = new Set();
      merged.selectedWhitelistTarget = null;
    }
    state = computeState(merged);
    renderAll(state, root);
    refreshHashes(state);
    emitMotionSignal({
      reason: state.lastChangeReason,
      detectionsCount: state.detections.length,
      redactionMode: state.redactionMode,
    });
  };

  const runTypewriterSample = (sampleText, label) => {
    if (cancelTypewriter) cancelTypewriter();
    const reduced = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (reduced || sampleText.length > 3500) {
      updateAndRender(
        { rawText: sampleText, inputMode: 'auto', feedbackMessage: label, lastChangeReason: 'scan' },
        { resetColumns: true },
      );
      emitToast(label);
      return;
    }

    const textarea = query(SELECTORS.inputTextarea, root);
    const totalDuration = 580;
    const startTime = performance.now();
    let rafId = 0;
    let active = true;

    cancelTypewriter = () => {
      active = false;
      cancelAnimationFrame(rafId);
      cancelTypewriter = null;
    };

    const step = (now) => {
      if (!active) return;
      const progress = Math.min(1, (now - startTime) / totalDuration);
      const count = Math.max(1, Math.floor(sampleText.length * progress));
      if (textarea) textarea.value = sampleText.slice(0, count);
      if (progress < 1) {
        rafId = requestAnimationFrame(step);
      } else {
        cancelTypewriter = null;
        updateAndRender(
          { rawText: sampleText, inputMode: 'auto', feedbackMessage: label, lastChangeReason: 'scan' },
          { resetColumns: true },
        );
        emitToast(label);
      }
    };

    rafId = requestAnimationFrame(step);
  };

  const loadFileIntoWorkbench = async (file) => {
    if (!file) return;
    if (cancelTypewriter) cancelTypewriter();
    const inputSection = query(SELECTORS.inputSection, root);
    const dropStatus = query(SELECTORS.fileDropStatus, root);
    const dropLabel = query(SELECTORS.fileDropLabel, root);
    const progressLabel = query(SELECTORS.parseProgressLabel, root);

    if (dropStatus) dropStatus.dataset.uploadState = 'loading';
    if (dropLabel) dropLabel.textContent = `Loading ${file.name} locally…`;

    const isPdf = file.name.toLowerCase().endsWith('.pdf') || file.type === 'application/pdf';
    const isLarge = isPdf || file.size > 30000;
    if (isLarge && inputSection) {
      inputSection.dataset.parsing = 'true';
      if (progressLabel) progressLabel.textContent = `Extracting ${file.name} locally… 25%`;
    }

    try {
      let content = '';
      if (isPdf) {
        const buffer = await file.arrayBuffer();
        const { extractTextFromPdf } = await import('./pdfExtractor.js');
        const result = await extractTextFromPdf(buffer, (pct) => {
          if (progressLabel) progressLabel.textContent = `Extracting ${file.name} locally… ${pct}%`;
        });
        content = result.text;
        if (dropLabel) dropLabel.textContent = `Loaded ${file.name} (${result.pageCount} page${result.pageCount === 1 ? '' : 's'})`;
      } else {
        content = await file.text();
        if (dropLabel) dropLabel.textContent = `Loaded ${file.name} (${file.size.toLocaleString()} B)`;
      }

      if (inputSection) inputSection.dataset.parsing = 'false';
      if (dropStatus) dropStatus.dataset.uploadState = 'done';

      const nextView = file.name.toLowerCase().endsWith('.csv') ? 'table' : state.activeView;
      updateAndRender(
        {
          rawText: content,
          inputMode: 'auto',
          activeView: nextView,
          feedbackMessage: `Loaded ${file.name}.`,
          lastChangeReason: 'scan',
        },
        { resetColumns: true },
      );
      emitToast(`Loaded ${file.name} locally`);
    } catch (err) {
      if (inputSection) inputSection.dataset.parsing = 'false';
      if (dropStatus) dropStatus.dataset.uploadState = 'idle';
      if (dropLabel) dropLabel.textContent = 'Drop a .txt, .csv, .json, or .pdf file here';
      emitToast(err?.message || `Could not read ${file.name}.`);
    }
  };

  const textarea = query(SELECTORS.inputTextarea, root);
  textarea?.addEventListener('input', (event) => {
    if (cancelTypewriter) cancelTypewriter();
    updateAndRender(
      { rawText: event.target.value, feedbackMessage: '', lastChangeReason: 'scan' },
      { resetColumns: true },
    );
  });

  query(SELECTORS.inputModeSelect, root)?.addEventListener('change', (event) => {
    updateAndRender(
      { inputMode: event.target.value, feedbackMessage: '', lastChangeReason: 'scan' },
      { resetColumns: true },
    );
  });

  query(SELECTORS.redactionModeSelect, root)?.addEventListener('change', (event) => {
    updateAndRender({
      redactionMode: event.target.value,
      feedbackMessage: '',
      lastChangeReason: 'mode-change',
    });
  });

  query(SELECTORS.categoryFilters, root)?.addEventListener('click', (event) => {
    const btn = event.target.closest('[data-category]');
    if (!btn) return;
    const categoryId = btn.dataset.category;
    const nextEnabled = new Set(state.enabledCategories);
    if (nextEnabled.has(categoryId)) {
      nextEnabled.delete(categoryId);
    } else {
      nextEnabled.add(categoryId);
    }
    updateAndRender({
      enabledCategories: nextEnabled,
      feedbackMessage: '',
      lastChangeReason: 'mode-change',
    });
  });

  const toggleColumnByName = (columnName) => {
    const colInfo = state.columnReport.columns.find((c) => c.name === columnName);
    const current = colInfo ? colInfo.activeAction : 'redact';
    const nextAction = current === 'redact' ? 'keep' : 'redact';
    updateAndRender({
      columnOverrides: { ...state.columnOverrides, [columnName]: nextAction },
      feedbackMessage: `Column "${columnName}" set to ${nextAction}.`,
      lastChangeReason: 'mode-change',
    });
  };

  query(SELECTORS.columnsList, root)?.addEventListener('click', (event) => {
    const btn = event.target.closest('[data-action="toggle-column"]');
    if (btn) toggleColumnByName(btn.dataset.column);
  });

  query(SELECTORS.tableViewer, root)?.addEventListener('click', (event) => {
    const toggleBtn = event.target.closest('[data-action="toggle-column"]');
    if (toggleBtn) {
      toggleColumnByName(toggleBtn.dataset.column);
      return;
    }
    const chip = event.target.closest('[data-finding-id]');
    if (chip) {
      state = {
        ...state,
        selectedWhitelistTarget: {
          findingId: chip.dataset.findingId,
          value: chip.dataset.rawValue,
          category: chip.dataset.category,
          label: chip.dataset.label || chip.dataset.category,
        },
      };
      renderDiff(state, root);
    }
  });

  query(SELECTORS.diffViewer, root)?.addEventListener('click', (event) => {
    const chip = event.target.closest('[data-segment-type="redacted"][data-finding-id]');
    if (!chip) return;
    state = {
      ...state,
      selectedWhitelistTarget: {
        findingId: chip.dataset.findingId,
        value: chip.dataset.rawValue,
        category: chip.dataset.category,
        label: chip.dataset.label || chip.dataset.category,
      },
    };
    renderDiff(state, root);
  });

  query(SELECTORS.whitelistOneBtn, root)?.addEventListener('click', () => {
    const target = state.selectedWhitelistTarget;
    if (!target) return;
    const nextSuppressed = new Set(state.suppressedFindingIds);
    nextSuppressed.add(target.findingId);
    updateAndRender({
      suppressedFindingIds: nextSuppressed,
      selectedWhitelistTarget: null,
      feedbackMessage: `Ignored single ${target.label} occurrence.`,
      lastChangeReason: 'mode-change',
    });
    emitToast('Ignored selected occurrence');
  });

  query(SELECTORS.whitelistAllBtn, root)?.addEventListener('click', () => {
    const target = state.selectedWhitelistTarget;
    if (!target) return;
    const nextWhitelisted = new Set(state.whitelistedValues);
    nextWhitelisted.add(target.value);
    updateAndRender({
      whitelistedValues: nextWhitelisted,
      selectedWhitelistTarget: null,
      feedbackMessage: `Whitelisted all matching ${target.label} values.`,
      lastChangeReason: 'mode-change',
    });
    emitToast('Whitelisted all matching occurrences');
  });

  query(SELECTORS.whitelistDismissBtn, root)?.addEventListener('click', () => {
    state = { ...state, selectedWhitelistTarget: null };
    renderDiff(state, root);
  });

  query(SELECTORS.whitelistResetBtn, root)?.addEventListener('click', () => {
    updateAndRender({
      suppressedFindingIds: new Set(),
      whitelistedValues: new Set(),
      selectedWhitelistTarget: null,
      feedbackMessage: 'Reset whitelist filters.',
      lastChangeReason: 'mode-change',
    });
    emitToast('Whitelist cleared');
  });

  for (const selector of [
    SELECTORS.viewTabDiff,
    SELECTORS.viewTabSplit,
    SELECTORS.viewTabClean,
    SELECTORS.viewTabTable,
    SELECTORS.viewTabRehydrate,
  ]) {
    query(selector, root)?.addEventListener('click', (event) => {
      const targetView = event.currentTarget.dataset.viewTarget;
      state = { ...state, activeView: targetView, lastChangeReason: 'view-switch' };
      renderDiff(state, root);
      emitMotionSignal({ reason: 'view-switch', detectionsCount: state.detections.length });
    });
  }

  for (const selector of [SELECTORS.themeBtnAuto, SELECTORS.themeBtnLight, SELECTORS.themeBtnDark]) {
    query(selector, root)?.addEventListener('click', (event) => {
      const choice = event.currentTarget.dataset.themeChoice;
      state = { ...state, theme: choice };
      applyTheme(choice, root);
      emitToast(`Theme set to ${choice}`);
    });
  }

  const fileInput = query(SELECTORS.fileUploadInput, root);
  query(SELECTORS.fileUploadBtn, root)?.addEventListener('click', () => {
    fileInput?.click();
  });
  fileInput?.addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    if (file) loadFileIntoWorkbench(file);
  });

  const inputSection = query(SELECTORS.inputSection, root);
  if (inputSection) {
    inputSection.addEventListener('dragover', (event) => {
      event.preventDefault();
      inputSection.dataset.dragOver = 'true';
    });
    inputSection.addEventListener('dragleave', (event) => {
      if (!inputSection.contains(event.relatedTarget)) {
        inputSection.dataset.dragOver = 'false';
      }
    });
    inputSection.addEventListener('drop', (event) => {
      event.preventDefault();
      inputSection.dataset.dragOver = 'false';
      const file = event.dataTransfer?.files?.[0];
      if (file) loadFileIntoWorkbench(file);
    });
  }

  query(SELECTORS.sampleLogsBtn, root)?.addEventListener('click', () => {
    runTypewriterSample(SAMPLE_DATA.logs, 'Loaded log sample.');
  });

  query(SELECTORS.sampleIndiaBtn, root)?.addEventListener('click', () => {
    runTypewriterSample(SAMPLE_DATA.india, 'Loaded Indian PII sample.');
  });

  query(SELECTORS.sampleCsvBtn, root)?.addEventListener('click', () => {
    runTypewriterSample(SAMPLE_DATA.csv, 'Loaded CSV sample.');
  });

  query(SELECTORS.sampleJsonBtn, root)?.addEventListener('click', () => {
    runTypewriterSample(SAMPLE_DATA.json, 'Loaded JSON sample.');
  });

  query(SELECTORS.clearInputBtn, root)?.addEventListener('click', () => {
    if (cancelTypewriter) cancelTypewriter();
    const dropStatus = query(SELECTORS.fileDropStatus, root);
    const dropLabel = query(SELECTORS.fileDropLabel, root);
    if (dropStatus) dropStatus.dataset.uploadState = 'idle';
    if (dropLabel) dropLabel.textContent = 'Drop a .txt, .csv, .json, or .pdf file here';
    updateAndRender({ rawText: '', feedbackMessage: 'Cleared input.', lastChangeReason: 'clear' }, { resetColumns: true });
    emitToast('Cleared input');
  });

  const pulseButtonState = (btn, attr) => {
    if (!btn) return;
    btn.dataset[attr] = 'true';
    window.setTimeout(() => {
      btn.dataset[attr] = 'false';
    }, 1500);
  };

  query(SELECTORS.copyOutputBtn, root)?.addEventListener('click', async (event) => {
    const btn = event.currentTarget;
    try {
      await navigator.clipboard.writeText(state.redacted.scrubbedText);
      state = { ...state, feedbackMessage: 'Copied scrubbed output to clipboard.' };
      pulseButtonState(btn, 'copied');
      emitToast('Copied scrubbed output');
    } catch {
      state = { ...state, feedbackMessage: 'Clipboard access unavailable in this browser context.' };
      emitToast('Clipboard access unavailable');
    }
    renderDiff(state, root);
  });

  query(SELECTORS.exportCleanBtn, root)?.addEventListener('click', (event) => {
    const ext = state.structured.format === 'json'
      ? 'json'
      : state.structured.format === 'csv'
        ? 'csv'
        : 'txt';
    const filename = `vaultscrub-clean.${ext}`;
    triggerDownload(filename, state.redacted.scrubbedText, 'text/plain;charset=utf-8');
    pulseButtonState(event.currentTarget, 'downloaded');
    state = { ...state, feedbackMessage: `Downloaded ${filename}.` };
    renderDiff(state, root);
    emitToast(`Downloaded ${filename}`);
  });

  query(SELECTORS.exportPdfBtn, root)?.addEventListener('click', async (event) => {
    const btn = event.currentTarget;
    try {
      const { buildSanitizedPdfBlob } = await import('./pdfExtractor.js');
      const blob = buildSanitizedPdfBlob(state.redacted.scrubbedText);
      triggerDownload('vaultscrub-sanitized.pdf', blob, 'application/pdf');
      pulseButtonState(btn, 'downloaded');
      state = { ...state, feedbackMessage: 'Downloaded vaultscrub-sanitized.pdf.' };
      emitToast('Downloaded sanitized PDF');
    } catch (err) {
      emitToast(err?.message || 'PDF export failed');
    }
    renderDiff(state, root);
  });

  // Encrypted Vault Modal
  const vaultModal = query(SELECTORS.vaultModal, root);
  const vaultPassInput = query(SELECTORS.vaultPassphraseInput, root);
  const vaultErr = query(SELECTORS.vaultModalError, root);

  query(SELECTORS.exportVaultBtn, root)?.addEventListener('click', () => {
    if (!vaultModal) return;
    if (vaultPassInput) vaultPassInput.value = '';
    if (vaultErr) vaultErr.textContent = '';
    vaultModal.dataset.open = 'true';
    vaultPassInput?.focus();
  });

  query(SELECTORS.vaultCancelBtn, root)?.addEventListener('click', () => {
    if (vaultModal) vaultModal.dataset.open = 'false';
  });

  query(SELECTORS.vaultConfirmBtn, root)?.addEventListener('click', async () => {
    const passphrase = vaultPassInput?.value || '';
    try {
      const vaultJson = await encryptVaultMapping(state.redacted.mappingEntries, passphrase);
      triggerDownload('vaultscrub-key.vault.json', vaultJson, 'application/json;charset=utf-8');
      if (vaultModal) vaultModal.dataset.open = 'false';
      state = { ...state, feedbackMessage: 'Downloaded encrypted key vaultscrub-key.vault.json.' };
      renderDiff(state, root);
      emitToast('Exported AES-GCM encrypted key');
    } catch (err) {
      if (vaultErr) vaultErr.textContent = err?.message || 'Encryption failed.';
    }
  });

  // Re-hydrate / Restore Loop
  const vaultFileInput = query(SELECTORS.vaultFileInput, root);
  query(SELECTORS.vaultFileBtn, root)?.addEventListener('click', () => {
    vaultFileInput?.click();
  });

  vaultFileInput?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    state = {
      ...state,
      rehydrate: {
        ...state.rehydrate,
        vaultJsonText: text,
        vaultFileName: file.name,
        statusMessage: `Loaded ${file.name}. Enter passphrase to decrypt.`,
      },
    };
    renderDiff(state, root);
  });

  query(SELECTORS.rehydrateRunBtn, root)?.addEventListener('click', async () => {
    const aiText = query(SELECTORS.rehydrateInput, root)?.value || '';
    const passphrase = query(SELECTORS.rehydratePassphrase, root)?.value || '';
    try {
      let entries;
      if (state.rehydrate.vaultJsonText) {
        const decrypted = await decryptVaultMapping(state.rehydrate.vaultJsonText, passphrase);
        entries = decrypted.entries;
      } else if (state.redacted.mappingEntries.length > 0 && !passphrase) {
        throw new Error('Upload a .vault.json key file and enter its passphrase to decrypt.');
      } else {
        throw new Error('Upload a .vault.json key file first.');
      }
      const res = rehydrateText(aiText, entries);
      state = {
        ...state,
        rehydrate: {
          ...state.rehydrate,
          restoredText: res.restoredText,
          statusMessage: `Restored ${res.restoredCount} token occurrence(s) across ${res.tokensFound} unique token(s) locally.`,
        },
      };
      emitToast(`Restored ${res.restoredCount} token(s)`);
    } catch (err) {
      state = {
        ...state,
        rehydrate: {
          ...state.rehydrate,
          statusMessage: err?.message || 'Decryption failed.',
        },
      };
      emitToast(err?.message || 'Decryption failed');
    }
    renderDiff(state, root);
  });

  query(SELECTORS.rehydrateCopyBtn, root)?.addEventListener('click', async () => {
    const restored = state.rehydrate.restoredText;
    if (!restored) return;
    try {
      await navigator.clipboard.writeText(restored);
      emitToast('Copied restored response');
    } catch {
      emitToast('Clipboard unavailable');
    }
  });

  // Audit Certificates & Reports
  query(SELECTORS.exportCertJsonBtn, root)?.addEventListener('click', async (event) => {
    const btn = event.currentTarget;
    const { buildAuditCertificate } = await import('./auditReport.js');
    const cert = await buildAuditCertificate({
      rawText: state.rawText,
      scrubbedText: state.redacted.scrubbedText,
      report: state.report,
      whitelistedCount: state.suppressedFindingIds.size + state.whitelistedValues.size,
    });
    triggerDownload('vaultscrub-audit-certificate.json', JSON.stringify(cert, null, 2), 'application/json;charset=utf-8');
    pulseButtonState(btn, 'downloaded');
    state = { ...state, feedbackMessage: 'Downloaded vaultscrub-audit-certificate.json.' };
    renderDiff(state, root);
    emitToast('Downloaded JSON Audit Certificate');
  });

  query(SELECTORS.exportCertPdfBtn, root)?.addEventListener('click', async (event) => {
    const btn = event.currentTarget;
    const { buildAuditCertificate, buildAuditCertificatePdfBlob } = await import('./auditReport.js');
    const cert = await buildAuditCertificate({
      rawText: state.rawText,
      scrubbedText: state.redacted.scrubbedText,
      report: state.report,
      whitelistedCount: state.suppressedFindingIds.size + state.whitelistedValues.size,
    });
    const pdfBlob = buildAuditCertificatePdfBlob(cert);
    triggerDownload('vaultscrub-audit-certificate.pdf', pdfBlob, 'application/pdf');
    pulseButtonState(btn, 'downloaded');
    state = { ...state, feedbackMessage: 'Downloaded vaultscrub-audit-certificate.pdf.' };
    renderDiff(state, root);
    emitToast('Downloaded PDF Audit Certificate');
  });

  query(SELECTORS.exportReportMdBtn, root)?.addEventListener('click', (event) => {
    triggerDownload('vaultscrub-audit.md', formatReportAsMarkdown(state.report), 'text/markdown;charset=utf-8');
    pulseButtonState(event.currentTarget, 'downloaded');
    state = { ...state, feedbackMessage: 'Downloaded vaultscrub-audit.md.' };
    renderDiff(state, root);
    emitToast('Downloaded vaultscrub-audit.md');
  });

  query(SELECTORS.exportReportJsonBtn, root)?.addEventListener('click', (event) => {
    triggerDownload('vaultscrub-audit.json', formatReportAsJson(state.report), 'application/json;charset=utf-8');
    pulseButtonState(event.currentTarget, 'downloaded');
    state = { ...state, feedbackMessage: 'Downloaded vaultscrub-audit.json.' };
    renderDiff(state, root);
    emitToast('Downloaded vaultscrub-audit.json');
  });

  // Zero-Trust Proof Modal & Online/Offline tracking
  const ztModal = query(SELECTORS.zeroTrustModal, root);
  query(SELECTORS.zeroTrustInfoBtn, root)?.addEventListener('click', () => {
    if (ztModal) ztModal.dataset.open = 'true';
  });
  query(SELECTORS.zeroTrustCloseBtn, root)?.addEventListener('click', () => {
    if (ztModal) ztModal.dataset.open = 'false';
  });

  if (typeof window !== 'undefined') {
    const syncOnline = () => {
      state = { ...state, privacy: { ...state.privacy, isOnline: navigator.onLine } };
      renderPrivacy(state, root);
    };
    window.addEventListener('online', syncOnline);
    window.addEventListener('offline', syncOnline);
  }

  if (typeof window !== 'undefined' && window.location?.search) {
    const params = new URLSearchParams(window.location.search);
    const viewParam = params.get('view');
    if (viewParam === 'rehydrate') {
      state = { ...state, activeView: 'rehydrate', lastChangeReason: 'view-switch' };
      renderDiff(state, root);
    }
    const sampleParam = params.get('sample');
    if (sampleParam === 'logs') runTypewriterSample(SAMPLE_DATA.logs, 'Loaded log sample.');
    if (sampleParam === 'india') runTypewriterSample(SAMPLE_DATA.india, 'Loaded Indian PII sample.');
    if (sampleParam === 'csv') runTypewriterSample(SAMPLE_DATA.csv, 'Loaded CSV sample.');
    if (sampleParam === 'json') runTypewriterSample(SAMPLE_DATA.json, 'Loaded JSON sample.');
  }

  return { getState: () => state };
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => initApp(document));
  } else {
    initApp(document);
  }
}
