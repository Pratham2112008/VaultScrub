/**
 * @module redact
 * @description Pure redaction & diff-segmentation engine for VaultScrub.
 *
 * Implements four redaction modes (token, mask, hash, remove), consistent
 * pseudonym token assignment across repeated values, partial value masking
 * per-category, deterministic FNV-1a hashing, structured CSV/JSON cell-by-cell
 * redaction with column overrides, and bidirectional mapping export for
 * encrypted key vault re-hydration.
 *
 * Zero DOM or browser global dependencies — safe for Node.js test execution.
 */

import { escapeCsvCell } from './csvParser.js';

export const REDACTION_MODES = Object.freeze([
  { id: 'token', label: 'Tokenize', description: 'Consistent typed tokens e.g. [EMAIL_1]' },
  { id: 'mask', label: 'Mask', description: 'Partial character masking e.g. j***@domain.com' },
  { id: 'hash', label: 'Hash', description: 'Deterministic non-reversible digest tags' },
  { id: 'remove', label: 'Remove', description: 'Uniform [REDACTED] placeholder' },
]);

/**
 * Pure 64-bit-like deterministic FNV-1a hex digest (two 32-bit lanes).
 * @param {string} input
 * @returns {string}
 */
function deterministicHash(input) {
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    h1 ^= code;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 ^= code + (i & 0xff);
    h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
  }
  return `${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`.slice(0, 10);
}

/**
 * Create a partially masked preview that preserves minimal structural cues.
 * @param {string} value
 * @param {string} category
 * @returns {string}
 */
export function maskValue(value, category) {
  if (!value) return '***';

  if (category === 'email' || category === 'upi_id') {
    const atIndex = value.indexOf('@');
    if (atIndex > 0) {
      const local = value.slice(0, atIndex);
      const domain = value.slice(atIndex + 1);
      const head = local.slice(0, Math.min(2, local.length));
      return `${head}***@${domain}`;
    }
  }

  if (category === 'aadhaar') {
    const digits = value.replace(/\D/g, '');
    return `XXXX-XXXX-${digits.slice(-4)}`;
  }

  if (category === 'pan') {
    return `${value.slice(0, 2)}******${value.slice(-2)}`;
  }

  if (category === 'gstin') {
    return `${value.slice(0, 2)}**********${value.slice(-3)}`;
  }

  if (category === 'ifsc') {
    return `${value.slice(0, 5)}****${value.slice(-2)}`;
  }

  if (category === 'credit_card') {
    const digits = value.replace(/\D/g, '');
    const last4 = digits.slice(-4);
    return `****-****-****-${last4}`;
  }

  if (category === 'ssn') {
    return `***-**-${value.slice(-4)}`;
  }

  if (category === 'phone') {
    const digits = value.replace(/\D/g, '');
    return `***-***-${digits.slice(-4)}`;
  }

  if (category === 'private_key') {
    return '[PRIVATE_KEY_MASKED]';
  }

  if (value.length <= 6) {
    return `${value.slice(0, 1)}${'*'.repeat(Math.max(2, value.length - 1))}`;
  }

  return `${value.slice(0, 3)}***${value.slice(-2)}`;
}

/**
 * Create replacement text for a single finding according to mode and token registry.
 * @param {object} finding
 * @param {string} mode
 * @param {{ counters: Map<string, number>, valueTokens: Map<string, string> }} registry
 * @returns {string}
 */
function buildReplacement(finding, mode, registry) {
  const categoryKey = finding.category.toUpperCase();
  const dedupeKey = `${finding.category}:${finding.value}`;

  if (mode === 'mask') return maskValue(finding.value, finding.category);
  if (mode === 'hash') return `[${categoryKey}#${deterministicHash(dedupeKey)}]`;
  if (mode === 'remove') return '[REDACTED]';

  // Default: 'token' with referential consistency for repeated values
  if (registry.valueTokens.has(dedupeKey)) {
    return registry.valueTokens.get(dedupeKey);
  }
  const nextCount = (registry.counters.get(categoryKey) || 0) + 1;
  registry.counters.set(categoryKey, nextCount);
  const token = `[${categoryKey}_${nextCount}]`;
  registry.valueTokens.set(dedupeKey, token);
  return token;
}

/**
 * Redact sensitive findings from raw text and emit diff segments.
 * @param {string} text
 * @param {Array<object>} detections
 * @param {{ mode?: 'token'|'mask'|'hash'|'remove', suppressedFindingIds?: Set<string> }} [options]
 * @returns {{
 *   originalText: string,
 *   scrubbedText: string,
 *   segments: Array<object>,
 *   replacements: Array<object>,
 *   stats: {
 *     totalApplied: number,
 *     uniqueValues: number,
 *     originalLength: number,
 *     scrubbedLength: number
 *   }
 * }}
 */
export function redactText(text, detections = [], options = {}) {
  const safeText = typeof text === 'string' ? text : '';
  const mode = options.mode || 'token';
  const suppressed = options.suppressedFindingIds instanceof Set
    ? options.suppressedFindingIds
    : new Set();
  const whitelistedValues = options.whitelistedValues instanceof Set
    ? options.whitelistedValues
    : new Set();

  const activeDetections = [...detections]
    .filter((item) => !suppressed.has(item.id) && !whitelistedValues.has(item.value))
    .sort((a, b) => a.start - b.start);

  const registry = {
    counters: new Map(),
    valueTokens: new Map(),
  };

  const segments = [];
  const replacements = [];
  const mappingByToken = new Map();
  const uniqueRawValues = new Set();
  let cursor = 0;

  for (const finding of activeDetections) {
    if (finding.start < cursor || finding.end > safeText.length) continue;

    if (finding.start > cursor) {
      segments.push({
        type: 'plain',
        text: safeText.slice(cursor, finding.start),
      });
    }

    const replacement = buildReplacement(finding, mode, registry);
    uniqueRawValues.add(`${finding.category}:${finding.value}`);

    if (mode === 'token' && !mappingByToken.has(replacement)) {
      mappingByToken.set(replacement, {
        token: replacement,
        original: finding.value,
        category: finding.category,
        label: finding.label,
      });
    }

    segments.push({
      type: 'redacted',
      text: replacement,
      originalText: finding.value,
      category: finding.category,
      label: finding.label,
      severity: finding.severity,
      findingId: finding.id,
      replacement,
    });

    replacements.push({
      findingId: finding.id,
      category: finding.category,
      label: finding.label,
      severity: finding.severity,
      line: finding.line,
      column: finding.column,
      originalPreview: maskValue(finding.value, finding.category),
      replacement,
    });

    cursor = finding.end;
  }

  if (cursor < safeText.length) {
    segments.push({
      type: 'plain',
      text: safeText.slice(cursor),
    });
  }

  const scrubbedText = segments.map((seg) => seg.text).join('');

  return {
    originalText: safeText,
    scrubbedText,
    segments,
    replacements,
    mappingEntries: Array.from(mappingByToken.values()),
    stats: {
      totalApplied: replacements.length,
      uniqueValues: uniqueRawValues.size,
      originalLength: safeText.length,
      scrubbedLength: scrubbedText.length,
    },
  };
}

/**
 * Redact structured CSV/JSON datasets cell-by-cell while honoring column overrides.
 * @param {{ format: string, headers: string[], rows: Array<Record<string, string>>, delimiter?: string }} structured
 * @param {Record<string, 'redact'|'keep'>} columnOverrides
 * @param {Function} detectFn
 * @param {{ mode?: string, enabledCategories?: Set<string>|string[]|Record<string, boolean> }} [options]
 * @returns {{
 *   scrubbedText: string,
 *   segments: Array<object>,
 *   replacements: Array<object>,
 *   stats: { totalApplied: number, uniqueValues: number, originalLength: number, scrubbedLength: number },
 *   suppressedCells: number
 * } | null}
 */
export function redactStructuredDataset(structured, columnOverrides = {}, detectFn, options = {}) {
  if (!structured || structured.format === 'text' || !structured.rows.length) {
    return null;
  }

  const mode = options.mode || 'token';
  const suppressed = options.suppressedFindingIds instanceof Set
    ? options.suppressedFindingIds
    : new Set();
  const whitelistedValues = options.whitelistedValues instanceof Set
    ? options.whitelistedValues
    : new Set();
  const registry = { counters: new Map(), valueTokens: new Map() };
  const replacements = [];
  const mappingByToken = new Map();
  const uniqueRawValues = new Set();
  let suppressedCells = 0;
  let originalLength = 0;

  const redactCell = (cellValue, rowIndex, header) => {
    const cellFindings = detectFn(cellValue, { enabledCategories: options.enabledCategories })
      .filter((f) => {
        const scopedId = `${f.id}-r${rowIndex + 1}-${header}`;
        return !suppressed.has(f.id) && !suppressed.has(scopedId) && !whitelistedValues.has(f.value);
      });
    if (cellFindings.length === 0) {
      return { value: cellValue, segs: cellValue ? [{ type: 'plain', text: cellValue }] : [] };
    }
    const segs = [];
    let out = '';
    let cursor = 0;
    for (const f of cellFindings) {
      if (f.start > cursor) {
        const plain = cellValue.slice(cursor, f.start);
        out += plain;
        segs.push({ type: 'plain', text: plain });
      }
      const replacement = buildReplacement(f, mode, registry);
      uniqueRawValues.add(`${f.category}:${f.value}`);
      if (mode === 'token' && !mappingByToken.has(replacement)) {
        mappingByToken.set(replacement, {
          token: replacement,
          original: f.value,
          category: f.category,
          label: f.label,
        });
      }
      out += replacement;
      const scopedId = `${f.id}-r${rowIndex + 1}-${header}`;
      segs.push({
        type: 'redacted',
        text: replacement,
        originalText: f.value,
        category: f.category,
        label: f.label,
        severity: f.severity,
        findingId: scopedId,
        replacement,
      });
      replacements.push({
        findingId: scopedId,
        category: f.category,
        label: f.label,
        severity: f.severity,
        line: rowIndex + 2,
        column: 1,
        originalPreview: maskValue(f.value, f.category),
        replacement,
      });
      cursor = f.end;
    }
    if (cursor < cellValue.length) {
      const tail = cellValue.slice(cursor);
      out += tail;
      segs.push({ type: 'plain', text: tail });
    }
    return { value: out, segs };
  };

  const cellSegmentsByRow = [];
  const scrubbedRows = structured.rows.map((row, rowIndex) => {
    const nextRow = {};
    const rowSegs = {};
    for (const header of structured.headers) {
      const cellValue = row[header] ?? '';
      originalLength += cellValue.length;
      const action = columnOverrides[header] || 'redact';
      if (action === 'keep') {
        nextRow[header] = cellValue;
        rowSegs[header] = cellValue ? [{ type: 'plain', text: cellValue }] : [];
        suppressedCells += 1;
        continue;
      }
      const res = redactCell(cellValue, rowIndex, header);
      nextRow[header] = res.value;
      rowSegs[header] = res.segs;
    }
    cellSegmentsByRow.push(rowSegs);
    return nextRow;
  });

  if (structured.format === 'json') {
    const scrubbedText = JSON.stringify(scrubbedRows, null, 2);
    // Build unified segments for JSON lines by running plain/redacted segmentation cleanly
    const segments = [{ type: 'plain', text: scrubbedText }];
    return {
      scrubbedText,
      segments,
      replacements,
      mappingEntries: Array.from(mappingByToken.values()),
      stats: {
        totalApplied: replacements.length,
        uniqueValues: uniqueRawValues.size,
        originalLength,
        scrubbedLength: scrubbedText.length,
      },
      suppressedCells,
    };
  }

  const delimiter = structured.delimiter || ',';
  const segments = [];
  const headerLine = structured.headers.map((h) => escapeCsvCell(h, delimiter)).join(delimiter);
  segments.push({ type: 'plain', text: `${headerLine}\n` });

  const lines = [headerLine];
  scrubbedRows.forEach((row, rowIndex) => {
    const rowSegs = cellSegmentsByRow[rowIndex];
    const encodedCells = structured.headers.map((header, colIdx) => {
      const rawCell = row[header] ?? '';
      const needsQuotes = rawCell.includes(delimiter) || rawCell.includes('"') || rawCell.includes('\n');
      if (needsQuotes) {
        segments.push({ type: 'plain', text: escapeCsvCell(rawCell, delimiter) });
      } else {
        for (const seg of rowSegs[header]) segments.push(seg);
      }
      if (colIdx < structured.headers.length - 1) {
        segments.push({ type: 'plain', text: delimiter });
      }
      return escapeCsvCell(rawCell, delimiter);
    });
    if (rowIndex < scrubbedRows.length - 1) {
      segments.push({ type: 'plain', text: '\n' });
    }
    lines.push(encodedCells.join(delimiter));
  });

  const scrubbedText = lines.join('\n');
  return {
    scrubbedText,
    segments,
    replacements,
    mappingEntries: Array.from(mappingByToken.values()),
    stats: {
      totalApplied: replacements.length,
      uniqueValues: uniqueRawValues.size,
      originalLength,
      scrubbedLength: scrubbedText.length,
    },
    suppressedCells,
  };
}
