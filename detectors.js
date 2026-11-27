/**
 * @module detectors
 * @description Pure PII & secret detection engine for VaultScrub.
 *
 * Implements 16 detector categories with regex rules, validation functions
 * (Luhn, Verhoeff, IBAN mod-97, SSN area checks, IPv4 range checks, phone
 * heuristics), overlap resolution, and 1-based line/column position mapping.
 *
 * Zero DOM or browser global dependencies — safe for Node.js test execution.
 */

import { isValidAadhaar } from './verhoeff.js';
import { parseCsvRecords } from './csvParser.js';

export const DETECTOR_CATALOG = Object.freeze([
  {
    id: 'private_key',
    label: 'Private Key',
    severity: 'critical',
    description: 'PEM-encoded private key blocks',
    defaultEnabled: true,
  },
  {
    id: 'api_key',
    label: 'API Key / Secret',
    severity: 'critical',
    description: 'Cloud, VCS, payment, and inline secret tokens',
    defaultEnabled: true,
  },
  {
    id: 'credit_card',
    label: 'Credit Card',
    severity: 'critical',
    description: 'Luhn-validated payment card numbers',
    defaultEnabled: true,
  },
  {
    id: 'aadhaar',
    label: 'Aadhaar',
    severity: 'critical',
    description: 'Verhoeff-validated 12-digit Indian Aadhaar IDs',
    defaultEnabled: true,
  },
  {
    id: 'pan',
    label: 'Indian PAN',
    severity: 'critical',
    description: '10-character Indian Permanent Account Numbers',
    defaultEnabled: true,
  },
  {
    id: 'ssn',
    label: 'SSN',
    severity: 'critical',
    description: 'US Social Security numbers',
    defaultEnabled: true,
  },
  {
    id: 'jwt',
    label: 'JWT',
    severity: 'high',
    description: 'JSON Web Tokens (header.payload.signature)',
    defaultEnabled: true,
  },
  {
    id: 'url_credentials',
    label: 'URL Secret',
    severity: 'high',
    description: 'Embedded URL credentials and secret query params',
    defaultEnabled: true,
  },
  {
    id: 'gstin',
    label: 'GSTIN',
    severity: 'high',
    description: '15-character Indian GST Identification Numbers',
    defaultEnabled: true,
  },
  {
    id: 'upi_id',
    label: 'UPI ID',
    severity: 'high',
    description: 'Indian Unified Payments Interface VPA handles',
    defaultEnabled: true,
  },
  {
    id: 'iban',
    label: 'IBAN',
    severity: 'high',
    description: 'International Bank Account Numbers',
    defaultEnabled: true,
  },
  {
    id: 'ifsc',
    label: 'IFSC',
    severity: 'medium',
    description: '11-character Indian Financial System Codes',
    defaultEnabled: true,
  },
  {
    id: 'email',
    label: 'Email',
    severity: 'medium',
    description: 'Email addresses',
    defaultEnabled: true,
  },
  {
    id: 'phone',
    label: 'Phone',
    severity: 'medium',
    description: 'Domestic and international phone numbers',
    defaultEnabled: true,
  },
  {
    id: 'ipv4',
    label: 'IPv4',
    severity: 'low',
    description: 'IPv4 network addresses',
    defaultEnabled: true,
  },
  {
    id: 'ipv6',
    label: 'IPv6',
    severity: 'low',
    description: 'IPv6 network addresses',
    defaultEnabled: true,
  },
]);

const SEVERITY_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
});

const CATALOG_BY_ID = new Map(DETECTOR_CATALOG.map((item) => [item.id, item]));

/**
 * Validate a payment card string using the Luhn checksum.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidLuhn(raw) {
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Validate a US SSN against invalid area/group/serial blocks.
 * @param {string} raw
 * @returns {boolean}
 */
function isValidSsn(raw) {
  const digits = raw.replace(/\D/g, '');
  if (digits.length !== 9) return false;
  const area = digits.slice(0, 3);
  const group = digits.slice(3, 5);
  const serial = digits.slice(5, 9);
  if (area === '000' || area === '666' || area.startsWith('9')) return false;
  if (group === '00' || serial === '0000') return false;
  return true;
}

/**
 * Validate an IBAN using length + mod-97 checksum.
 * @param {string} raw
 * @returns {boolean}
 */
function isValidIban(raw) {
  const compact = raw.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i += 1) {
    const code = rearranged.charCodeAt(i);
    const expanded = code >= 65 && code <= 90 ? String(code - 55) : rearranged[i];
    for (let j = 0; j < expanded.length; j += 1) {
      remainder = (remainder * 10 + (expanded.charCodeAt(j) - 48)) % 97;
    }
  }
  return remainder === 1;
}

/**
 * Validate an IPv4 address.
 * @param {string} raw
 * @returns {boolean}
 */
function isValidIpv4(raw) {
  const parts = raw.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

/**
 * Validate a candidate phone number without capturing dates or short IDs.
 * @param {string} raw
 * @returns {boolean}
 */
function isValidPhone(raw) {
  const trimmed = raw.trim();
  if (/^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$/.test(trimmed)) return false;
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length < 10 || digits.length > 15) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  return true;
}

const DETECTOR_RULES = [
  {
    category: 'private_key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{16,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    confidence: 0.99,
  },
  {
    category: 'api_key',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    confidence: 0.98,
  },
  {
    category: 'api_key',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    confidence: 0.99,
  },
  {
    category: 'api_key',
    regex: /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bxox[baprs]-[A-Za-z0-9-]{16,}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bsk-[A-Za-z0-9_-]{20,}\b/g,
    confidence: 0.97,
  },
  {
    category: 'api_key',
    regex: /\bBearer\s+[A-Za-z0-9._-]{16,}\b/g,
    confidence: 0.92,
  },
  {
    category: 'api_key',
    regex: /(?<![A-Za-z0-9_])(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|pwd)\s*[:=]\s*(['"]?)([A-Za-z0-9._/+=-]{8,})\1/gi,
    groupIndex: 2,
    confidence: 0.9,
  },
  {
    category: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
    confidence: 0.98,
  },
  {
    category: 'url_credentials',
    regex: /\bhttps?:\/\/[^\s:/?#]+:[^\s@/?#]+@[^\s"'<>]+/gi,
    confidence: 0.97,
  },
  {
    category: 'url_credentials',
    regex: /(?<=[?&](?:token|api_key|apikey|secret|sig|signature|access_token|auth)=)[^&\s"'<>]{8,}/gi,
    confidence: 0.92,
  },
  {
    category: 'credit_card',
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validate: isValidLuhn,
    confidence: 0.96,
  },
  {
    category: 'aadhaar',
    regex: /(?<![\dA-Za-z])\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![\dA-Za-z])/g,
    validate: isValidAadhaar,
    confidence: 0.97,
  },
  {
    category: 'pan',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    confidence: 0.96,
  },
  {
    category: 'gstin',
    regex: /\b(?:0[1-9]|[1-2][0-9]|3[0-8])[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g,
    confidence: 0.96,
  },
  {
    category: 'upi_id',
    regex: /\b[A-Za-z0-9._-]{2,64}@(?:okhdfcbank|okicici|oksbi|okaxis|ybl|ibl|axl|paytm|upi|apl|icici|hdfcbank|sbi|kotak|axisbank|indus|federal|barodampay|waaxis|wahdfcbank|waicici|wasbi|jupiteraxis|sliceaxis|fbl|idfcbank|aubank|yesbank|pnb|boi|cnrb|unionbank|airtel|jio|freecharge|mobikwik|amazonpay|gpay|phonepe|pingpay|naviaxis|timecosmos|[a-z]{2,20}bank)\b/g,
    confidence: 0.94,
  },
  {
    category: 'ifsc',
    regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    confidence: 0.93,
  },
  {
    category: 'ssn',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    validate: isValidSsn,
    confidence: 0.95,
  },
  {
    category: 'iban',
    regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g,
    validate: isValidIban,
    confidence: 0.94,
  },
  {
    category: 'email',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    confidence: 0.96,
  },
  {
    category: 'phone',
    regex: /(?<![\w.])(?:\+91[\s.-]?[6-9]\d{4}[\s.-]?\d{5}|(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{3}[\s.-])\d{3}[\s.-]?\d{4})(?![\w.])/g,
    validate: isValidPhone,
    confidence: 0.86,
  },
  {
    category: 'ipv4',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: isValidIpv4,
    confidence: 0.9,
  },
  {
    category: 'ipv6',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g,
    confidence: 0.88,
  },
];

/**
 * Normalize enabled category options into a Set of enabled category IDs.
 * @param {Set<string>|string[]|Record<string, boolean>|undefined} enabledCategories
 * @returns {Set<string>}
 */
function resolveEnabledCategories(enabledCategories) {
  if (!enabledCategories) {
    return new Set(DETECTOR_CATALOG.filter((c) => c.defaultEnabled).map((c) => c.id));
  }
  if (enabledCategories instanceof Set) return enabledCategories;
  if (Array.isArray(enabledCategories)) return new Set(enabledCategories);
  return new Set(
    Object.entries(enabledCategories)
      .filter(([, enabled]) => Boolean(enabled))
      .map(([id]) => id),
  );
}

/**
 * Compute 1-based line and column offsets for every index lookup.
 * @param {string} text
 * @returns {number[]}
 */
function computeLineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/**
 * Map character offset to 1-based line and column.
 * @param {number[]} lineStarts
 * @param {number} offset
 * @returns {{ line: number, column: number }}
 */
function locateOffset(lineStarts, offset) {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (lineStarts[mid] <= offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  const lineIndex = Math.max(0, high);
  return {
    line: lineIndex + 1,
    column: offset - lineStarts[lineIndex] + 1,
  };
}

/**
 * Resolve overlapping candidate matches deterministically.
 * Prefers higher severity, then longer span, then earlier start.
 * @param {Array<object>} candidates
 * @returns {Array<object>}
 */
function resolveOverlaps(candidates) {
  const prioritized = [...candidates].sort((a, b) => {
    const rankDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (rankDiff !== 0) return rankDiff;
    const lenDiff = (b.end - b.start) - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted = [];
  for (const candidate of prioritized) {
    const overlaps = accepted.some(
      (existing) => candidate.start < existing.end && candidate.end > existing.start,
    );
    if (!overlaps) accepted.push(candidate);
  }

  return accepted.sort((a, b) => a.start - b.start);
}

/**
 * Detect sensitive entities inside arbitrary text.
 * @param {string} text
 * @param {{ enabledCategories?: Set<string>|string[]|Record<string, boolean> }} [options]
 * @returns {Array<{
 *   id: string,
 *   category: string,
 *   label: string,
 *   severity: string,
 *   value: string,
 *   start: number,
 *   end: number,
 *   line: number,
 *   column: number,
 *   confidence: number
 * }>}
 */
export function detectSensitiveData(text, options = {}) {
  if (typeof text !== 'string' || text.length === 0) return [];

  const enabled = resolveEnabledCategories(options.enabledCategories);
  const candidates = [];

  for (const rule of DETECTOR_RULES) {
    if (!enabled.has(rule.category)) continue;
    const meta = CATALOG_BY_ID.get(rule.category);
    const regex = new RegExp(rule.regex.source, rule.regex.flags);

    let match;
    while ((match = regex.exec(text)) !== null) {
      let value = match[0];
      let start = match.index;

      if (rule.groupIndex !== undefined && match[rule.groupIndex] !== undefined) {
        value = match[rule.groupIndex];
        const innerOffset = match[0].lastIndexOf(value);
        if (innerOffset >= 0) start += innerOffset;
      }

      if (!value || (rule.validate && !rule.validate(value))) {
        if (match[0].length === 0) regex.lastIndex += 1;
        continue;
      }

      candidates.push({
        category: rule.category,
        label: meta ? meta.label : rule.category,
        severity: meta ? meta.severity : 'medium',
        value,
        start,
        end: start + value.length,
        confidence: rule.confidence,
      });

      if (match[0].length === 0) regex.lastIndex += 1;
    }
  }

  const resolved = resolveOverlaps(candidates);
  const lineStarts = computeLineStarts(text);

  return resolved.map((finding, index) => {
    const pos = locateOffset(lineStarts, finding.start);
    return {
      id: `finding-${index + 1}`,
      ...finding,
      line: pos.line,
      column: pos.column,
    };
  });
}

/**
 * Parse a single CSV line respecting quoted commas and escaped double quotes.
 * @param {string} line
 * @param {string} delimiter
 * @returns {string[]}
 */
function parseCsvRow(line, delimiter) {
  const cells = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === delimiter && !inQuotes) {
      cells.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return cells;
}

/**
 * Detect whether input is structured CSV/TSV, JSON, or unstructured text.
 * @param {string} text
 * @param {'auto'|'text'|'csv'|'json'} [preferredMode='auto']
 * @returns {{
 *   format: 'text'|'csv'|'json',
 *   delimiter?: string,
 *   headers: string[],
 *   rows: Array<Record<string, string>>,
 *   valid: boolean
 * }}
 */
export function detectStructuredFormat(text, preferredMode = 'auto') {
  if (typeof text !== 'string' || text.trim().length === 0) {
    return { format: 'text', headers: [], rows: [], valid: true };
  }

  const trimmed = text.trim();

  if (preferredMode === 'json' || (preferredMode === 'auto' && (trimmed.startsWith('[') || trimmed.startsWith('{')))) {
    try {
      const parsed = JSON.parse(trimmed);
      const list = Array.isArray(parsed)
        ? parsed
        : parsed && typeof parsed === 'object'
          ? [parsed]
          : null;

      if (list && list.length > 0 && list.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
        const headerSet = new Set();
        for (const item of list) {
          for (const key of Object.keys(item)) headerSet.add(key);
        }
        const headers = Array.from(headerSet);
        const rows = list.map((item) => {
          const row = {};
          for (const h of headers) {
            const val = item[h];
            row[h] = val === null || val === undefined
              ? ''
              : typeof val === 'object'
                ? JSON.stringify(val)
                : String(val);
          }
          return row;
        });
        return { format: 'json', headers, rows, valid: true };
      }
    } catch {
      if (preferredMode === 'json') {
        return { format: 'json', headers: [], rows: [], valid: false };
      }
    }
  }

  if (preferredMode === 'csv' || preferredMode === 'auto') {
    const parsedCsv = parseCsvRecords(trimmed);
    if (parsedCsv.headers.length >= 2 && parsedCsv.rows.length >= 1) {
      if (parsedCsv.valid || preferredMode === 'csv') {
        return {
          format: 'csv',
          delimiter: parsedCsv.delimiter,
          headers: parsedCsv.headers,
          rows: parsedCsv.rows,
          valid: parsedCsv.valid,
        };
      }
    }
  }

  return { format: 'text', headers: [], rows: [], valid: true };
}
