/**
 * Pure RFC-4180-compatible CSV/TSV parser and serializer.
 * Handles quoted fields, embedded commas, escaped quotes, and multiline cells.
 * Zero DOM dependencies.
 */

/**
 * Detect likely delimiter from the first logical line of CSV/TSV text.
 * @param {string} text
 * @returns {string}
 */
export function detectCsvDelimiter(text) {
  const firstLine = (text || '').split(/\r?\n/)[0] || '';
  const commas = (firstLine.match(/,/g) || []).length;
  const tabs = (firstLine.match(/\t/g) || []).length;
  const semicolons = (firstLine.match(/;/g) || []).length;
  if (tabs > commas && tabs >= semicolons) return '\t';
  if (semicolons > commas && semicolons > tabs) return ';';
  return ',';
}

/**
 * Parse CSV/TSV text into raw row arrays, respecting quoted fields and newlines inside quotes.
 * @param {string} text
 * @param {string} [delimiter]
 * @returns {{ delimiter: string, matrix: string[][] }}
 */
export function parseCsvMatrix(text, delimiter = detectCsvDelimiter(text)) {
  if (typeof text !== 'string' || text.trim().length === 0) {
    return { delimiter, matrix: [] };
  }

  const matrix = [];
  let row = [];
  let cell = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cell += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === delimiter) {
      row.push(cell);
      cell = '';
    } else if (ch === '\r') {
      if (text[i + 1] === '\n') i += 1;
      row.push(cell);
      if (row.some((v) => v.length > 0)) matrix.push(row);
      row = [];
      cell = '';
    } else if (ch === '\n') {
      row.push(cell);
      if (row.some((v) => v.length > 0)) matrix.push(row);
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }

  row.push(cell);
  if (row.some((v) => v.length > 0)) matrix.push(row);

  return { delimiter, matrix };
}

/**
 * Parse CSV/TSV text into headers + normalized row objects.
 * @param {string} text
 * @param {string} [preferredDelimiter]
 * @returns {{ delimiter: string, headers: string[], rows: Array<Record<string, string>>, valid: boolean }}
 */
export function parseCsvRecords(text, preferredDelimiter) {
  const delimiter = preferredDelimiter || detectCsvDelimiter(text);
  const { matrix } = parseCsvMatrix(text, delimiter);
  if (matrix.length < 2) {
    return { delimiter, headers: [], rows: [], valid: false };
  }

  const rawHeaders = matrix[0];
  if (rawHeaders.length < 2) {
    return { delimiter, headers: [], rows: [], valid: false };
  }

  const headers = rawHeaders.map((h, idx) => h.trim() || `column_${idx + 1}`);
  const dataRows = matrix.slice(1);
  const valid = dataRows.every((cells) => cells.length === headers.length);

  const rows = dataRows.map((cells) => {
    const record = {};
    headers.forEach((header, idx) => {
      record[header] = (cells[idx] ?? '').trim();
    });
    return record;
  });

  return { delimiter, headers, rows, valid };
}

/**
 * Escape a single CSV cell if it contains delimiter, quotes, or newlines.
 * @param {string} value
 * @param {string} [delimiter=',']
 * @returns {string}
 */
export function escapeCsvCell(value, delimiter = ',') {
  const str = String(value ?? '');
  if (str.includes(delimiter) || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Serialize headers and row objects back into valid CSV text.
 * @param {string[]} headers
 * @param {Array<Record<string, string>>} rows
 * @param {string} [delimiter=',']
 * @returns {string}
 */
export function serializeCsvRecords(headers, rows, delimiter = ',') {
  if (!headers || headers.length === 0) return '';
  const headerLine = headers.map((h) => escapeCsvCell(h, delimiter)).join(delimiter);
  const bodyLines = rows.map((row) =>
    headers.map((h) => escapeCsvCell(row[h] ?? '', delimiter)).join(delimiter),
  );
  return [headerLine, ...bodyLines].join('\n');
}
