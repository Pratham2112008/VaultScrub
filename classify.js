/**
 * Pure risk and column classification logic for VaultScrub.
 * Zero DOM or browser global dependencies.
 */

export const RISK_LEVELS = Object.freeze(['none', 'low', 'medium', 'high', 'critical']);

const SEVERITY_WEIGHTS = Object.freeze({
  critical: 32,
  high: 18,
  medium: 8,
  low: 3,
});

const HEADER_CATEGORY_HINTS = [
  { pattern: /(?:^|_|-)(?:aadhaar|aadhar|uidai)(?:$|_|-)/i, category: 'aadhaar', severity: 'critical' },
  { pattern: /(?:^|_|-)(?:pan|pan_no|pan_number)(?:$|_|-)/i, category: 'pan', severity: 'critical' },
  { pattern: /(?:^|_|-)(?:gstin|gst)(?:$|_|-)/i, category: 'gstin', severity: 'high' },
  { pattern: /(?:^|_|-)(?:upi|vpa|upi_id)(?:$|_|-)/i, category: 'upi_id', severity: 'high' },
  { pattern: /(?:^|_|-)(?:ifsc)(?:$|_|-)/i, category: 'ifsc', severity: 'medium' },
  { pattern: /(?:^|_|-)(?:ssn|social|tax_id)(?:$|_|-)/i, category: 'ssn', severity: 'critical' },
  { pattern: /(?:^|_|-)(?:card|cc|pan|cvv|credit)(?:$|_|-)/i, category: 'credit_card', severity: 'critical' },
  { pattern: /(?:^|_|-)(?:secret|token|api_?key|password|passwd|pwd|private_?key)(?:$|_|-)/i, category: 'api_key', severity: 'critical' },
  { pattern: /(?:^|_|-)(?:iban|bank|routing|account)(?:$|_|-)/i, category: 'iban', severity: 'high' },
  { pattern: /(?:^|_|-)(?:email|e-mail|mail)(?:$|_|-)/i, category: 'email', severity: 'medium' },
  { pattern: /(?:^|_|-)(?:phone|mobile|tel|cell)(?:$|_|-)/i, category: 'phone', severity: 'medium' },
  { pattern: /(?:^|_|-)(?:ip|ipv4|ipv6|ip_addr)(?:$|_|-)/i, category: 'ipv4', severity: 'low' },
];

/**
 * Compute aggregate risk score, normalized risk level, and explanations.
 * @param {Array<object>} detections
 * @param {number} [textLength=0]
 * @returns {{
 *   level: 'none'|'low'|'medium'|'high'|'critical',
 *   score: number,
 *   countsBySeverity: { critical: number, high: number, medium: number, low: number },
 *   reasons: string[]
 * }}
 */
export function classifyRisk(detections = [], textLength = 0) {
  const countsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };

  if (!Array.isArray(detections) || detections.length === 0) {
    return {
      level: 'none',
      score: 0,
      countsBySeverity,
      reasons: textLength > 0
        ? ['No sensitive patterns matched active detectors.']
        : ['Paste or load data to evaluate exposure risk.'],
    };
  }

  for (const item of detections) {
    if (countsBySeverity[item.severity] !== undefined) {
      countsBySeverity[item.severity] += 1;
    }
  }

  // Diminishing-returns weighting so 100 emails doesn't outrank 1 private key, while volume still matters.
  let rawScore = 0;
  for (const [severity, count] of Object.entries(countsBySeverity)) {
    if (count === 0) continue;
    const base = SEVERITY_WEIGHTS[severity] || 5;
    rawScore += base + Math.round(Math.log2(count) * (base * 0.45));
  }

  const score = Math.min(100, Math.max(1, rawScore));

  let level = 'low';
  if (countsBySeverity.critical > 0 || score >= 75) {
    level = 'critical';
  } else if (countsBySeverity.high > 0 || score >= 45) {
    level = 'high';
  } else if (countsBySeverity.medium > 0 || score >= 20) {
    level = 'medium';
  }

  const reasons = [];
  if (countsBySeverity.critical > 0) {
    reasons.push(`${countsBySeverity.critical} critical credential or financial secret(s) detected.`);
  }
  if (countsBySeverity.high > 0) {
    reasons.push(`${countsBySeverity.high} high-sensitivity token or account identifier(s) found.`);
  }
  if (countsBySeverity.medium > 0) {
    reasons.push(`${countsBySeverity.medium} direct contact PII item(s) (email/phone) present.`);
  }
  if (countsBySeverity.low > 0) {
    reasons.push(`${countsBySeverity.low} network identifier(s) (IP address) present.`);
  }

  return {
    level,
    score,
    countsBySeverity,
    reasons,
  };
}

/**
 * Classify columns in a parsed CSV or JSON dataset.
 * @param {{ format: string, headers: string[], rows: Array<Record<string, string>> }} structured
 * @param {Function} detectFn
 * @param {Record<string, 'redact'|'keep'>} [columnOverrides={}]
 * @param {{ enabledCategories?: Set<string>|string[]|Record<string, boolean> }} [options={}]
 * @returns {{
 *   format: string,
 *   columns: Array<{
 *     name: string,
 *     totalCells: number,
 *     matchedCells: number,
 *     hitRate: number,
 *     categories: string[],
 *     riskLevel: 'none'|'low'|'medium'|'high'|'critical',
 *     recommendedAction: 'redact'|'review'|'keep',
 *     activeAction: 'redact'|'keep',
 *     hintedByHeader: boolean
 *   }>
 * }}
 */
export function classifyColumns(structured, detectFn, columnOverrides = {}, options = {}) {
  if (!structured || structured.format === 'text' || !structured.headers.length) {
    return { format: structured ? structured.format : 'text', columns: [] };
  }

  const columns = structured.headers.map((header) => {
    const categoryCounts = new Map();
    let maxSeverityRank = 0;
    let maxRiskLevel = 'none';
    let matchedCells = 0;
    let nonEmptyCells = 0;

    const rankMap = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

    for (const row of structured.rows) {
      const value = row[header] ?? '';
      if (value.trim().length > 0) nonEmptyCells += 1;

      const findings = detectFn(value, options);
      if (findings.length > 0) {
        matchedCells += 1;
        for (const f of findings) {
          categoryCounts.set(f.category, (categoryCounts.get(f.category) || 0) + 1);
          if ((rankMap[f.severity] || 0) > maxSeverityRank) {
            maxSeverityRank = rankMap[f.severity];
            maxRiskLevel = f.severity;
          }
        }
      }
    }

    let hintedByHeader = false;
    for (const hint of HEADER_CATEGORY_HINTS) {
      if (hint.pattern.test(header)) {
        hintedByHeader = true;
        if (!categoryCounts.has(hint.category)) {
          categoryCounts.set(hint.category, 0);
        }
        if ((rankMap[hint.severity] || 0) > maxSeverityRank) {
          maxSeverityRank = rankMap[hint.severity];
          maxRiskLevel = hint.severity;
        }
        break;
      }
    }

    const totalCells = Math.max(1, nonEmptyCells || structured.rows.length);
    const hitRate = Math.round((matchedCells / totalCells) * 100);
    const recommendedAction = matchedCells > 0
      ? 'redact'
      : hintedByHeader
        ? 'review'
        : 'keep';

    const activeAction = columnOverrides[header]
      || (recommendedAction === 'redact' ? 'redact' : 'keep');

    return {
      name: header,
      totalCells: structured.rows.length,
      matchedCells,
      hitRate,
      categories: Array.from(categoryCounts.keys()),
      riskLevel: maxRiskLevel,
      recommendedAction,
      activeAction,
      hintedByHeader,
    };
  });

  return {
    format: structured.format,
    columns,
  };
}
