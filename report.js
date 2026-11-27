/**
 * @module report
 * @description Pure audit report builder and serializers for VaultScrub.
 *
 * Assembles a structured report from pipeline results (detections, redaction
 * stats, risk classification, column analysis, privacy telemetry) and
 * serializes it to both JSON and human-readable Markdown — without ever
 * including raw secret values in the output.
 *
 * Zero DOM or browser global dependencies — safe for Node.js test execution.
 */

import { DETECTOR_CATALOG } from './detectors.js';

const CATALOG_META = new Map(DETECTOR_CATALOG.map((item) => [item.id, item]));

/**
 * Build a structured privacy & redaction audit report from current pipeline results.
 * Never includes unmasked raw secret values in exported findings.
 * @param {{
 *   rawText: string,
 *   detections: Array<object>,
 *   redacted: object,
 *   classification: object,
 *   columnReport?: object,
 *   format?: string,
 *   redactionMode?: string,
 *   privacy?: object
 * }} snapshot
 * @returns {object}
 */
export function buildReport(snapshot) {
  const {
    rawText = '',
    detections = [],
    redacted = { scrubbedText: '', replacements: [], stats: { totalApplied: 0, uniqueValues: 0, originalLength: 0, scrubbedLength: 0 } },
    classification = { level: 'none', score: 0, countsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, reasons: [] },
    columnReport = { format: 'text', columns: [] },
    format = 'text',
    redactionMode = 'token',
    privacy = { localOnly: true, networkRequests: 0, persistence: 'memory-only' },
  } = snapshot || {};

  const categoryMap = new Map();
  for (const finding of detections) {
    const existing = categoryMap.get(finding.category);
    if (existing) {
      existing.count += 1;
    } else {
      const meta = CATALOG_META.get(finding.category);
      categoryMap.set(finding.category, {
        category: finding.category,
        label: meta ? meta.label : finding.label || finding.category,
        severity: meta ? meta.severity : finding.severity || 'medium',
        count: 1,
      });
    }
  }

  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const countsByCategory = Array.from(categoryMap.values()).sort((a, b) => {
    const sevDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return b.count - a.count;
  });

  const originalLength = rawText.length;
  const scrubbedLength = (redacted.scrubbedText || '').length;

  return {
    summary: {
      totalFindings: detections.length,
      appliedRedactions: redacted.stats?.totalApplied ?? 0,
      uniqueValues: redacted.stats?.uniqueValues ?? 0,
      categoriesDetected: countsByCategory.length,
      riskLevel: classification.level,
      riskScore: classification.score,
      format,
      redactionMode,
      originalLength,
      scrubbedLength,
      characterDelta: scrubbedLength - originalLength,
    },
    countsByCategory,
    countsBySeverity: { ...classification.countsBySeverity },
    reasons: [...(classification.reasons || [])],
    columns: [...(columnReport.columns || [])],
    findings: [...(redacted.replacements || [])],
    privacyAudit: {
      localOnly: Boolean(privacy.localOnly ?? true),
      networkRequests: Number(privacy.networkRequests ?? 0),
      externalDependencies: 0,
      persistence: privacy.persistence || 'memory-only',
      bytesProcessed: originalLength,
    },
  };
}

/**
 * Serialize a report object to formatted JSON.
 * @param {object} report
 * @returns {string}
 */
export function formatReportAsJson(report) {
  return JSON.stringify(report, null, 2);
}

/**
 * Serialize a report object to a human-readable Markdown audit log.
 * @param {object} report
 * @returns {string}
 */
export function formatReportAsMarkdown(report) {
  const s = report.summary;
  const lines = [
    '# VaultScrub Audit Report',
    '',
    `- **Risk Level**: ${String(s.riskLevel).toUpperCase()} (${s.riskScore}/100)`,
    `- **Input Format**: ${s.format}`,
    `- **Redaction Mode**: ${s.redactionMode}`,
    `- **Total Findings**: ${s.totalFindings} (${s.uniqueValues} unique values)`,
    `- **Applied Redactions**: ${s.appliedRedactions}`,
    `- **Processing Mode**: Local-only (${report.privacyAudit.networkRequests} network calls, ${report.privacyAudit.persistence})`,
    '',
    '## Category Breakdown',
    '',
  ];

  if (report.countsByCategory.length === 0) {
    lines.push('No sensitive entities detected.');
  } else {
    lines.push('| Category | Severity | Count |');
    lines.push('| --- | --- | ---: |');
    for (const item of report.countsByCategory) {
      lines.push(`| ${item.label} | ${item.severity} | ${item.count} |`);
    }
  }

  if (report.columns.length > 0) {
    lines.push('', '## Structured Columns', '', '| Column | Risk | Hit Rate | Action |', '| --- | --- | ---: | --- |');
    for (const col of report.columns) {
      lines.push(`| ${col.name} | ${col.riskLevel} | ${col.hitRate}% | ${col.activeAction} |`);
    }
  }

  if (report.findings.length > 0) {
    lines.push('', '## Redacted Items (Masked Previews)', '', '| Line:Col | Category | Preview | Replacement |', '| --- | --- | --- | --- |');
    for (const item of report.findings) {
      lines.push(`| ${item.line}:${item.column} | ${item.label} | \`${item.originalPreview}\` | \`${item.replacement}\` |`);
    }
  }

  return lines.join('\n');
}
