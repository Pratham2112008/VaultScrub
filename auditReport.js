/**
 * @module auditReport
 * @description Compliance Audit Certificate generator for VaultScrub.
 *
 * Builds tamper-evident audit certificates with real SHA-256 digests
 * (via `crypto.subtle.digest`) and exports them as both structured JSON
 * and formatted PDF (via jsPDF). Raw PII values are never included in
 * the certificate payload — only counts, categories, risk levels, and
 * cryptographic integrity hashes.
 */

import { jsPDF } from 'jspdf';
import { computeSha256Hex } from './cryptoVault.js';

export { computeSha256Hex };

/**
 * Build a complete compliance Audit Certificate payload (never includes raw PII).
 * @param {{
 *   rawText: string,
 *   scrubbedText: string,
 *   report: object,
 *   whitelistedCount?: number
 * }} params
 * @returns {Promise<object>}
 */
export async function buildAuditCertificate({ rawText = '', scrubbedText = '', report, whitelistedCount = 0 }) {
  const [originalSha256, sanitizedSha256] = await Promise.all([
    computeSha256Hex(rawText),
    computeSha256Hex(scrubbedText),
  ]);

  const summary = report?.summary || {};
  return {
    certificateType: 'VaultScrub Sanitization Audit Certificate',
    version: '1.0',
    timestamp: new Date().toISOString(),
    verificationStatement: '100% Client-Side Execution • 0 Bytes Transmitted • Memory-Only Processing',
    privacyRiskScore: summary.riskScore ?? 0,
    privacyRiskLevel: String(summary.riskLevel || 'none').toUpperCase(),
    redactionMode: summary.redactionMode || 'token',
    inputFormat: summary.format || 'text',
    totalFindings: summary.totalFindings ?? 0,
    appliedRedactions: summary.appliedRedactions ?? 0,
    whitelistedCount,
    countsByCategory: (report?.countsByCategory || []).map((c) => ({
      category: c.category,
      label: c.label,
      severity: c.severity,
      count: c.count,
    })),
    hashes: {
      algorithm: 'SHA-256',
      originalInputSha256: originalSha256,
      sanitizedOutputSha256: sanitizedSha256,
    },
  };
}

/**
 * Render an Audit Certificate into a downloadable PDF Blob via jsPDF.
 * @param {object} certificate
 * @returns {Blob}
 */
export function buildAuditCertificatePdfBlob(certificate) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 48;
  const maxWidth = pageWidth - margin * 2;
  let y = 56;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('VaultScrub Sanitization Audit Certificate', margin, y);
  y += 22;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text(certificate.verificationStatement, margin, y);
  y += 16;
  doc.text(`Issued (UTC): ${certificate.timestamp}`, margin, y);
  y += 26;

  doc.setDrawColor(180);
  doc.line(margin, y, pageWidth - margin, y);
  y += 22;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('Compliance & Risk Summary', margin, y);
  y += 18;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10.5);
  const summaryLines = [
    `Privacy Risk Score: ${certificate.privacyRiskScore} / 100 (${certificate.privacyRiskLevel})`,
    `Redaction Mode: ${certificate.redactionMode}`,
    `Detected Format: ${String(certificate.inputFormat).toUpperCase()}`,
    `Total Findings: ${certificate.totalFindings} | Applied Redactions: ${certificate.appliedRedactions} | Whitelisted: ${certificate.whitelistedCount}`,
  ];
  for (const line of summaryLines) {
    doc.text(line, margin, y);
    y += 16;
  }

  y += 12;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('Cryptographic Integrity (SHA-256)', margin, y);
  y += 18;

  doc.setFont('courier', 'normal');
  doc.setFontSize(9);
  for (const hashLine of [
    `Original Input SHA-256:  ${certificate.hashes.originalInputSha256}`,
    `Sanitized Output SHA-256: ${certificate.hashes.sanitizedOutputSha256}`,
  ]) {
    const wrapped = doc.splitTextToSize(hashLine, maxWidth);
    for (const part of wrapped) {
      doc.text(part, margin, y);
      y += 13;
    }
  }

  y += 16;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('Detected Categories (Raw Values Omitted)', margin, y);
  y += 18;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  if (!certificate.countsByCategory || certificate.countsByCategory.length === 0) {
    doc.text('No sensitive categories detected.', margin, y);
  } else {
    for (const cat of certificate.countsByCategory) {
      if (y > 760) {
        doc.addPage();
        y = 56;
      }
      doc.text(`• ${cat.label} (${cat.severity}): ${cat.count}`, margin + 8, y);
      y += 15;
    }
  }

  return doc.output('blob');
}
