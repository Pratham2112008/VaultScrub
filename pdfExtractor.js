/**
 * @module pdfExtractor
 * @description Client-side PDF text extraction and sanitized PDF generation.
 *
 * Uses `pdfjs-dist` with a locally bundled worker for zero-CDN PDF text
 * extraction, and `jsPDF` for generating clean multi-page sanitized PDF
 * documents from scrubbed output.
 *
 * Both operations run entirely in-browser with zero external network calls.
 */

import * as pdfjsLib from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { jsPDF } from 'jspdf';

pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl;

/**
 * Extract plain text from an uploaded PDF file in browser memory.
 * @param {ArrayBuffer} arrayBuffer
 * @param {(percent: number) => void} [onProgress]
 * @returns {Promise<{ text: string, pageCount: number }>}
 */
export async function extractTextFromPdf(arrayBuffer, onProgress) {
  const loadingTask = pdfjsLib.getDocument({ data: new Uint8Array(arrayBuffer) });
  const pdf = await loadingTask.promise;
  const pageTexts = [];

  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum += 1) {
    const page = await pdf.getPage(pageNum);
    const content = await page.getTextContent();

    let lastY = null;
    let line = '';
    const lines = [];

    for (const item of content.items) {
      if (!('str' in item)) continue;
      const y = Array.isArray(item.transform) ? Math.round(item.transform[5]) : null;
      if (lastY !== null && y !== null && Math.abs(y - lastY) > 4) {
        if (line.trim()) lines.push(line.trimEnd());
        line = item.str;
      } else {
        line += line && item.str && !line.endsWith(' ') && !item.str.startsWith(' ')
          ? ` ${item.str}`
          : item.str;
      }
      lastY = y;
    }

    if (line.trim()) lines.push(line.trimEnd());
    pageTexts.push(lines.join('\n'));

    if (typeof onProgress === 'function') {
      onProgress(Math.round((pageNum / pdf.numPages) * 100));
    }
  }

  return {
    text: pageTexts.join('\n\n'),
    pageCount: pdf.numPages,
  };
}

/**
 * Generate a clean, multi-page sanitized PDF document locally via jsPDF.
 * @param {string} scrubbedText
 * @param {{ title?: string }} [options]
 * @returns {Blob}
 */
export function buildSanitizedPdfBlob(scrubbedText, options = {}) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 48;
  const maxWidth = pageWidth - margin * 2;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text(options.title || 'VaultScrub Sanitized Document', margin, margin);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text(`Generated locally • Zero network egress • ${new Date().toISOString()}`, margin, margin + 16);

  doc.setFont('courier', 'normal');
  doc.setFontSize(9.5);

  const lines = doc.splitTextToSize(scrubbedText || '(empty document)', maxWidth);
  let y = margin + 40;
  const lineHeight = 13;

  for (const line of lines) {
    if (y > pageHeight - margin) {
      doc.addPage();
      y = margin;
    }
    doc.text(line, margin, y);
    y += lineHeight;
  }

  return doc.output('blob');
}
