import test from 'node:test';
import assert from 'node:assert/strict';

import { detectSensitiveData, detectStructuredFormat, isValidLuhn } from '../detectors.js';
import { redactText, redactStructuredDataset, maskValue } from '../redact.js';
import { classifyRisk, classifyColumns } from '../classify.js';
import { buildReport, formatReportAsJson, formatReportAsMarkdown } from '../report.js';
import { isValidVerhoeff, generateVerhoeffCheckDigit, isValidAadhaar } from '../verhoeff.js';
import { parseCsvRecords, serializeCsvRecords } from '../csvParser.js';
import { encryptVaultMapping, decryptVaultMapping, rehydrateText, computeSha256Hex } from '../cryptoVault.js';
import { buildAuditCertificate } from '../auditReport.js';

test('detectSensitiveData detects core PII and secret types with accurate positions', () => {
  const sample = [
    'Contact: alice@example.com or (415) 555-0199',
    'Key: AKIAIOSFODNN7EXAMPLE',
    'SSN: 123-45-6789',
    'IP: 10.0.0.42',
  ].join('\n');

  const findings = detectSensitiveData(sample);
  const categories = findings.map((f) => f.category);

  assert.ok(categories.includes('email'));
  assert.ok(categories.includes('phone'));
  assert.ok(categories.includes('api_key'));
  assert.ok(categories.includes('ssn'));
  assert.ok(categories.includes('ipv4'));

  for (const f of findings) {
    assert.equal(sample.slice(f.start, f.end), f.value);
    assert.ok(f.line >= 1 && f.column >= 1);
  }
});

test('credit card Luhn validation rejects invalid sequences and accepts valid cards', () => {
  assert.equal(isValidLuhn('4532-0151-1283-0366'), true);
  assert.equal(isValidLuhn('4532-0151-1283-0367'), false);

  const findings = detectSensitiveData('valid=4532015112830366 invalid=4532015112830367');
  assert.equal(findings.filter((f) => f.category === 'credit_card').length, 1);
});

test('category filtering disables specific detectors cleanly', () => {
  const text = 'user@example.com 192.168.1.1';
  const onlyEmail = detectSensitiveData(text, { enabledCategories: ['email'] });
  assert.equal(onlyEmail.length, 1);
  assert.equal(onlyEmail[0].category, 'email');
});

test('redactText supports token, mask, hash, and remove modes with consistent tokens', () => {
  const text = 'From alice@example.com to bob@example.com (cc alice@example.com)';
  const findings = detectSensitiveData(text);

  const tokenized = redactText(text, findings, { mode: 'token' });
  assert.equal(tokenized.scrubbedText, 'From [EMAIL_1] to [EMAIL_2] (cc [EMAIL_1])');
  assert.equal(tokenized.stats.totalApplied, 3);
  assert.equal(tokenized.stats.uniqueValues, 2);

  const masked = redactText(text, findings, { mode: 'mask' });
  assert.ok(masked.scrubbedText.includes('al***@example.com'));

  const hashed = redactText(text, findings, { mode: 'hash' });
  assert.match(hashed.scrubbedText, /\[EMAIL#[0-9a-f]{10}\]/);

  const removed = redactText(text, findings, { mode: 'remove' });
  assert.equal(removed.scrubbedText, 'From [REDACTED] to [REDACTED] (cc [REDACTED])');
});

test('detectStructuredFormat parses CSV and JSON arrays and classifyColumns evaluates risk', () => {
  const csv = 'id,email,notes\n1,a@example.com,ok\n2,b@example.com,ok';
  const parsedCsv = detectStructuredFormat(csv, 'auto');
  assert.equal(parsedCsv.format, 'csv');
  assert.deepEqual(parsedCsv.headers, ['id', 'email', 'notes']);

  const colReport = classifyColumns(parsedCsv, detectSensitiveData, { email: 'keep' });
  const emailCol = colReport.columns.find((c) => c.name === 'email');
  assert.equal(emailCol.hitRate, 100);
  assert.equal(emailCol.activeAction, 'keep');

  const redactedCsv = redactStructuredDataset(parsedCsv, { email: 'keep', id: 'redact', notes: 'redact' }, detectSensitiveData, { mode: 'token' });
  assert.ok(redactedCsv.scrubbedText.includes('a@example.com'));
  assert.equal(redactedCsv.suppressedCells, 2);
});

test('classifyRisk and buildReport produce safe audit summaries without leaking raw secrets', () => {
  const secret = 'AKIAIOSFODNN7EXAMPLE';
  const rawText = `key=${secret}`;
  const detections = detectSensitiveData(rawText);
  const classification = classifyRisk(detections, rawText.length);
  assert.equal(classification.level, 'critical');
  assert.ok(classification.score >= 30);

  const redacted = redactText(rawText, detections, { mode: 'token' });
  const report = buildReport({ rawText, detections, redacted, classification, format: 'text', redactionMode: 'token' });

  const jsonOut = formatReportAsJson(report);
  const mdOut = formatReportAsMarkdown(report);
  assert.equal(jsonOut.includes(secret), false);
  assert.equal(mdOut.includes(secret), false);
  assert.ok(mdOut.includes('VaultScrub Audit Report'));
  assert.equal(maskValue(secret, 'api_key').includes(secret), false);
});

test('Verhoeff algorithm validates genuine Aadhaar numbers and rejects random 12-digit numbers', () => {
  const base = '23415678901';
  const validAadhaar = `${base}${generateVerhoeffCheckDigit(base)}`;
  const invalidAadhaar = `${base}${(Number(validAadhaar.slice(-1)) + 1) % 10}`;

  assert.equal(isValidVerhoeff(validAadhaar), true);
  assert.equal(isValidAadhaar(validAadhaar), true);
  assert.equal(isValidAadhaar(invalidAadhaar), false);
  assert.equal(isValidAadhaar('999999999999'), false);
  assert.equal(isValidAadhaar('123456789012'), false);
});

test('Indian PII detectors match Aadhaar, PAN, UPI ID, GSTIN, IFSC, and +91 phone across redaction modes', () => {
  const base = '23415678901';
  const validAadhaar = `${base}${generateVerhoeffCheckDigit(base)}`;
  const text = [
    `PAN: ABCDE1234F Aadhaar: ${validAadhaar} Fake: 999999999999`,
    'UPI: aarav.sharma@okhdfcbank GSTIN: 27ABCDE1234F1Z5 IFSC: HDFC0001234',
    'Phone: +91 98765 43210',
  ].join('\n');

  const findings = detectSensitiveData(text);
  const categories = findings.map((f) => f.category);
  assert.ok(categories.includes('pan'));
  assert.ok(categories.includes('aadhaar'));
  assert.ok(categories.includes('upi_id'));
  assert.ok(categories.includes('gstin'));
  assert.ok(categories.includes('ifsc'));
  assert.ok(categories.includes('phone'));
  assert.equal(findings.some((f) => f.value === '999999999999'), false);

  const tokenOut = redactText(text, findings, { mode: 'token' });
  assert.ok(tokenOut.scrubbedText.includes('[PAN_1]'));
  assert.ok(tokenOut.scrubbedText.includes('[AADHAAR_1]'));
  assert.ok(tokenOut.scrubbedText.includes('[UPI_ID_1]'));
  assert.ok(tokenOut.mappingEntries.length >= 6);

  const maskOut = redactText(text, findings, { mode: 'mask' });
  assert.ok(maskOut.scrubbedText.includes('XXXX-XXXX-'));
  assert.ok(maskOut.scrubbedText.includes('aa***@okhdfcbank'));

  const removeOut = redactText(text, findings, { mode: 'remove' });
  assert.ok(removeOut.scrubbedText.includes('[REDACTED]'));
});

test('RFC-4180 CSV parser handles quoted commas and selective whitelisting restores ignored items', () => {
  const csv = 'name,email,notes\n"Sharma, Aarav",aarav@example.com,"VIP, Delhi"\n"Lin, Maya",maya@example.com,"Standard"';
  const parsed = parseCsvRecords(csv);
  assert.equal(parsed.valid, true);
  assert.equal(parsed.rows[0].name, 'Sharma, Aarav');
  assert.equal(parsed.rows[0].notes, 'VIP, Delhi');

  const roundTrip = serializeCsvRecords(parsed.headers, parsed.rows, ',');
  assert.ok(roundTrip.includes('"Sharma, Aarav"'));

  const text = 'Primary: aarav@example.com Backup: maya@example.com Secondary: aarav@example.com';
  const findings = detectSensitiveData(text);
  const whitelisted = redactText(text, findings, {
    mode: 'token',
    whitelistedValues: new Set(['aarav@example.com']),
  });
  assert.ok(whitelisted.scrubbedText.includes('aarav@example.com'));
  assert.ok(!whitelisted.scrubbedText.includes('maya@example.com'));
});

test('AES-GCM + PBKDF2 encrypted key vault round-trips and re-hydrates AI responses locally', async () => {
  const input = 'Send invoice to aarav@example.com and PAN ABCDE1234F.';
  const findings = detectSensitiveData(input);
  const scrubbed = redactText(input, findings, { mode: 'token' });

  const vaultJson = await encryptVaultMapping(scrubbed.mappingEntries, 'vault-pass-123');
  assert.equal(vaultJson.includes('aarav@example.com'), false);
  assert.equal(vaultJson.includes('ABCDE1234F'), false);

  await assert.rejects(() => decryptVaultMapping(vaultJson, 'wrong-pass'));

  const decrypted = await decryptVaultMapping(vaultJson, 'vault-pass-123');
  const aiReply = 'Confirmed: invoice emailed to [EMAIL_1] under tax ID [PAN_1].';
  const restored = rehydrateText(aiReply, decrypted.entries);
  assert.equal(restored.restoredText, 'Confirmed: invoice emailed to aarav@example.com under tax ID ABCDE1234F.');
  assert.equal(restored.restoredCount, 2);
});

test('Audit Certificate computes real SHA-256 hashes and omits raw PII', async () => {
  const rawText = 'PAN=ABCDE1234F';
  const detections = detectSensitiveData(rawText);
  const redacted = redactText(rawText, detections, { mode: 'token' });
  const classification = classifyRisk(detections, rawText.length);
  const report = buildReport({ rawText, detections, redacted, classification, format: 'text', redactionMode: 'token' });

  const cert = await buildAuditCertificate({
    rawText,
    scrubbedText: redacted.scrubbedText,
    report,
    whitelistedCount: 0,
  });

  assert.match(cert.hashes.originalInputSha256, /^[0-9a-f]{64}$/);
  assert.match(cert.hashes.sanitizedOutputSha256, /^[0-9a-f]{64}$/);
  assert.notEqual(cert.hashes.originalInputSha256, cert.hashes.sanitizedOutputSha256);
  assert.equal(cert.hashes.originalInputSha256, await computeSha256Hex(rawText));
  assert.equal(JSON.stringify(cert).includes('ABCDE1234F'), false);
});
