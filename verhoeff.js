/**
 * Pure Verhoeff checksum validation for Indian Aadhaar numbers.
 * Uses the standard d (dihedral), p (permutation), and inv lookup tables.
 * Zero DOM dependencies.
 */

// Multiplication table d(j, k)
export const VERHOEFF_D = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]);

// Permutation table p(pos mod 8, digit)
export const VERHOEFF_P = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]);

// Inverse table inv(j)
export const VERHOEFF_INV = Object.freeze([0, 4, 3, 2, 1, 5, 6, 7, 8, 9]);

/**
 * Validate a numeric string using the Verhoeff checksum algorithm.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidVerhoeff(raw) {
  if (typeof raw !== 'string') return false;
  const digits = raw.replace(/\D/g, '');
  if (!digits || !/^\d+$/.test(digits)) return false;

  let c = 0;
  for (let i = 0; i < digits.length; i += 1) {
    const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

/**
 * Generate the Verhoeff check digit for a base numeric string (useful for tests).
 * @param {string} baseDigits
 * @returns {string}
 */
export function generateVerhoeffCheckDigit(baseDigits) {
  let c = 0;
  for (let i = 0; i < baseDigits.length; i += 1) {
    const digit = baseDigits.charCodeAt(baseDigits.length - 1 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digit]];
  }
  return String(VERHOEFF_INV[c]);
}

/**
 * Validate a 12-digit Indian Aadhaar number (format + Verhoeff checksum).
 * Aadhaar numbers never begin with 0 or 1 and cannot be all identical digits.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidAadhaar(raw) {
  if (typeof raw !== 'string') return false;
  const digits = raw.replace(/[\s-]/g, '');
  if (!/^\d{12}$/.test(digits)) return false;
  if (digits.startsWith('0') || digits.startsWith('1')) return false;
  if (/^(\d)\1{11}$/.test(digits)) return false;
  return isValidVerhoeff(digits);
}
