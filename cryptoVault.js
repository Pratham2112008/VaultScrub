/**
 * @module cryptoVault
 * @description Client-side AES-GCM + PBKDF2 Encrypted Key Vault & Re-hydration.
 *
 * Encrypts bidirectional pseudonym token mappings into a portable `.vault.json`
 * file using AES-GCM-256 with a user passphrase derived via PBKDF2-SHA256
 * (250 000 iterations). Provides decryption, AI-response re-hydration
 * (restoring `[EMAIL_1]` back to original values), and SHA-256 hex hashing.
 *
 * Uses the Web Crypto API (`crypto.subtle`) with zero network calls.
 */

const VAULT_FORMAT = 'vaultscrub-key-v1';
const PBKDF2_ITERATIONS = 250000;

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API is unavailable in this context.');
  }
  return subtle;
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

async function deriveAesKey(passphrase, saltBytes, iterations = PBKDF2_ITERATIONS) {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const keyMaterial = await subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypt bidirectional pseudonym token mappings with a user passphrase.
 * @param {Array<{ token: string, original: string, category: string }>} mappingEntries
 * @param {string} passphrase
 * @returns {Promise<string>} JSON string for .vault.json export
 */
export async function encryptVaultMapping(mappingEntries, passphrase) {
  if (!passphrase || passphrase.length < 4) {
    throw new Error('Passphrase must be at least 4 characters long.');
  }
  if (!Array.isArray(mappingEntries) || mappingEntries.length === 0) {
    throw new Error('No pseudonym mappings available to export.');
  }

  const subtle = getSubtle();
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS);

  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      version: 1,
      createdAt: new Date().toISOString(),
      entries: mappingEntries,
    }),
  );

  const encryptedBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext,
  );

  return JSON.stringify(
    {
      format: VAULT_FORMAT,
      kdf: 'PBKDF2-SHA256',
      iterations: PBKDF2_ITERATIONS,
      cipher: 'AES-GCM-256',
      createdAt: new Date().toISOString(),
      tokenCount: mappingEntries.length,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
    },
    null,
    2,
  );
}

/**
 * Decrypt a .vault.json key file using the user's passphrase.
 * @param {string} vaultJsonString
 * @param {string} passphrase
 * @returns {Promise<{ entries: Array<{ token: string, original: string, category: string }>, createdAt: string }>}
 */
export async function decryptVaultMapping(vaultJsonString, passphrase) {
  if (!passphrase) {
    throw new Error('Enter the passphrase used to encrypt this key file.');
  }

  let parsed;
  try {
    parsed = JSON.parse(vaultJsonString);
  } catch {
    throw new Error('Invalid .vault.json file format.');
  }

  if (!parsed || parsed.format !== VAULT_FORMAT || !parsed.salt || !parsed.iv || !parsed.ciphertext) {
    throw new Error('Unrecognized VaultScrub encrypted key schema.');
  }

  const subtle = getSubtle();
  const salt = base64ToBytes(parsed.salt);
  const iv = base64ToBytes(parsed.iv);
  const ciphertext = base64ToBytes(parsed.ciphertext);
  const key = await deriveAesKey(passphrase, salt, parsed.iterations || PBKDF2_ITERATIONS);

  let decryptedBuffer;
  try {
    decryptedBuffer = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  } catch {
    throw new Error('Decryption failed. Verify your passphrase or key file.');
  }

  const decoded = JSON.parse(new TextDecoder().decode(decryptedBuffer));
  if (!decoded || !Array.isArray(decoded.entries)) {
    throw new Error('Decrypted key payload is malformed.');
  }

  return {
    entries: decoded.entries,
    createdAt: decoded.createdAt || parsed.createdAt || '',
  };
}

/**
 * Restore pseudonym tokens inside an AI response back to their original PII values.
 * @param {string} aiResponseText
 * @param {Array<{ token: string, original: string }>} entries
 * @returns {{ restoredText: string, restoredCount: number, tokensFound: number }}
 */
export function rehydrateText(aiResponseText, entries = []) {
  const safeText = typeof aiResponseText === 'string' ? aiResponseText : '';
  if (!safeText || entries.length === 0) {
    return { restoredText: safeText, restoredCount: 0, tokensFound: 0 };
  }

  const lookup = new Map(entries.map((item) => [item.token, item.original]));
  const escapedTokens = entries
    .map((item) => item.token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .sort((a, b) => b.length - a.length);

  if (escapedTokens.length === 0) {
    return { restoredText: safeText, restoredCount: 0, tokensFound: 0 };
  }

  const pattern = new RegExp(escapedTokens.join('|'), 'g');
  let restoredCount = 0;
  const matchedSet = new Set();

  const restoredText = safeText.replace(pattern, (match) => {
    const original = lookup.get(match);
    if (original === undefined) return match;
    restoredCount += 1;
    matchedSet.add(match);
    return original;
  });

  return {
    restoredText,
    restoredCount,
    tokensFound: matchedSet.size,
  };
}

/**
 * Compute real lowercase hex SHA-256 hash of a UTF-8 string using Web Crypto API.
 * @param {string} text
 * @returns {Promise<string>}
 */
export async function computeSha256Hex(text) {
  const subtle = getSubtle();
  const bytes = new TextEncoder().encode(typeof text === 'string' ? text : '');
  const hashBuffer = await subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
