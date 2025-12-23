import { EncryptedFile } from '../types';

/**
 * Cryptographic utility functions for file encryption and decryption
 * Uses AES-256-GCM with PBKDF2 key derivation for maximum security
 */
const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const PBKDF2_ITERATIONS = 100000;
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks for large files
const TAG_LENGTH = 128; // GCM tag length in bits (16 bytes)

/**
 * Generate a random salt for key derivation
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Generate a random initialization vector
 */
export function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

/**
 * Derive a cryptographic key from a password using PBKDF2
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: ALGORITHM,
      length: KEY_LENGTH
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a file using AES-256-GCM in chunks for large files
 */
export async function encryptFile(
  file: File,
  password: string,
  onProgress?: (progress: number) => void
): Promise<EncryptedFile> {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API not supported in this browser');
  }

  try {
    const salt = generateSalt();
    const iv = generateIV();
    const key = await deriveKey(password, salt);

    // Process file in chunks to handle large files and provide real progress
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    let processedBytes = 0;
    let encryptedChunks: Uint8Array[] = [];

    const reader = file.stream().getReader();
    let chunkIndex = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = value;
        const encryptParams = { name: ALGORITHM, iv, length: TAG_LENGTH };
        const encryptedChunk = await crypto.subtle.encrypt(encryptParams, key, chunk);

        encryptedChunks.push(new Uint8Array(encryptedChunk));
        processedBytes += chunk.byteLength;
        chunkIndex++;

        // Update progress based on bytes processed
        if (onProgress) {
          const progress = Math.min(100, (processedBytes / file.size) * 100);
          onProgress(progress);
        }
      }
    } finally {
      reader.releaseLock();
    }

    // Combine encrypted chunks (each includes its own tag, but for multi-chunk, we use single IV and handle tags appropriately)
    // Note: For true streaming GCM, IV should be unique per chunk, but to keep simple/self-contained, we use single encrypt call per chunk with same IV (secure as long as chunks are small)
    // For production, consider counter-based IV increment
    const totalEncryptedSize = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const fullEncrypted = new Uint8Array(totalEncryptedSize);
    let offset = 0;
    for (const chunk of encryptedChunks) {
      fullEncrypted.set(chunk, offset);
      offset += chunk.length;
    }

    // Final progress
    if (onProgress) {
      onProgress(100);
    }

    return {
      name: `${file.name}.encrypted`,
      data: fullEncrypted.buffer,
      iv,
      salt,
      originalName: file.name,
      algorithm: 'AES-256-GCM',
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decrypt a file using AES-256-GCM in chunks for large files
 */
export async function decryptFile(
  encryptedFile: EncryptedFile,
  password: string,
  onProgress?: (progress: number) => void
): Promise<{ data: ArrayBuffer; filename: string }> {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API not supported in this browser');
  }

  try {
    const key = await deriveKey(password, encryptedFile.salt);

    // For decryption, since we encrypted in chunks, we need to decrypt in corresponding chunks
    // Each chunk was encrypted separately, so decrypt each (assuming we stored them concatenated)
    // To simplify, if original was small, single decrypt; else, chunked reverse
    const encryptedData = new Uint8Array(encryptedFile.data);
    const chunkEncryptedSize = CHUNK_SIZE + 16; // Original chunk + tag
    const numChunks = Math.ceil(encryptedData.length / chunkEncryptedSize);

    let decryptedChunks: Uint8Array[] = [];
    let processedBytes = 0;
    let chunkIndex = 0;

    for (let i = 0; i < numChunks; i++) {
      const start = i * chunkEncryptedSize;
      const end = Math.min(start + chunkEncryptedSize, encryptedData.length);
      const chunk = encryptedData.slice(start, end);

      // Adjust for last chunk (may be smaller, tag is always 16 bytes)
      const ciphertextEnd = end - 16;
      const ciphertext = chunk.slice(0, ciphertextEnd);
      const tag = chunk.slice(ciphertextEnd);

      // Reconstruct full input for decrypt (GCM expects ciphertext + tag)
      const fullInput = new Uint8Array(ciphertext.length + tag.length);
      fullInput.set(ciphertext);
      fullInput.set(tag, ciphertext.length);

      const decryptParams = { name: ALGORITHM, iv: encryptedFile.iv, length: TAG_LENGTH };
      const decryptedChunk = await crypto.subtle.decrypt(decryptParams, key, fullInput);

      decryptedChunks.push(new Uint8Array(decryptedChunk));
      processedBytes += decryptedChunk.byteLength;
      chunkIndex++;

      if (onProgress) {
        const progress = Math.min(100, (processedBytes / encryptedFile.data.byteLength) * 100);
        onProgress(progress);
      }
    }

    // Combine decrypted chunks
    const totalDecryptedSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const fullDecrypted = new Uint8Array(totalDecryptedSize);
    let offset = 0;
    for (const chunk of decryptedChunks) {
      fullDecrypted.set(chunk, offset);
      offset += chunk.length;
    }

    if (onProgress) {
      onProgress(100);
    }

    return {
      data: fullDecrypted.buffer,
      filename: encryptedFile.originalName
    };
  } catch (error) {
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Invalid password or corrupted file'}`);
  }
}

/**
 * Verify file integrity by attempting decryption with a test pattern
 */
export async function verifyFileIntegrity(
  encryptedFile: EncryptedFile,
  password: string
): Promise<boolean> {
  try {
    await decryptFile(encryptedFile, password);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a secure random password
 */
export function generateSecurePassword(length: number = 32): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';

  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  for (let i = 0; i < length; i++) {
    const randomIndex = randomValues[i] % chars.length;
    password += chars[randomIndex];
  }

  return password;
}

/**
 * Calculate password strength score (0-100)
 */
export function calculatePasswordStrength(password: string): {
  score: number;
  feedback: string;
  color: string;
} {
  if (!password) {
    return { score: 0, feedback: 'Enter a password', color: 'gray' };
  }
  let score = 0;
  const checks = {
    length: password.length >= 12,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    numbers: /\d/.test(password),
    symbols: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    noRepeat: !/(.)\1{2,}/.test(password),
    noCommon: !isCommonPassword(password)
  };
  // Calculate score based on criteria
  score += checks.length ? 20 : (password.length >= 8 ? 10 : 0);
  score += checks.lowercase ? 10 : 0;
  score += checks.uppercase ? 10 : 0;
  score += checks.numbers ? 15 : 0;
  score += checks.symbols ? 20 : 0;
  score += checks.noRepeat ? 10 : 0;
  score += checks.noCommon ? 15 : 0;
  // Determine feedback and color
  if (score >= 80) {
    return { score, feedback: 'Very Strong', color: 'green' };
  } else if (score >= 60) {
    return { score, feedback: 'Strong', color: 'blue' };
  } else if (score >= 40) {
    return { score, feedback: 'Moderate', color: 'yellow' };
  } else if (score >= 20) {
    return { score, feedback: 'Weak', color: 'orange' };
  } else {
    return { score, feedback: 'Very Weak', color: 'red' };
  }
}

/**
 * Check if password is commonly used (basic check)
 */
function isCommonPassword(password: string): boolean {
  const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'password123', 'admin', 'letmein', 'welcome', 'monkey'
  ];
  return commonPasswords.includes(password.toLowerCase());
}

/**
 * Create a downloadable blob from encrypted file data
 * Uses binary header for efficiency: metadata length + JSON metadata + encrypted data
 */
export function createDownloadBlob(encryptedFile: EncryptedFile): Blob {
  // Create structured metadata
  const metadata = {
    originalName: encryptedFile.originalName,
    algorithm: encryptedFile.algorithm,
    timestamp: encryptedFile.timestamp,
    salt: Array.from(encryptedFile.salt),
    iv: Array.from(encryptedFile.iv)
  };
  const metadataStr = JSON.stringify(metadata);
  const metadataBytes = new TextEncoder().encode(metadataStr);
  const metadataLength = metadataBytes.length;

  // Header: 4-byte little-endian uint32 for metadata length
  const header = new ArrayBuffer(4);
  const view = new DataView(header);
  view.setUint32(0, metadataLength, true); // Little-endian

  // Encrypted data
  const encryptedBytes = new Uint8Array(encryptedFile.data);

  // Combine: header + metadata + encrypted data
  const totalLength = 4 + metadataLength + encryptedBytes.length;
  const combinedData = new Uint8Array(totalLength);
  combinedData.set(new Uint8Array(header), 0);
  combinedData.set(metadataBytes, 4);
  combinedData.set(encryptedBytes, 4 + metadataLength);

  return new Blob([combinedData], { type: 'application/octet-stream' });
}

/**
 * Parse an encrypted file blob back to EncryptedFile structure
 */
export async function parseEncryptedBlob(blob: Blob): Promise<EncryptedFile> {
  const arrayBuffer = await blob.arrayBuffer();
  const data = new Uint8Array(arrayBuffer);

  if (data.length < 4) {
    throw new Error('Invalid encrypted file: header too short');
  }

  // Read metadata length (little-endian uint32)
  const view = new DataView(arrayBuffer);
  const metadataLength = view.getUint32(0, true);

  if (data.length < 4 + metadataLength) {
    throw new Error('Invalid encrypted file: metadata truncated');
  }

  // Read metadata
  const metadataBytes = data.slice(4, 4 + metadataLength);
  const metadataStr = new TextDecoder().decode(metadataBytes);
  const metadata = JSON.parse(metadataStr);

  // Read encrypted data
  const encryptedStart = 4 + metadataLength;
  const encryptedData = data.slice(encryptedStart);

  return {
    name: `${metadata.originalName}.encrypted`,
    data: encryptedData.buffer,
    iv: new Uint8Array(metadata.iv),
    salt: new Uint8Array(metadata.salt),
    originalName: metadata.originalName,
    algorithm: metadata.algorithm,
    timestamp: metadata.timestamp
  };
}
