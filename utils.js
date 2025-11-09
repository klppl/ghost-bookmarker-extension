/**
 * JWT signing utility for Ghost Admin API
 * Based on Ghost's JWT implementation
 */

/**
 * Base64 URL-safe encode
 */
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Create JWT token for Ghost Admin API
 * @param {string} keyId - The ID part of the Admin API key (before the colon)
 * @param {string} secret - The Secret part of the Admin API key (after the colon)
 * @param {string} audience - The API URL endpoint
 * @returns {string} JWT token
 */
function createJWT(keyId, secret, audience) {
  const header = {
    alg: 'HS256',
    kid: keyId,
    typ: 'JWT'
  };
  
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    exp: now + 5 * 60, // 5 minutes expiry
    aud: audience
  };
  
  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  // Create signature
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = b64_hmac_sha256(secret, signatureInput);
  const encodedSignature = base64UrlEncode(signature);
  
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * HMAC SHA256 implementation for JWT signing
 * Uses Web Crypto API when available, falls back to simpler method
 */
function b64_hmac_sha256(key, message) {
  // Note: In a real implementation, we'd use Web Crypto API
  // For now, this is a placeholder - in production, you'd want to use
  // SubtleCrypto API or a library like jsrsasign
  
  // Using a simple implementation - in production, use Web Crypto API:
  // crypto.subtle.importKey(...).then(key => crypto.subtle.sign(...))
  
  // For Firefox extension, we can use Web Crypto API synchronously in workers
  // but for background scripts, we'll need to use async crypto
  
  // This is a simplified version - in production, use proper crypto
  throw new Error('JWT signing requires Web Crypto API implementation');
}

/**
 * Async JWT creation using Web Crypto API
 */
async function createJWTAsync(keyId, secret, audience) {
  const header = {
    alg: 'HS256',
    kid: keyId,
    typ: 'JWT'
  };
  
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    exp: now + 5 * 60,
    aud: audience
  };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  // Import key
  const keyData = hexToUint8Array(secret);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  // Sign
  const signatureArrayBuffer = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    new TextEncoder().encode(signatureInput)
  );
  
  // Convert to base64
  const signatureBytes = new Uint8Array(signatureArrayBuffer);
  const signatureB64 = btoa(String.fromCharCode(...signatureBytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${encodedHeader}.${encodedPayload}.${signatureB64}`;
}

/**
 * Parse Admin API key into keyId and secret
 * @param {string} apiKey - Full Admin API key (format: keyId:secret)
 * @returns {Object} {keyId, secret}
 */
function parseAdminAPIKey(apiKey) {
  const parts = apiKey.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid Admin API key format. Expected format: keyId:secret');
  }
  return {
    keyId: parts[0],
    secret: parts[1]
  };
}

/**
 * Sanitize and validate Ghost API URL
 * @param {string} url - Ghost Admin API URL
 * @returns {string} Sanitized URL
 */
function sanitizeGhostURL(url) {
  if (!url) {
    throw new Error('Ghost API URL is required');
  }
  
  // Remove trailing slashes
  url = url.trim().replace(/\/+$/, '');
  
  // Validate URL format
  try {
    const urlObj = new URL(url);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Ghost API URL must use HTTP or HTTPS');
    }
    return url;
  } catch (e) {
    throw new Error('Invalid Ghost API URL format');
  }
}

function hexToUint8Array(hex) {
  const normalized = hex.trim();
  if (normalized.length % 2 !== 0) {
    throw new Error('Invalid Admin API secret length. Expected even number of hex characters.');
  }
  if (!/^[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error('Admin API secret must be a hex string.');
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}
