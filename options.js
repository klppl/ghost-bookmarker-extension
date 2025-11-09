/**
 * Options page script for Ghost Bookmarker
 */

document.addEventListener('DOMContentLoaded', async () => {
  const form = document.getElementById('settings-form');
  const apiUrlInput = document.getElementById('ghost-api-url');
  const apiKeyInput = document.getElementById('ghost-api-key');
  const saveButton = document.getElementById('save-button');
  const testButton = document.getElementById('test-button');
  const statusMessage = document.getElementById('status-message');
  
  // Load existing settings
  const settings = await browser.storage.sync.get(['ghostApiUrl', 'ghostApiKey']);
  if (settings.ghostApiUrl) {
    apiUrlInput.value = settings.ghostApiUrl;
  }
  if (settings.ghostApiKey) {
    apiKeyInput.value = settings.ghostApiKey;
  }
  
  // Handle form submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await saveSettings();
  });
  
  // Handle test button
  testButton.addEventListener('click', async () => {
    await testConnection();
  });
  
  /**
   * Save settings
   */
  async function saveSettings() {
    const apiUrl = apiUrlInput.value.trim();
    const apiKey = apiKeyInput.value.trim();
    
    // Validate inputs
    if (!apiUrl || !apiKey) {
      showStatus('Please fill in all fields', 'error');
      return;
    }
    
    // Validate URL
    let sanitizedUrl;
    try {
      sanitizedUrl = sanitizeGhostURL(apiUrl);
    } catch (error) {
      showStatus(error.message, 'error');
      return;
    }
    
    // Validate API key format (can be either Admin API key or Staff token)
    if (!apiKey || apiKey.trim().length === 0) {
      showStatus('API key or token is required', 'error');
      return;
    }
    
    // Admin API keys have format keyId:secret, Staff tokens are just strings
    // Both are valid, so we don't need strict validation here
    
    // Save to storage
    try {
      await browser.storage.sync.set({
        ghostApiUrl: sanitizedUrl,
        ghostApiKey: apiKey
      });
      
      showStatus('Settings saved successfully!', 'success');
    } catch (error) {
      console.error('Error saving settings:', error);
      showStatus('Failed to save settings: ' + error.message, 'error');
    }
  }
  
  /**
   * Test connection to Ghost API
   */
  async function testConnection() {
    const apiUrl = apiUrlInput.value.trim();
    const apiKey = apiKeyInput.value.trim();
    
    if (!apiUrl || !apiKey) {
      showStatus('Please fill in all fields before testing', 'error');
      return;
    }
    
    testButton.disabled = true;
    testButton.textContent = 'Testing...';
    showStatus('Testing connection...', 'info');
    
    try {
      // Validate URL format first
      sanitizeGhostURL(apiUrl);
      
      // API key can be either Admin API key (keyId:secret) or Staff token (plain string)
      if (!apiKey || apiKey.trim().length === 0) {
        showStatus('API key or token is required', 'error');
        return;
      }
      
      // Send test request through background script (has proper permissions)
      const response = await browser.runtime.sendMessage({
        action: 'testConnection',
        apiUrl: apiUrl,
        apiKey: apiKey
      });
      
      if (response.success) {
        showStatus(response.message, 'success');
      } else {
        showStatus(response.error || 'Connection test failed', 'error');
      }
    } catch (error) {
      console.error('Error testing connection:', error);
      showStatus(`Test failed: ${error.message}`, 'error');
    } finally {
      testButton.disabled = false;
      testButton.textContent = 'Test Connection';
    }
  }
  
  /**
   * Show status message
   */
  function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
    
    // Scroll to status message
    statusMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});

// Utility functions (same as in background.js)
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

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
  
  const keyData = hexToUint8Array(secret);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signatureArrayBuffer = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    new TextEncoder().encode(signatureInput)
  );
  
  const signatureBytes = new Uint8Array(signatureArrayBuffer);
  const signatureB64 = btoa(String.fromCharCode(...signatureBytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${encodedHeader}.${encodedPayload}.${signatureB64}`;
}

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

// Note: This function is only used for Admin API keys (keyId:secret format)
// Staff tokens don't need parsing - they're used directly

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

function sanitizeGhostURL(url) {
  if (!url) {
    throw new Error('Ghost API URL is required');
  }
  
  url = url.trim().replace(/\/+$/, '');
  
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
