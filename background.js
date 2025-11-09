/**
 * Background script for Ghost Bookmarker
 * Handles context menu and webRequest interception
 */

// Import utils (will be bundled)
// In a real build, utils.js would be bundled into background.js

/**
 * Initialize the extension
 */
async function init() {
  // Create context menu item
  browser.contextMenus.create({
    id: 'add-bookmark-to-ghost',
    title: 'Add bookmark to Ghost',
    contexts: ['link', 'selection', 'page']
  });
  
  // Listen for context menu clicks
  browser.contextMenus.onClicked.addListener(handleContextMenuClick);
  
  // Set up webRequest listener for CORS
  browser.webRequest.onBeforeSendHeaders.addListener(
    handleBeforeSendHeaders,
    {
      urls: [
        'https://*.ghost.io/*',
        'https://*.ghost.org/*',
        'https://*.ghost.is/*',
        'https://*/ghost/*',
        'http://*/ghost/*'
      ]
    },
    ['blocking', 'requestHeaders']
  );
}

/**
 * Handle context menu clicks
 */
async function handleContextMenuClick(info, tab) {
  if (info.menuItemId === 'add-bookmark-to-ghost') {
    let url = '';
    let selectedText = '';
    
    if (info.linkUrl) {
      url = info.linkUrl;
      selectedText = info.selectionText || '';
    } else if (info.pageUrl) {
      url = info.pageUrl;
      selectedText = info.selectionText || '';
    }
    
    await openPopupWithData(url, selectedText);
  }
}

/**
 * Open popup with pre-filled data
 */
async function openPopupWithData(url, note) {
  // Store the data temporarily
  await browser.storage.local.set({
    pendingBookmark: { url, note }
  });
  
  // Open popup (user will need to click the icon)
  // Alternatively, we could use browser.windows.create to open a popup window
  showNotification('Ready', 'Click the extension icon to add bookmark');
}

/**
 * Handle webRequest to set Origin header
 */
async function handleBeforeSendHeaders(details) {
  try {
    const settings = await browser.storage.sync.get(['ghostApiUrl']);
    
    if (!settings.ghostApiUrl) {
      return {}; // No custom origin set
    }
    
    const ghostUrl = new URL(settings.ghostApiUrl);
    const origin = `${ghostUrl.protocol}//${ghostUrl.host}`;
    
    // Set Origin header to Ghost site
    const headers = details.requestHeaders || [];
    
    // Remove existing Origin header
    const filteredHeaders = headers.filter(h => 
      h.name.toLowerCase() !== 'origin'
    );
    
    // Add new Origin header
    filteredHeaders.push({
      name: 'Origin',
      value: origin
    });
    
    return { requestHeaders: filteredHeaders };
  } catch (error) {
    console.error('Error in handleBeforeSendHeaders:', error);
    return {};
  }
}

function buildAdminApiUrl(apiUrl, path = '') {
  const base = apiUrl.endsWith('/') ? apiUrl : `${apiUrl}/`;
  return new URL(path, `${base}ghost/api/admin/`).toString();
}

function buildGhostHeaders(authHeader) {
  return {
    'Authorization': authHeader,
    'Content-Type': 'application/json',
    'Accept-Version': 'v5.0'
  };
}

async function fetchBookmarkMetadata(apiUrl, authHeader, targetUrl) {
  try {
    const requestUrl = new URL(buildAdminApiUrl(apiUrl, 'oembed/'));
    requestUrl.searchParams.set('type', 'bookmark');
    requestUrl.searchParams.set('url', targetUrl);
    
    const response = await fetch(requestUrl.toString(), {
      method: 'GET',
      headers: {
        'Authorization': authHeader,
        'Accept-Version': 'v5.0'
      }
    });
    
    if (!response.ok) {
      return null;
    }
    
    const data = await response.json();
    return data && typeof data === 'object' ? data.metadata || null : null;
  } catch (error) {
    console.warn('Failed to fetch bookmark metadata:', error);
    return null;
  }
}

function safeParseLexical(lexicalJson) {
  if (!lexicalJson) {
    return createLexicalRoot();
  }
  
  try {
    const parsed = typeof lexicalJson === 'string' ? JSON.parse(lexicalJson) : lexicalJson;
    return ensureLexicalDocument(parsed);
  } catch (error) {
    console.warn('Failed to parse lexical content. Starting with a fresh document.', error);
    return createLexicalRoot();
  }
}

function appendBookmarkToLexical(doc, url, note, metadata) {
  const lexicalDoc = ensureLexicalDocument(doc);
  const children = lexicalDoc.root.children;
  
  if (children.length === 1 && isEmptyParagraphNode(children[0])) {
    children.pop();
  }
  
  if (children.length > 0) {
    children.push(createEmptyParagraphNode());
  }
  
  if (metadata) {
    const cardMetadata = {
      url,
      ...metadata
    };
    children.push(createBookmarkCardNode(cardMetadata));
  } else {
    children.push(createLinkParagraphNode(url));
  }
  
  if (note) {
    children.push(createNoteParagraphNode(note));
  }
  
  return lexicalDoc;
}

function ensureLexicalDocument(doc) {
  if (!doc || typeof doc !== 'object') {
    return createLexicalRoot();
  }
  
  if (!doc.root || typeof doc.root !== 'object') {
    doc.root = createLexicalRoot().root;
  }
  
  if (!Array.isArray(doc.root.children)) {
    doc.root.children = [];
  }
  
  return doc;
}

function createLexicalRoot() {
  return {
    root: {
      children: [
        createEmptyParagraphNode()
      ],
      direction: null,
      format: '',
      indent: 0,
      type: 'root',
      version: 1
    }
  };
}

function createEmptyParagraphNode() {
  return createParagraphNode([]);
}

function isEmptyParagraphNode(node) {
  return node &&
    node.type === 'paragraph' &&
    Array.isArray(node.children) &&
    node.children.length === 0;
}

function createParagraphNode(children) {
  return {
    children,
    direction: 'ltr',
    format: '',
    indent: 0,
    type: 'paragraph',
    version: 1
  };
}

function createLinkParagraphNode(url) {
  const linkNode = {
    children: [createTextNode(url)],
    direction: 'ltr',
    format: '',
    indent: 0,
    type: 'link',
    version: 1,
    rel: null,
    target: null,
    title: null,
    url
  };
  
  return createParagraphNode([linkNode]);
}

function createBookmarkCardNode(metadata = {}) {
  const {
    url = '',
    icon = '',
    title = '',
    description = '',
    author = '',
    publisher = '',
    thumbnail = '',
    caption = ''
  } = metadata;
  
  return {
    type: 'bookmark',
    version: 1,
    url,
    metadata: {
      icon,
      title,
      description,
      author,
      publisher,
      thumbnail
    },
    caption
  };
}

function createNoteParagraphNode(note) {
  return createParagraphNode([createTextNode(note)]);
}

function createTextNode(text) {
  return {
    detail: 0,
    format: 0,
    mode: 'normal',
    style: '',
    text,
    type: 'text',
    version: 1
  };
}

function buildNewPostPayload(lexicalDoc) {
  return {
    title: 'Bookmarked links',
    lexical: JSON.stringify(lexicalDoc),
    status: 'draft',
    tags: [{ name: 'Bookmarked links', slug: 'bookmarked-links' }]
  };
}

function buildUpdatedPostPayload(post, lexicalDoc) {
  const payload = {
    id: post.id,
    updated_at: post.updated_at,
    title: post.title || 'Bookmarked links',
    status: post.status || 'draft'
  };
  
  if (lexicalDoc) {
    payload.lexical = JSON.stringify(lexicalDoc);
  }
  
  if (typeof post.featured === 'boolean') {
    payload.featured = post.featured;
  }
  
  if (post.visibility) {
    payload.visibility = post.visibility;
  }
  
  if (post.feature_image) {
    payload.feature_image = post.feature_image;
  }
  
  const existingTags = Array.isArray(post.tags)
    ? post.tags.map(normalizeTag).filter(Boolean)
    : [];
  payload.tags = existingTags.length > 0 ? existingTags : [{ name: 'Bookmarked links', slug: 'bookmarked-links' }];
  
  const authors = Array.isArray(post.authors)
    ? post.authors.map(normalizeAuthor).filter(Boolean)
    : [];
  if (authors.length > 0) {
    payload.authors = authors;
  }
  
  const primaryAuthor = normalizeAuthor(post.primary_author);
  if (primaryAuthor) {
    payload.primary_author = primaryAuthor;
  }
  
  const primaryTag = normalizeTag(post.primary_tag);
  if (primaryTag) {
    payload.primary_tag = primaryTag;
  }
  
  return payload;
}

function normalizeTag(tag) {
  if (!tag || typeof tag !== 'object') {
    return null;
  }
  
  const normalized = {};
  if (tag.id) {
    normalized.id = tag.id;
  }
  if (tag.slug) {
    normalized.slug = tag.slug;
  }
  if (tag.name) {
    normalized.name = tag.name;
  }
  
  return Object.keys(normalized).length > 0 ? normalized : null;
}

function normalizeAuthor(author) {
  if (!author || typeof author !== 'object') {
    return null;
  }
  
  const normalized = {};
  if (author.id) {
    normalized.id = author.id;
  }
  if (author.slug) {
    normalized.slug = author.slug;
  }
  
  return Object.keys(normalized).length > 0 ? normalized : null;
}

/**
 * Get authorization header for Ghost API
 * Supports both Staff tokens (Ghost prefix) and Admin API keys (JWT)
 */
async function getGhostAuthHeader(apiUrl, apiKey) {
  // Check if it's an Admin API key (format: keyId:secret) or Staff token
  if (apiKey.includes(':')) {
    // Admin API Key - use JWT
    const { keyId, secret } = parseAdminAPIKey(apiKey);
    const audience = buildAdminApiUrl(apiUrl);
    const token = await createJWTAsync(keyId, secret, audience);
    return `Ghost ${token}`;
  } else {
    // Staff Token (Personal Access Token) - use Ghost prefix as required by API
    return `Ghost ${apiKey}`;
  }
}

/**
 * Create or update Ghost post with bookmarked links
 */
async function createOrUpdateGhostPost(url, note) {
  try {
    const settings = await browser.storage.sync.get(['ghostApiUrl', 'ghostApiKey']);
    
    if (!settings.ghostApiUrl || !settings.ghostApiKey) {
      throw new Error('Ghost API settings not configured. Please set them in options.');
    }
    
    const apiUrl = sanitizeGhostURL(settings.ghostApiUrl);
    const authHeader = await getGhostAuthHeader(apiUrl, settings.ghostApiKey);
    const headers = buildGhostHeaders(authHeader);
    
    // First, try to find existing "Bookmarked links" post
    const postsUrl = new URL(buildAdminApiUrl(apiUrl, 'posts/'));
    postsUrl.searchParams.set('filter', `title:'Bookmarked links'+status:draft`);
    postsUrl.searchParams.set('limit', '1');
    postsUrl.searchParams.set('formats', 'lexical,html');
    postsUrl.searchParams.set('include', 'tags,authors');
    
    const getResponse = await fetch(postsUrl.toString(), {
      method: 'GET',
      headers
    });
    
    if (!getResponse.ok) {
      let errorDetail = '';
      try {
        errorDetail = await getResponse.text();
      } catch (readError) {
        console.error('Failed to read error response:', readError);
      }
      const statusPart = `${getResponse.status}${getResponse.statusText ? ' ' + getResponse.statusText : ''}`;
      const message = `Failed to fetch posts: ${statusPart}${errorDetail ? ' - ' + errorDetail : ''}`;
      throw new Error(message);
    }
    
    const postsData = await getResponse.json();
    let post = null;
    
    if (postsData.posts && postsData.posts.length > 0) {
      post = postsData.posts[0];
    }
    
    const safeNote = (note || '').trim();
    const bookmarkMetadata = await fetchBookmarkMetadata(apiUrl, authHeader, url);
    
    if (post && !post.lexical) {
      throw new Error('Existing "Bookmarked links" draft needs to be opened once in Ghost to migrate to the Lexical editor.');
    }
    
    const lexicalDoc = post
      ? appendBookmarkToLexical(safeParseLexical(post.lexical), url, safeNote, bookmarkMetadata)
      : appendBookmarkToLexical(null, url, safeNote, bookmarkMetadata);
    
    const postPayload = post
      ? buildUpdatedPostPayload(post, lexicalDoc)
      : buildNewPostPayload(lexicalDoc);
    
    const requestUrl = post ? buildAdminApiUrl(apiUrl, `posts/${post.id}/`) : buildAdminApiUrl(apiUrl, 'posts/');
    const method = post ? 'PUT' : 'POST';
    const postData = { posts: [postPayload] };
    
    const response = await fetch(requestUrl, {
      method,
      headers,
      body: JSON.stringify(postData)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to save bookmark: ${response.statusText} - ${errorText}`);
    }
    
    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Error creating/updating Ghost post:', error);
    throw error;
  }
}

/**
 * Show browser notification
 */
function showNotification(title, message) {
  browser.notifications.create({
    type: 'basic',
    iconUrl: browser.runtime.getURL('icons/icon-48.png'),
    title: title,
    message: message
  });
}

// Import utility functions (inline since we can't use ES modules in background)
// These will be included from utils.js at build time
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

/**
 * Test connection to Ghost API
 */
async function testGhostConnection(apiUrl, apiKey) {
  try {
    const sanitizedUrl = sanitizeGhostURL(apiUrl);
    const authHeader = await getGhostAuthHeader(sanitizedUrl, apiKey);
    const headers = buildGhostHeaders(authHeader);
    
    // Test API connection
    const testUrl = new URL(buildAdminApiUrl(sanitizedUrl, 'posts/'));
    testUrl.searchParams.set('limit', '1');
    const response = await fetch(testUrl.toString(), {
      method: 'GET',
      headers
    });
    
    if (response.ok) {
      return { success: true, message: 'Connection successful! Your Ghost API credentials are valid.' };
    } else {
      const errorText = await response.text();
      return { success: false, error: `Connection failed: ${response.statusText} - ${errorText}` };
    }
  } catch (error) {
    console.error('Error testing connection:', error);
    return { success: false, error: error.message };
  }
}

// Listen for messages from popup and options page
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'saveBookmark') {
    createOrUpdateGhostPost(message.url, message.note)
      .then(result => {
        sendResponse({ success: true, result });
        showNotification('Success', 'Bookmark saved to Ghost!');
      })
      .catch(error => {
        console.error('Error saving bookmark:', error);
        sendResponse({ success: false, error: error.message });
        showNotification('Error', `Failed to save bookmark: ${error.message}`);
      });
    return true; // Indicates we will send a response asynchronously
  } else if (message.action === 'testConnection') {
    testGhostConnection(message.apiUrl, message.apiKey)
      .then(result => {
        sendResponse(result);
      })
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });
    return true; // Indicates we will send a response asynchronously
  }
});

// Initialize on startup
init().catch(error => {
  console.error('Error initializing extension:', error);
});
