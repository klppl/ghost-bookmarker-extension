/**
 * Popup script for Ghost Bookmarker
 */

document.addEventListener('DOMContentLoaded', async () => {
  const form = document.getElementById('bookmark-form');
  const urlInput = document.getElementById('url-input');
  const noteInput = document.getElementById('note-input');
  const saveButton = document.getElementById('save-button');
  const settingsButton = document.getElementById('settings-button');
  const statusMessage = document.getElementById('status-message');
  
  // Load pending bookmark data (from context menu or command)
  const pendingData = await browser.storage.local.get('pendingBookmark');
  if (pendingData.pendingBookmark) {
    urlInput.value = pendingData.pendingBookmark.url || '';
    noteInput.value = pendingData.pendingBookmark.note || '';
    // Clear pending data
    await browser.storage.local.remove('pendingBookmark');
  } else {
    // Try to get current tab URL
    try {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0 && tabs[0].url) {
        urlInput.value = tabs[0].url;
      }
    } catch (error) {
      console.error('Error getting current tab:', error);
    }
  }
  
  // Handle form submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const url = urlInput.value.trim();
    const note = noteInput.value.trim();
    
    if (!url) {
      showStatus('Please enter a URL', 'error');
      return;
    }
    
    // Validate URL
    try {
      new URL(url);
    } catch (error) {
      showStatus('Please enter a valid URL', 'error');
      return;
    }
    
    // Disable button and show loading state
    saveButton.disabled = true;
    saveButton.textContent = 'Saving...';
    showStatus('Saving bookmark...', 'info');
    
    try {
      // Send message to background script
      const response = await browser.runtime.sendMessage({
        action: 'saveBookmark',
        url: url,
        note: note
      });
      
      if (response.success) {
        showStatus('Bookmark saved successfully!', 'success');
        // Clear form after short delay
        setTimeout(() => {
          urlInput.value = '';
          noteInput.value = '';
          // Try to get current tab URL again
          browser.tabs.query({ active: true, currentWindow: true })
            .then(tabs => {
              if (tabs.length > 0 && tabs[0].url) {
                urlInput.value = tabs[0].url;
              }
            })
            .catch(() => {});
        }, 1500);
      } else {
        showStatus(response.error || 'Failed to save bookmark', 'error');
      }
    } catch (error) {
      console.error('Error saving bookmark:', error);
      showStatus(`Error: ${error.message}`, 'error');
    } finally {
      saveButton.disabled = false;
      saveButton.textContent = 'Save to Ghost';
    }
  });
  
  // Handle settings button
  settingsButton.addEventListener('click', () => {
    browser.runtime.openOptionsPage();
  });
  
  // Show status message
  function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
    
    // Auto-hide success messages after 3 seconds
    if (type === 'success') {
      setTimeout(() => {
        statusMessage.className = 'status-message';
      }, 3000);
    }
  }
});

