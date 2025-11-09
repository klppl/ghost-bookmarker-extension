# Ghost Bookmarker

Bookmark webpages into a Ghost draft with a single click or shortcut.

## What It Does
- Adds a context menu entry and `Ctrl+Shift+P` shortcut to capture the active tab (plus selection as a note).
- Opens a popup to review the URL, add an optional note, and save.
- Stores everything in a "Bookmarked links" draft inside your Ghost Admin.

## How It Works
- Reads your Ghost Admin/API credentials from the options page (Staff token or Admin key).
- Routes bookmark saves through the background script, which signs requests and hits the Ghost Admin API.
- Uses `browser.storage.sync` to persist settings and adds the bookmark to a Lexical document via the Admin API.

