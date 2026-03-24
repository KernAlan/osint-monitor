---
name: x-collect
description: Collect tweets from X/Twitter For You feed via browser and ingest into the OSINT pipeline. Use when the user wants to pull their X feed, collect from Twitter, or run the browser collector.
allowed-tools: Bash, Read, Write, Grep, Glob, Agent
argument-hint: "[scrolls] — number of scroll rounds, default 15"
---

# X For You Browser Collector

Collect tweets from the user's X/Twitter "For You" feed using claude-in-chrome browser automation, then ingest into the OSINT Monitor pipeline via `/api/ingest`.

## Prerequisites

Before running, ensure:
- The OSINT Monitor dashboard is running (`python main.py serve`) on port 8000
- The `/api/ingest` endpoint is available
- Chrome is open with claude-in-chrome extension active

## Procedure

### 1. Get browser context and navigate to X

Load the chrome tools first:
- `mcp__claude-in-chrome__tabs_context_mcp`
- `mcp__claude-in-chrome__tabs_create_mcp`
- `mcp__claude-in-chrome__navigate`
- `mcp__claude-in-chrome__javascript_tool`
- `mcp__claude-in-chrome__computer`

Create a new tab (or reuse an existing x.com tab) and navigate to `https://x.com/home`.

### 2. Set up the DOM harvester

Wait 3 seconds for page load, then inject this harvester via `javascript_tool`:

```javascript
window.__xItems = [];
window.__xSeen = new Set();

window.__xHarvest = function() {
    for (const tweet of document.querySelectorAll('article[data-testid="tweet"]')) {
        const textEl = tweet.querySelector('[data-testid="tweetText"]');
        const text = textEl ? textEl.textContent.trim() : '';
        if (!text || window.__xSeen.has(text)) continue;

        let isAd = false;
        for (const s of tweet.querySelectorAll('span')) {
            const t = s.textContent.trim();
            if (t === 'Ad' || t === 'Promoted') { isAd = true; break; }
        }
        if (isAd) continue;

        window.__xSeen.add(text);
        const userEl = tweet.querySelector('[data-testid="User-Name"]');
        const timeEl = tweet.querySelector('time');
        let tweetUrl = '', tweetId = '';
        for (const a of tweet.querySelectorAll('a[href*="/status/"]')) {
            const m = a.href.match(/\/status\/(\d+)$/);
            if (m) { tweetUrl = a.href; tweetId = m[1]; break; }
        }
        let username = '', displayName = '';
        if (userEl) {
            for (const s of userEl.querySelectorAll('span')) {
                if (s.textContent.startsWith('@')) { username = s.textContent; break; }
            }
            const first = userEl.querySelector('span');
            displayName = first ? first.textContent : '';
        }
        window.__xItems.push({
            title: `${displayName} (${username}): ${text.substring(0, 150)}`,
            content: text,
            url: tweetUrl,
            published_at: timeEl ? timeEl.getAttribute('datetime') : null,
            source_name: 'X-ForYou',
            external_id: tweetId || ('xfy-' + btoa(unescape(encodeURIComponent(text.substring(0, 80)))).substring(0, 40)),
        });
    }
    return window.__xItems.length;
};

// Poll every 300ms to catch tweets as they appear
window.__xPoll = setInterval(window.__xHarvest, 300);
window.__xHarvest(); // initial sweep
```

### 3. Scroll with mouse wheel

**CRITICAL: You must use the `computer` tool with `scroll` action, NOT `window.scrollBy()`.** X's infinite scroll loader only responds to real mouse wheel events.

Perform scroll rounds (default 15, configurable via `$ARGUMENTS`):
- Each round: `computer` tool, action `scroll`, direction `down`, amount `10`, coordinate `[600, 400]`
- No need to wait between scrolls — the 300ms poll harvester catches everything

### 4. Stop harvester and check count

```javascript
clearInterval(window.__xPoll);
window.__xHarvest(); // final sweep
window.__xItems.length
```

Report the count to the user.

### 5. Relay data to the ingest API

X's Content Security Policy blocks outgoing fetch requests to other origins. Data must be relayed through a localhost tab.

1. Navigate to or find an existing `localhost:8000` tab
2. Read items from X tab in batches of 6 using `javascript_tool` (MCP output truncates at ~2KB):
   ```javascript
   window.__xItems.slice(START, END).map(i =>
     [i.external_id, i.published_at||'', i.url||'', i.title.substring(0,80), i.content.substring(0,120)].join('\t')
   ).join('\n')
   ```
3. Reconstruct items as JSON and inject into localhost tab via `javascript_tool`
4. POST to `/api/ingest` from the localhost tab:
   ```javascript
   fetch('/api/ingest', {
       method: 'POST',
       headers: {'Content-Type': 'application/json'},
       body: JSON.stringify(items)
   }).then(r => r.json())
   ```

### 6. Report results

Show the user: items collected, items ingested (new vs dupes), entities extracted.

## Key learnings

- `window.scrollBy()` does NOT trigger X's infinite scroll — must use mouse wheel via `computer` tool
- X virtualizes the DOM — only ~5 articles exist at once, old ones get removed as you scroll
- The 300ms polling harvester captures tweets before they get recycled
- X CSP blocks all outgoing fetches from x.com — relay through localhost tab
- MCP tool output truncates at ~2KB — read data in small batches
- The `placementTracking` div exists on ALL tweets, not just ads — detect ads by looking for "Ad" or "Promoted" span text
