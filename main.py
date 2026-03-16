#!/usr/bin/env python3
"""
OSINT Monitor - Autonomous Geopolitical Intelligence Collection
Collects from RSS feeds, synthesizes with Gemini Flash, delivers briefings.
"""

import feedparser
import requests
import json
import yaml
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from bs4 import BeautifulSoup

# Config paths
BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config" / "sources.yaml"
DATA_DIR = BASE_DIR / "data"
ARCHIVE_PATH = DATA_DIR / "archive.json"
BRIEFING_PATH = DATA_DIR / "briefing.md"

def load_config():
    """Load sources configuration."""
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)

def fetch_rss_feed(url, name, max_items=20):
    """Fetch and parse an RSS feed."""
    items = []
    try:
        feed = feedparser.parse(url)
        for entry in feed.entries[:max_items]:
            # Parse publication date
            pub_date = None
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                pub_date = datetime(*entry.published_parsed[:6])
            elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                pub_date = datetime(*entry.updated_parsed[:6])
            
            # Clean description
            description = ""
            if hasattr(entry, 'description'):
                description = entry.description
                # Strip HTML
                description = re.sub(r'<[^>]+>', '', description)
                description = description[:500]  # Truncate
            
            items.append({
                "title": entry.get("title", "No title"),
                "link": entry.get("link", ""),
                "description": description,
                "published": pub_date.isoformat() if pub_date else None,
                "source": name,
                "fetched_at": datetime.utcnow().isoformat()
            })
        print(f"  ✓ {name}: {len(items)} items")
    except Exception as e:
        print(f"  ✗ {name}: {e}")
    return items

def fetch_nitter_feed(username, instance="https://nitter.net"):
    """Fetch Twitter via Nitter RSS."""
    url = f"{instance}/{username}/rss"
    return fetch_rss_feed(url, f"@{username}", max_items=10)

def collect_all_sources(config, hours_back=24):
    """Collect from all configured sources."""
    all_items = []
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)
    
    print("\n📡 Collecting RSS feeds...")
    
    # RSS feeds
    for feed in config.get("rss_feeds", []):
        items = fetch_rss_feed(feed["url"], feed["name"])
        all_items.extend(items)
    
    # Twitter via Nitter
    print("\n🐦 Collecting Twitter/X feeds...")
    nitter_instances = config.get("nitter_instances", ["https://nitter.net"])
    
    for account in config.get("twitter_accounts", []):
        # Try each Nitter instance until one works
        for instance in nitter_instances:
            items = fetch_nitter_feed(account["username"], instance)
            if items:
                all_items.extend(items)
                break
    
    # Filter by recency
    recent_items = []
    for item in all_items:
        if item.get("published"):
            try:
                pub_date = datetime.fromisoformat(item["published"].replace("Z", "+00:00"))
                if pub_date.replace(tzinfo=None) > cutoff:
                    recent_items.append(item)
            except:
                recent_items.append(item)  # Keep if we can't parse date
        else:
            recent_items.append(item)
    
    print(f"\n📊 Total recent items: {len(recent_items)}")
    return recent_items

def check_alerts(items, config):
    """Check for critical keywords requiring immediate alerts."""
    alerts = []
    alert_keywords = config.get("alert_keywords", {})
    
    critical_keywords = [kw.lower() for kw in alert_keywords.get("critical", [])]
    high_keywords = [kw.lower() for kw in alert_keywords.get("high", [])]
    
    for item in items:
        text = f"{item.get('title', '')} {item.get('description', '')}".lower()
        
        # Check critical
        for kw in critical_keywords:
            if kw in text:
                alerts.append({
                    "level": "CRITICAL",
                    "keyword": kw,
                    "item": item
                })
                break
        
        # Check high (if not already critical)
        if not any(a["item"] == item for a in alerts):
            for kw in high_keywords:
                if kw in text:
                    alerts.append({
                        "level": "HIGH",
                        "keyword": kw,
                        "item": item
                    })
                    break
    
    return alerts

def categorize_by_region(items, config):
    """Categorize items by region."""
    regions = config.get("regions", {})
    categorized = {region: [] for region in regions}
    categorized["other"] = []
    
    for item in items:
        text = f"{item.get('title', '')} {item.get('description', '')}"
        matched = False
        
        for region, data in regions.items():
            for keyword in data.get("keywords", []):
                if keyword.lower() in text.lower():
                    categorized[region].append(item)
                    matched = True
                    break
            if matched:
                break
        
        if not matched:
            categorized["other"].append(item)
    
    return categorized

def save_archive(items, alerts):
    """Save items to archive."""
    DATA_DIR.mkdir(exist_ok=True)
    
    archive = {
        "last_updated": datetime.utcnow().isoformat(),
        "items_count": len(items),
        "alerts_count": len(alerts),
        "items": items,
        "alerts": alerts
    }
    
    with open(ARCHIVE_PATH, "w") as f:
        json.dump(archive, f, indent=2, default=str)
    
    print(f"📁 Archived to {ARCHIVE_PATH}")

def generate_briefing_text(items, alerts, categorized, config):
    """Generate raw briefing text (to be synthesized by Gemini)."""
    lines = []
    lines.append(f"# OSINT Briefing — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
    lines.append("")
    
    # Alerts
    if alerts:
        lines.append("## 🚨 ALERTS")
        for alert in alerts:
            lines.append(f"\n**{alert['level']}** — Keyword: *{alert['keyword']}*")
            lines.append(f"- [{alert['item']['title']}]({alert['item']['link']})")
            lines.append(f"  Source: {alert['item']['source']}")
        lines.append("")
    
    # By region
    lines.append("## 🌍 By Region")
    for region, region_items in categorized.items():
        if region_items and region != "other":
            priority = config["regions"].get(region, {}).get("priority", 2)
            lines.append(f"\n### {region.upper()} (Priority {priority})")
            for item in region_items[:5]:  # Top 5 per region
                lines.append(f"- [{item['title']}]({item['link']})")
                lines.append(f"  *{item['source']}*")
    
    # Other
    if categorized.get("other"):
        lines.append(f"\n### OTHER ({len(categorized['other'])} items)")
        for item in categorized["other"][:10]:
            lines.append(f"- [{item['title']}]({item['link']}) — *{item['source']}*")
    
    return "\n".join(lines)

def main():
    """Main collection and processing."""
    print("=" * 50)
    print("OSINT MONITOR - Starting collection")
    print("=" * 50)
    
    # Load config
    config = load_config()
    
    # Collect
    items = collect_all_sources(config, hours_back=24)
    
    if not items:
        print("⚠️ No items collected. Check feeds.")
        return
    
    # Check alerts
    alerts = check_alerts(items, config)
    if alerts:
        print(f"\n🚨 {len(alerts)} ALERT(S) DETECTED!")
        for alert in alerts:
            print(f"  [{alert['level']}] {alert['keyword']}: {alert['item']['title'][:60]}...")
    
    # Categorize
    categorized = categorize_by_region(items, config)
    
    # Save archive
    save_archive(items, alerts)
    
    # Generate briefing
    briefing = generate_briefing_text(items, alerts, categorized, config)
    
    with open(BRIEFING_PATH, "w") as f:
        f.write(briefing)
    
    print(f"\n✅ Briefing saved to {BRIEFING_PATH}")
    print(f"   Items: {len(items)} | Alerts: {len(alerts)}")
    
    return briefing

if __name__ == "__main__":
    main()
