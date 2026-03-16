#!/usr/bin/env python3
"""
OSINT Synthesizer - Uses Gemini Flash to create actionable briefings.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
BRIEFING_PATH = BASE_DIR / "data" / "briefing.md"
SYNTHESIS_PATH = BASE_DIR / "data" / "synthesis.md"
ARCHIVE_PATH = BASE_DIR / "data" / "archive.json"

GEMINI_MODEL = "gemini-3-flash-preview"

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

def run_gemini(prompt):
    """Run Gemini CLI with prompt."""
    try:
        result = subprocess.run(
            ["gemini", "-m", GEMINI_MODEL, prompt],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"Gemini error: {result.stderr}")
            return None
    except Exception as e:
        print(f"Gemini not available: {e}")
        return None

def simple_synthesis(items, alerts, categorized):
    """Generate a simple synthesis without AI."""
    lines = []
    lines.append(f"# Geopolitical Intelligence Briefing")
    lines.append(f"**{datetime.utcnow().strftime('%A, %B %d, %Y')} — {datetime.utcnow().strftime('%H:%M')} UTC**")
    lines.append("")
    
    # Alerts
    if alerts:
        lines.append("## 🚨 ALERTS")
        lines.append("")
        for alert in alerts:
            level_emoji = "🔴" if alert["level"] == "CRITICAL" else "🟠"
            lines.append(f"{level_emoji} **{alert['level']}** — _{alert['keyword']}_")
            lines.append(f"  [{alert['item']['title']}]({alert['item']['link']})")
            lines.append(f"  Source: {alert['item']['source']}")
            lines.append("")
    
    # Executive summary
    lines.append("## ⚡ EXECUTIVE SUMMARY")
    lines.append("")
    if alerts:
        lines.append(f"**{len(alerts)} alert(s)** detected in last 24h monitoring. Key focus areas:")
    
    # Top items by priority region
    priority_regions = ["iran", "china", "russia", "middle_east"]
    lines.append("")
    for region in priority_regions:
        region_items = categorized.get(region, [])
        if region_items:
            lines.append(f"- **{region.upper()}**: {len(region_items)} items")
    
    lines.append("")
    
    # Key developments
    lines.append("## 🎯 KEY DEVELOPMENTS")
    lines.append("")
    
    # Take top 5 from each priority region
    for region in priority_regions:
        region_items = categorized.get(region, [])
        if region_items:
            lines.append(f"### {region.upper()}")
            for item in region_items[:3]:
                lines.append(f"- [{item['title']}]({item['link']})")
                lines.append(f"  _{item['source']}_")
            lines.append("")
    
    # Stats
    total_items = sum(len(v) for v in categorized.values())
    lines.append("---")
    lines.append(f"📊 **Stats**: {total_items} items from 20+ sources | {len(alerts)} alerts")
    
    return "\n".join(lines)

def synthesize_briefing():
    """Create synthesized intelligence briefing."""
    
    # Load archive
    if not ARCHIVE_PATH.exists():
        print("No archive found. Run main.py first.")
        return None
    
    with open(ARCHIVE_PATH) as f:
        archive = json.load(f)
    
    items = archive.get("items", [])
    alerts = archive.get("alerts", [])
    
    # Load config for categorization
    import yaml
    with open(BASE_DIR / "config" / "sources.yaml") as f:
        config = yaml.safe_load(f)
    
    # Categorize by region
    categorized = categorize_by_region(items, config)
    
    # Try Gemini first, fall back to simple synthesis
    print("🤖 Attempting AI synthesis...")
    
    raw_briefing = None
    if BRIEFING_PATH.exists():
        with open(BRIEFING_PATH) as f:
            raw_briefing = f.read()
    
    if raw_briefing:
        synthesis = run_gemini(f"""Synthesize this OSINT data into a concise briefing with executive summary, key developments, and watch list. Be specific and actionable:\n\n{raw_briefing[:8000]}""")
        
        if synthesis:
            full_synthesis = f"# Geopolitical Intelligence Briefing\n**{datetime.utcnow().strftime('%A, %B %d, %Y')} — {datetime.utcnow().strftime('%H:%M')} UTC**\n\n{synthesis}"
            with open(SYNTHESIS_PATH, "w") as f:
                f.write(full_synthesis)
            print(f"✅ AI synthesis saved to {SYNTHESIS_PATH}")
            return full_synthesis
    
    # Fall back to simple synthesis
    print("📝 Using structured synthesis...")
    synthesis = simple_synthesis(items, alerts, categorized)
    
    with open(SYNTHESIS_PATH, "w") as f:
        f.write(synthesis)
    
    print(f"✅ Synthesis saved to {SYNTHESIS_PATH}")
    return synthesis

def quick_alert_check():
    """Quick check for critical alerts only."""
    
    if not ARCHIVE_PATH.exists():
        return None
    
    with open(ARCHIVE_PATH) as f:
        archive = json.load(f)
    
    alerts = archive.get("alerts", [])
    
    if not alerts:
        return None
    
    # Format alerts
    lines = ["🚨 **OSINT ALERTS**\n"]
    for alert in alerts:
        level = alert["level"]
        keyword = alert["keyword"]
        item = alert["item"]
        
        lines.append(f"**{level}** — *{keyword}*")
        lines.append(f"[{item['title']}]({item['link']})")
        lines.append(f"Source: {item['source']}\n")
    
    return "\n".join(lines)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--alerts":
        # Just check for alerts
        alerts = quick_alert_check()
        if alerts:
            print(alerts)
        else:
            print("No critical alerts.")
    else:
        # Full synthesis
        synthesis = synthesize_briefing()
        if synthesis:
            print("\n" + "="*50)
            print(synthesis)
