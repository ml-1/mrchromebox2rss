#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from datetime import datetime
from email.utils import format_datetime
import hashlib
import json
import os
import re
import sys

URL = "https://docs.mrchromebox.tech/docs/news.html"
OUTPUT_FILE = "mrchromebox-news.xml"
STATE_FILE = ".mrchromebox_rss_state.json"


def fetch_page():
    r = requests.get(URL, timeout=20)
    r.raise_for_status()
    return r.text


def parse_date_from_first_paragraph(header):
    """
    Looks for date in first paragraph after header:
    <p>(2026.01.25)</p>
    """
    first_p = header.find_next_sibling("p")
    if not first_p:
        return None, None

    text = first_p.get_text(strip=True)
    match = re.match(r"\((\d{4})\.(\d{2})\.(\d{2})\)", text)

    if not match:
        return None, None

    year, month, day = match.groups()
    dt = datetime(int(year), int(month), int(day))
    return dt, first_p


def parse_items(html):
    soup = BeautifulSoup(html, "html.parser")
    items = []

    for header in soup.find_all(["h2"]):
        title = header.get_text(strip=True)
        if not title:
            continue

        pub_date, date_element = parse_date_from_first_paragraph(header)

        anchor = header.get("id")
        link = f"{URL}#{anchor}" if anchor else URL

        description_parts = []

        for sibling in header.find_next_siblings():
            if sibling.name in ["h2"]:
                break

            # Skip date paragraph
            if date_element and sibling == date_element:
                continue

            description_parts.append(str(sibling))

        description_html = "\n".join(description_parts).strip()

        # GUID based on title + raw description (stable even if no date)
        guid_source = title + description_html
        guid = hashlib.sha256(guid_source.encode()).hexdigest()

        items.append({
            "title": title,
            "link": link,
            "description": description_html,
            "pubDate": format_datetime(pub_date) if pub_date else None,
            "guid": guid
        })

    return items


def build_rss(items):
    rss_items = []

    for item in items:
        pubdate_xml = f"<pubDate>{item['pubDate']}</pubDate>" if item["pubDate"] else ""

        rss_items.append(f"""
    <item>
      <title>{item['title']}</title>
      <link>{item['link']}</link>
      <guid isPermaLink="false">{item['guid']}</guid>
      {pubdate_xml}
      <description><![CDATA[{item['description']}]]></description>
    </item>
        """)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>MrChromebox.tech – Latest Updates</title>
    <link>{URL}</link>
    <description>Latest news & release updates from MrChromebox.tech</description>
    <language>en-us</language>
    {''.join(rss_items)}
  </channel>
</rss>
"""

def content_hash(items):
    m = hashlib.sha256()
    for item in items:
        m.update(item["guid"].encode())
    return m.hexdigest()


def load_previous_hash():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, "r") as f:
        return json.load(f).get("hash")


def save_state(hash_value):
    with open(STATE_FILE, "w") as f:
        json.dump({"hash": hash_value}, f)


def main():
    print("Fetching page...")
    html = fetch_page()

    print("Parsing items...")
    items = parse_items(html)

    new_hash = content_hash(items)
    old_hash = load_previous_hash()

    if new_hash == old_hash:
        print("No changes detected. RSS not updated.")
        return

    print("Changes detected. Writing RSS...")
    rss = build_rss(items)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(rss)

    save_state(new_hash)

    print(f"RSS updated: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
