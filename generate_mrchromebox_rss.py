#!/usr/bin/env python3

import urllib.request
from html.parser import HTMLParser
from datetime import datetime
from email.utils import format_datetime
import hashlib
import json
import os
import re

URL = "https://docs.mrchromebox.tech/docs/news.html"
OUTPUT_FILE = "mrchromebox-news.xml"
STATE_FILE = ".mrchromebox_rss_state.json"


class NewsParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_h2 = False
        self.current_title = None
        self.current_content = []
        self.items = []
        self.capture_data = False
        self.current_tag = None

    def handle_starttag(self, tag, attrs):
        if tag == "h2":
            if self.current_title:
                self._finish_item()
            self.in_h2 = True
            self.current_title = ""
            self.current_content = []
        elif self.current_title:
            self.current_tag = tag
            self.current_content.append(self.get_starttag_text())

    def handle_endtag(self, tag):
        if tag == "h2":
            self.in_h2 = False
        elif self.current_title:
            self.current_content.append(f"</{tag}>")

    def handle_data(self, data):
        if self.in_h2:
            self.current_title += data.strip()
        elif self.current_title:
            self.current_content.append(data)

    def _finish_item(self):
        content_html = "".join(self.current_content).strip()

        # Detect date paragraph: <p>(YYYY.MM.DD)</p>
        date_match = re.search(r"<p>\((\d{4})\.(\d{2})\.(\d{2})\)</p>", content_html)

        pub_date = None
        if date_match:
            year, month, day = date_match.groups()
            pub_date = datetime(int(year), int(month), int(day))
            # Remove date paragraph from content
            content_html = re.sub(
                r"<p>\(\d{4}\.\d{2}\.\d{2}\)</p>", "", content_html, count=1
            )

        guid_source = self.current_title + content_html
        guid = hashlib.sha256(guid_source.encode()).hexdigest()

        self.items.append({
            "title": self.current_title.strip(),
            "description": content_html.strip(),
            "pubDate": format_datetime(pub_date) if pub_date else None,
            "guid": guid
        })

    def close(self):
        super().close()
        if self.current_title:
            self._finish_item()


def fetch_page():
    with urllib.request.urlopen(URL) as response:
        return response.read().decode("utf-8")


def build_rss(items):
    rss_items = []

    for item in items:
        pubdate_xml = f"<pubDate>{item['pubDate']}</pubDate>" if item["pubDate"] else ""

        rss_items.append(f"""
    <item>
      <title>{item['title']}</title>
      <link>{URL}</link>
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
    html = fetch_page()

    parser = NewsParser()
    parser.feed(html)
    items = parser.items

    new_hash = content_hash(items)
    old_hash = load_previous_hash()

    if new_hash == old_hash:
        print("No changes detected.")
        return

    rss = build_rss(items)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(rss)

    save_state(new_hash)
    print("RSS updated.")


if __name__ == "__main__":
    main()
