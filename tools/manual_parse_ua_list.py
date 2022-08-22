#!/usr/bin/env python3

import json
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from bs4 import BeautifulSoup
try:
    import cloudscraper  # type: ignore
    HAS_CF = True
except ImportError:
    HAS_CF = False

from lookyloo.default import get_homedir, safe_create_dir
from lookyloo.helpers import ParsedUserAgent


def update_user_agents() -> None:
    # NOTE: this URL is behind cloudflare and tehre is no easy reliable way around it.
    # The manual way it to open the page in the browser, save it, and run this script.
    if not HAS_CF:
        # The website with the UAs is behind Cloudflare's anti-bot page, we need cloudscraper
        return

    today = datetime.now()
    ua_path = get_homedir() / 'user_agents' / str(today.year) / f'{today.month:02}'
    safe_create_dir(ua_path)
    ua_file_name: Path = ua_path / f'{today.date().isoformat()}.json'
    if ua_file_name.exists():
        # Already have a UA for that day.
        return
    try:
        s = cloudscraper.create_scraper()
        r = s.get('https://techblog.willshouse.com/2012/01/03/most-common-user-agents/')
    except Exception:
        traceback.print_exc()
        return
    to_store = ua_parser(r.text)
    with open(ua_file_name, 'w') as f:
        json.dump(to_store, f, indent=2)


def ua_parser(html_content: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html_content, 'html.parser')

    try:
        uas = soup.find_all('textarea')[1].text
    except Exception:
        traceback.print_exc()
        return {}

    to_store: Dict[str, Any] = {'by_frequency': []}
    for ua in json.loads(uas.replace('\n', '')):
        parsed_ua = ParsedUserAgent(ua['useragent'])
        if not parsed_ua.platform or not parsed_ua.browser:
            continue
        platform_key = parsed_ua.platform
        if parsed_ua.platform_version:
            platform_key = f'{platform_key} {parsed_ua.platform_version}'
        browser_key = parsed_ua.browser
        if parsed_ua.version:
            browser_key = f'{browser_key} {parsed_ua.version}'
        if platform_key not in to_store:
            to_store[platform_key] = {}
        if browser_key not in to_store[platform_key]:
            to_store[platform_key][browser_key] = []
        to_store[platform_key][browser_key].append(parsed_ua.string)
        to_store['by_frequency'].append({'os': platform_key,
                                         'browser': browser_key,
                                         'useragent': parsed_ua.string})
    return to_store


def main():
    to_parse = Path('Most Common User Agents - Tech Blog (wh).html')

    today = datetime.now()
    ua_path = get_homedir() / 'user_agents' / str(today.year) / f'{today.month:02}'
    safe_create_dir(ua_path)
    ua_file_name: Path = ua_path / f'{today.date().isoformat()}.json'

    with to_parse.open() as f:
        to_store = ua_parser(f.read())

    with open(ua_file_name, 'w') as f:
        json.dump(to_store, f, indent=2)


if __name__ == '__main__':
    main()
