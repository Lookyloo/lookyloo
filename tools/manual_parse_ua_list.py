#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from bs4 import BeautifulSoup  # type: ignore
try:
    import cloudscraper  # type: ignore
    HAS_CF = True
except ImportError:
    HAS_CF = False

from lookyloo.helpers import get_homedir, safe_create_dir


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
        os = ua['system'].split(' ')[-1]
        if os not in to_store:
            to_store[os] = {}
        browser = ' '.join(ua['system'].split(' ')[:-1])
        if browser not in to_store[os]:
            to_store[os][browser] = []
        to_store[os][browser].append(ua['useragent'])
        to_store['by_frequency'].append({'os': os, 'browser': browser, 'useragent': ua['useragent']})
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
