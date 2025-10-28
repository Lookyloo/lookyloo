#!/usr/bin/env python3

import json
import time
import traceback

from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

from lookyloo.default import get_homedir, safe_create_dir
from lookyloo.helpers import ParsedUserAgent, serialize_to_json

from bs4 import BeautifulSoup
from git import Repo
from pylookyloo import Lookyloo


def update_user_agents(lookyloo: Lookyloo) -> None | Path:
    # NOTE: this URL is behind cloudflare and tehre is no easy reliable way around it.
    # The manual way it to open the page in the browser, save it, and run this script.
    today = datetime.now()
    ua_path = get_homedir() / 'user_agents' / str(today.year) / f'{today.month:02}'
    safe_create_dir(ua_path)
    ua_file_name: Path = ua_path / f'{today.date().isoformat()}.json'
    if ua_file_name.exists():
        # Already have a UA for that day.
        return None
    ua_page = 'https://techblog.willshouse.com/2012/01/03/most-common-user-agents/'
    uuid = lookyloo.submit(url=ua_page, headless=False, listing=False, quiet=True)
    while True:
        if lookyloo.get_status(uuid)['status_code'] != 1:
            print(f'UA page capture ({uuid}) is not done yet, waiting...')
            time.sleep(5)
            continue
        break
    if rendered_html := lookyloo.get_html(uuid):
        to_store = ua_parser(rendered_html)
        with open(ua_file_name, 'w') as f:
            json.dump(to_store, f, indent=2, default=serialize_to_json)
        return ua_file_name
    return None


def ua_parser(html_content: StringIO) -> dict[str, Any]:
    soup = BeautifulSoup(html_content, 'html.parser')

    try:
        uas = soup.find_all('textarea')[1].text
    except Exception:
        traceback.print_exc()
        return {}

    to_store: dict[str, Any] = {'by_frequency': []}
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
            to_store[platform_key][browser_key] = set()
        to_store[platform_key][browser_key].add(parsed_ua.string)
        to_store['by_frequency'].append({'os': platform_key,
                                         'browser': browser_key,
                                         'useragent': parsed_ua.string})
    return to_store


def commit_ua_file(ua_file: Path) -> None:
    repo = Repo(get_homedir())
    repo.index.add([ua_file])
    repo.index.commit(f"Add user_agents from willshouse.com for {datetime.now()}")


def main() -> None:
    lookyloo = Lookyloo(root_url='http://127.0.0.1:5100')

    if new_ua_file := update_user_agents(lookyloo):
        commit_ua_file(new_ua_file)


if __name__ == '__main__':
    main()
