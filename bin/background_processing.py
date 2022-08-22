#!/usr/bin/env python3

import json
import logging
from collections import Counter
from datetime import date, timedelta
from typing import Any, Dict

from redis import Redis

from lookyloo.default import AbstractManager, get_config, get_homedir, get_socket_path, safe_create_dir
from lookyloo.helpers import ParsedUserAgent

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class Processing(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'archiver'

        self.use_own_ua = get_config('generic', 'use_user_agents_users')

    def _to_run_forever(self):
        if self.use_own_ua:
            self._build_ua_file()

    def _build_ua_file(self):
        '''Build a file in a format compatible with the capture page'''
        yesterday = (date.today() - timedelta(days=1))
        self_generated_ua_file_path = get_homedir() / 'own_user_agents' / str(yesterday.year) / f'{yesterday.month:02}'
        safe_create_dir(self_generated_ua_file_path)
        self_generated_ua_file = self_generated_ua_file_path / f'{yesterday.isoformat()}.json'
        if self_generated_ua_file.exists():
            self.logger.info(f'User-agent file for {yesterday} already exists.')
            return
        self.logger.info(f'Generating user-agent file for {yesterday}')
        redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        entries = redis.zrevrange(f'user_agents|{yesterday.isoformat()}', 0, -1)
        if not entries:
            self.logger.info(f'No User-agent file for {yesterday} to generate.')
            return

        to_store: Dict[str, Any] = {'by_frequency': []}
        uas = Counter([entry.split('|', 1)[1] for entry in entries])
        for ua, _ in uas.most_common():
            parsed_ua = ParsedUserAgent(ua)
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
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2)

        # Remove the UA / IP mapping.
        redis.delete(f'user_agents|{yesterday.isoformat()}')
        self.logger.info(f'User-agent file for {yesterday} generated.')


def main():
    p = Processing()
    p.run(sleep_in_sec=3600 * 24)


if __name__ == '__main__':
    main()
