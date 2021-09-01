#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
from collections import Counter
from datetime import timedelta, date
from typing import Dict, Any

from redis import Redis
from werkzeug.useragents import UserAgent

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import (get_config, get_homedir, get_socket_path,
                              safe_create_dir)

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
            parsed_ua = UserAgent(ua)
            if not parsed_ua.platform or not parsed_ua.browser:
                continue
            if parsed_ua.platform not in to_store:
                to_store[parsed_ua.platform] = {}
            if f'{parsed_ua.browser} {parsed_ua.version}' not in to_store[parsed_ua.platform]:
                to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'] = []
            to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'].append(parsed_ua.string)
            to_store['by_frequency'].append({'os': parsed_ua.platform,
                                             'browser': f'{parsed_ua.browser} {parsed_ua.version}',
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
