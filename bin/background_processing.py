#!/usr/bin/env python3

import json
import logging
import logging.config
from collections import Counter
from datetime import date, timedelta
from typing import Any, Dict, Optional

from lookyloo.lookyloo import Lookyloo
from lookyloo.default import AbstractManager, get_config, get_homedir, safe_create_dir
from lookyloo.helpers import ParsedUserAgent, serialize_to_json

logging.config.dictConfig(get_config('logging'))


class Processing(AbstractManager):

    def __init__(self, loglevel: Optional[int]=None):
        super().__init__(loglevel)
        self.script_name = 'processing'
        self.lookyloo = Lookyloo()

        self.use_own_ua = get_config('generic', 'use_user_agents_users')

    def _to_run_forever(self):
        if self.use_own_ua:
            self._build_ua_file()
        self._retry_failed_enqueue()

    def _build_ua_file(self):
        '''Build a file in a format compatible with the capture page'''
        yesterday = (date.today() - timedelta(days=1))
        self_generated_ua_file_path = get_homedir() / 'own_user_agents' / str(yesterday.year) / f'{yesterday.month:02}'
        safe_create_dir(self_generated_ua_file_path)
        self_generated_ua_file = self_generated_ua_file_path / f'{yesterday.isoformat()}.json'
        if self_generated_ua_file.exists():
            self.logger.debug(f'User-agent file for {yesterday} already exists.')
            return
        self.logger.info(f'Generating user-agent file for {yesterday}')
        entries = self.lookyloo.redis.zrevrange(f'user_agents|{yesterday.isoformat()}', 0, -1)
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
                to_store[platform_key][browser_key] = set()
            to_store[platform_key][browser_key].add(parsed_ua.string)
            to_store['by_frequency'].append({'os': platform_key,
                                             'browser': browser_key,
                                             'useragent': parsed_ua.string})
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2, default=serialize_to_json)

        # Remove the UA / IP mapping.
        self.lookyloo.redis.delete(f'user_agents|{yesterday.isoformat()}')
        self.logger.info(f'User-agent file for {yesterday} generated.')

    def _retry_failed_enqueue(self):
        '''If enqueuing failed, the settings are added, with a UUID in the 'to_capture key', and they have a UUID'''
        for uuid in self.lookyloo.redis.zrevrangebyscore('to_capture', 'Inf', '-Inf'):
            if self.lookyloo.redis.hexists(uuid, 'not_queued'):
                self.logger.info(f'Found a non-queued capture ({uuid}), retrying now.')
                # This capture couldn't be queued and we created the uuid locally
                query = self.lookyloo.redis.hgetall(uuid)
                try:
                    self.lookyloo.lacus.enqueue(
                        url=query.get('url', None),
                        document_name=query.get('document_name', None),
                        document=query.get('document', None),
                        # depth=query.get('depth', 0),
                        browser=query.get('browser', None),
                        device_name=query.get('device_name', None),
                        user_agent=query.get('user_agent', None),
                        proxy=query.get('proxy', None),
                        general_timeout_in_sec=query.get('general_timeout_in_sec', None),
                        cookies=query.get('cookies', None),
                        headers=query.get('headers', None),
                        http_credentials=query.get('http_credentials', None),
                        viewport=query.get('viewport', None),
                        referer=query.get('referer', None),
                        rendered_hostname_only=query.get('rendered_hostname_only', True),
                        # force=query.get('force', False),
                        # recapture_interval=query.get('recapture_interval', 300),
                        priority=query.get('priority', None),
                        uuid=uuid
                    )
                except Exception as e:
                    self.logger.warning(f'Still unable to enqueue capture: {e}')
                    break
                else:
                    self.lookyloo.redis.hdel(uuid, 'not_queued')
                    self.logger.info(f'{uuid} enqueued.')


def main():
    p = Processing()
    p.run(sleep_in_sec=30)


if __name__ == '__main__':
    main()
