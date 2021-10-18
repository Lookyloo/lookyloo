#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import logging
from datetime import date
from pathlib import Path
from typing import Any, Dict

import requests

from ..default import ConfigError, get_config, get_homedir
from ..helpers import get_useragent_for_requests


class UrlScan():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('apikey'):
            self.available = False
            return

        self.available = True
        self.autosubmit = False
        self.allow_auto_trigger = False
        self.client = requests.session()
        self.client.headers['User-Agent'] = get_useragent_for_requests()
        self.client.headers['API-Key'] = config['apikey']
        self.client.headers['Content-Type'] = 'application/json'

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        if config.get('autosubmit'):
            self.autosubmit = True

        if config.get('force_visibility'):
            # Cases:
            # 1. False: unlisted for hidden captures / public for others
            # 2. "key": default visibility defined on urlscan.io
            # 3. "public", "unlisted", "private": is set for all submissions
            self.force_visibility = config['force_visibility']
        else:
            self.force_visibility = False

        if self.force_visibility not in [False, 'key', 'public', 'unlisted', 'private']:
            self.logger.warning("Invalid value for force_visibility, default to False (unlisted for hidden captures / public for others).")
            self.force_visibility = False

        self.storage_dir_urlscan = get_homedir() / 'urlscan'
        self.storage_dir_urlscan.mkdir(parents=True, exist_ok=True)

    def __get_cache_directory(self, url: str, useragent: str, referer: str) -> Path:
        m = hashlib.md5()
        to_hash = f'{url}{useragent}{referer}'
        m.update(to_hash.encode())
        return self.storage_dir_urlscan / m.hexdigest()

    def get_url_submission(self, capture_info: Dict[str, Any]) -> Dict[str, Any]:
        url_storage_dir = self.__get_cache_directory(capture_info['url'],
                                                     capture_info['user_agent'],
                                                     capture_info['referer']) / 'submit'
        if not url_storage_dir.exists():
            return {}
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return {}

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, capture_info: Dict[str, Any], /, visibility: str, *, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Run the module on the initial URL'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            # NOTE: if auto_trigger is true, it means the request comes from the
            # auto trigger feature (disabled by default)
            # Each module can disable auto-trigger to avoid depleating the
            # API limits.
            return {'error': 'Auto trigger not allowed on module'}

        self.url_submit(capture_info, visibility, force)
        return {'success': 'Module triggered'}

    def __submit_url(self, url: str, useragent: str, referer: str, visibility: str) -> Dict:
        data = {'customagent': useragent, 'referer': referer}

        if not url.startswith('http'):
            url = f'http://{url}'
        data['url'] = url

        if self.force_visibility is False:
            data["visibility"] = visibility
        elif self.force_visibility in ["public", "unlisted", "private"]:
            data["visibility"] = self.force_visibility
        else:
            # default to key config on urlscan.io website
            pass
        response = self.client.post('https://urlscan.io/api/v1/scan/', json=data)
        if response.status_code == 400:
            # Error, but we have details in the response
            return response.json()
        response.raise_for_status()
        return response.json()

    def __url_result(self, uuid: str) -> Dict:
        response = self.client.get(f'https://urlscan.io/api/v1/result/{uuid}')
        response.raise_for_status()
        return response.json()

    def url_submit(self, capture_info: Dict[str, Any], visibility: str, force: bool=False) -> Dict:
        '''Lookup an URL on urlscan.io
        Note: force means 2 things:
            * (re)scan of the URL
            * re-fetch the object from urlscan.io even if we already did it today

        Note: the URL will only be submitted if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('UrlScan not available, probably no API key')

        url_storage_dir = self.__get_cache_directory(capture_info['url'],
                                                     capture_info['user_agent'],
                                                     capture_info['referer']) / 'submit'
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        urlscan_file_submit = url_storage_dir / date.today().isoformat()

        if urlscan_file_submit.exists():
            if not force:
                with urlscan_file_submit.open('r') as _f:
                    return json.load(_f)
        elif self.autosubmit:
            # submit is allowed and we either force it, or it's just allowed
            try:
                response = self.__submit_url(capture_info['url'],
                                             capture_info['user_agent'],
                                             capture_info['referer'],
                                             visibility)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            if 'status' in response and response['status'] == 400:
                response = {'error': response}
            with urlscan_file_submit.open('w') as _f:
                json.dump(response, _f)
            return response
        return {'error': 'Submitting is not allowed by the configuration'}

    def url_result(self, capture_info: Dict[str, Any]):
        '''Get the result from a submission.'''
        submission = self.get_url_submission(capture_info)
        if submission and 'uuid' in submission:
            uuid = submission['uuid']
            if (self.storage_dir_urlscan / f'{uuid}.json').exists():
                with (self.storage_dir_urlscan / f'{uuid}.json').open() as _f:
                    return json.load(_f)
            try:
                result = self.__url_result(uuid)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            with (self.storage_dir_urlscan / f'{uuid}.json').open('w') as _f:
                json.dump(result, _f)
            return result
        return {'error': 'Submission incomplete or unavailable.'}
