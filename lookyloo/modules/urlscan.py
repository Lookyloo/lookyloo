#!/usr/bin/env python3

import json
from datetime import date
from typing import Any, Dict, Optional, TYPE_CHECKING

import requests

from ..default import ConfigError, get_homedir
from ..helpers import get_useragent_for_requests, get_cache_directory

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

from .abstractmodule import AbstractModule


class UrlScan(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info('No API key.')
            return False

        self.client = requests.session()
        self.client.headers['User-Agent'] = get_useragent_for_requests()
        self.client.headers['API-Key'] = self.config['apikey']
        self.client.headers['Content-Type'] = 'application/json'

        self.allow_auto_trigger = bool(self.config.get('allow_auto_trigger', False))
        self.autosubmit = bool(self.config.get('autosubmit', False))

        if self.config.get('force_visibility'):
            # Cases:
            # 1. False: unlisted for hidden captures / public for others
            # 2. "key": default visibility defined on urlscan.io
            # 3. "public", "unlisted", "private": is set for all submissions
            self.force_visibility = self.config['force_visibility']
        else:
            self.force_visibility = False

        if self.force_visibility not in [False, 'key', 'public', 'unlisted', 'private']:
            self.logger.warning("Invalid value for force_visibility, default to False (unlisted for hidden captures / public for others).")
            self.force_visibility = False

        self.storage_dir_urlscan = get_homedir() / 'urlscan'
        self.storage_dir_urlscan.mkdir(parents=True, exist_ok=True)
        return True

    def get_url_submission(self, capture_info: 'CaptureCache') -> Dict[str, Any]:
        url_storage_dir = get_cache_directory(
            self.storage_dir_urlscan,
            f'{capture_info.url}{capture_info.user_agent}{capture_info.referer}',
            'submit')
        if not url_storage_dir.exists():
            return {}
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return {}

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, capture_info: 'CaptureCache', /, visibility: str, *, force: bool=False, auto_trigger: bool=False) -> Dict:
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

    def __submit_url(self, url: str, useragent: Optional[str], referer: Optional[str], visibility: str) -> Dict:
        data = {'customagent': useragent if useragent else '', 'referer': referer if referer else ''}

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

    def url_submit(self, capture_info: 'CaptureCache', visibility: str, force: bool=False) -> Dict:
        '''Lookup an URL on urlscan.io
        Note: force means 2 things:
            * (re)scan of the URL
            * re-fetch the object from urlscan.io even if we already did it today

        Note: the URL will only be submitted if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('UrlScan not available, probably no API key')

        if capture_info.url.startswith('file'):
            return {'error': 'URLScan does not support files.'}

        url_storage_dir = get_cache_directory(
            self.storage_dir_urlscan,
            f'{capture_info.url}{capture_info.user_agent}{capture_info.referer}',
            'submit')
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        urlscan_file_submit = url_storage_dir / date.today().isoformat()

        if urlscan_file_submit.exists():
            if not force:
                with urlscan_file_submit.open('r') as _f:
                    return json.load(_f)
        elif self.autosubmit:
            # submit is allowed and we either force it, or it's just allowed
            try:
                response = self.__submit_url(capture_info.url,
                                             capture_info.user_agent,
                                             capture_info.referer,
                                             visibility)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            if 'status' in response and response['status'] == 400:
                response = {'error': response}
            with urlscan_file_submit.open('w') as _f:
                json.dump(response, _f)
            return response
        return {'error': 'Submitting is not allowed by the configuration'}

    def url_result(self, capture_info: 'CaptureCache'):
        '''Get the result from a submission.'''
        submission = self.get_url_submission(capture_info)
        if submission and 'uuid' in submission:
            uuid = submission['uuid']
            url_storage_dir_response = get_cache_directory(
                self.storage_dir_urlscan,
                f'{capture_info.url}{capture_info.user_agent}{capture_info.referer}',
                'response')
            url_storage_dir_response.mkdir(parents=True, exist_ok=True)
            if (url_storage_dir_response / f'{uuid}.json').exists():
                with (url_storage_dir_response / f'{uuid}.json').open() as _f:
                    return json.load(_f)
            try:
                result = self.__url_result(uuid)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            with (url_storage_dir_response / f'{uuid}.json').open('w') as _f:
                json.dump(result, _f)
            return result
        return {'error': 'Submission incomplete or unavailable.'}
