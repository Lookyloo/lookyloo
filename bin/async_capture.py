#!/usr/bin/env python3

import asyncio
import ipaddress
import json
import logging
import socket
from datetime import datetime
from io import BufferedIOBase
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

from defang import refang  # type: ignore
from redis.asyncio import Redis
from playwrightcapture import Capture

from lookyloo.default import AbstractManager, get_config, get_socket_path, safe_create_dir
from lookyloo.helpers import get_captures_dir, load_cookies, UserAgents

from lookyloo.modules import FOX

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'async_capture'
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')
        self.capture_dir: Path = get_captures_dir()
        self.user_agents = UserAgents()

        self.fox = FOX(get_config('modules', 'FOX'))
        if not self.fox.available:
            self.logger.warning('Unable to setup the FOX module')

    def thirdparty_submit(self, capture_data: Dict[str, str]) -> None:
        if self.fox.available:
            self.fox.capture_default_trigger(capture_data['url'], auto_trigger=True)

    async def process_capture_queue(self) -> None:
        '''Process a query from the capture queue'''
        value: List[Tuple[str, float]] = await self.redis.zpopmax('to_capture')
        if not value or not value[0]:
            # The queue was consumed by an other process.
            return
        uuid, _score = value[0]
        queue: Optional[str] = await self.redis.get(f'{uuid}_mgmt')
        await self.redis.sadd('ongoing', uuid)

        async with self.redis.pipeline() as lazy_cleanup:
            await lazy_cleanup.delete(f'{uuid}_mgmt')
            if queue:
                # queue shouldn't be none, but if it is, just ignore.
                await lazy_cleanup.zincrby('queues', -1, queue)

            to_capture: Dict[str, str] = await self.redis.hgetall(uuid)

            if get_config('generic', 'default_public'):
                # By default, the captures are on the index, unless the user mark them as un-listed
                listing = False if ('listing' in to_capture and to_capture['listing'].lower() in ['false', '0', '']) else True
            else:
                # By default, the captures are not on the index, unless the user mark them as listed
                listing = True if ('listing' in to_capture and to_capture['listing'].lower() in ['true', '1']) else False

            # Turn the freetext for the headers into a dict
            headers = {}
            if 'headers' in to_capture:
                for header_line in to_capture['headers'].splitlines():
                    if header_line and ':' in header_line:
                        splitted = header_line.split(':', 1)
                        if splitted and len(splitted) == 2:
                            header, h_value = splitted
                            if header and h_value:
                                headers[header.strip()] = h_value.strip()

            self.logger.info(f'Capturing {to_capture["url"]} - {uuid}')
            self.thirdparty_submit(to_capture)
            success, error_message = await self._capture(
                to_capture['url'],
                perma_uuid=uuid,
                cookies_pseudofile=to_capture.get('cookies', None),
                listing=listing,
                user_agent=to_capture.get('user_agent', None),
                referer=to_capture.get('referer', None),
                headers=headers if headers else None,
                proxy=to_capture.get('proxy', None),
                os=to_capture.get('os', None),
                browser=to_capture.get('browser', None),
                parent=to_capture.get('parent', None)
            )
            if success:
                self.logger.info(f'Successfully captured {to_capture["url"]} - {uuid}')
            else:
                self.logger.warning(f'Unable to capture {to_capture["url"]} - {uuid}: {error_message}')
                await lazy_cleanup.setex(f'error_{uuid}', 36000, f'{error_message} - {to_capture["url"]} - {uuid}')
            await lazy_cleanup.srem('ongoing', uuid)
            await lazy_cleanup.delete(uuid)
            # make sure to expire the key if nothing was processed for a while (= queues empty)
            await lazy_cleanup.expire('queues', 600)
            await lazy_cleanup.execute()

    async def _capture(self, url: str, *, perma_uuid: str, cookies_pseudofile: Optional[Union[BufferedIOBase, str]]=None,
                       listing: bool=True, user_agent: Optional[str]=None,
                       referer: Optional[str]=None, headers: Optional[Dict[str, str]]=None,
                       proxy: Optional[Union[str, Dict]]=None, os: Optional[str]=None,
                       browser: Optional[str]=None, parent: Optional[str]=None) -> Tuple[bool, str]:
        '''Launch a capture'''
        url = url.strip()
        url = refang(url)
        if not url.startswith('http'):
            url = f'http://{url}'
        splitted_url = urlsplit(url)
        if self.only_global_lookups:
            if splitted_url.netloc:
                if splitted_url.hostname and splitted_url.hostname.split('.')[-1] != 'onion':
                    try:
                        ip = socket.gethostbyname(splitted_url.hostname)
                    except socket.gaierror:
                        self.logger.info('Name or service not known')
                        return False, 'Name or service not known.'
                    if not ipaddress.ip_address(ip).is_global:
                        return False, 'Capturing ressources on private IPs is disabled.'
            else:
                return False, 'Unable to find hostname or IP in the query.'

        # check if onion
        if (not proxy and splitted_url.netloc and splitted_url.hostname
                and splitted_url.hostname.split('.')[-1] == 'onion'):
            proxy = get_config('generic', 'tor_proxy')

        cookies = load_cookies(cookies_pseudofile)
        if not user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            self.user_agents.user_agents  # triggers an update if needed
            ua: str = self.user_agents.default['useragent']
        else:
            ua = user_agent

        self.logger.info(f'Capturing {url}')
        try:
            async with Capture(proxy=proxy) as capture:
                capture.prepare_cookies(cookies)
                capture.user_agent = ua
                if headers:
                    capture.http_headers = headers
                await capture.prepare_context()
                entries = await capture.capture_page(url, referer=referer)
        except Exception as e:
            self.logger.exception(f'Something went terribly wrong when capturing {url} - {e}')
            return False, f'Something went terribly wrong when capturing {url}.'

        if not entries:
            # broken
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            return False, f'Something went terribly wrong when capturing {url}.'
        now = datetime.now()
        dirpath = self.capture_dir / str(now.year) / f'{now.month:02}' / now.isoformat()
        safe_create_dir(dirpath)

        if os or browser:
            meta = {}
            if os:
                meta['os'] = os
            if browser:
                meta['browser'] = browser
            with (dirpath / 'meta').open('w') as _meta:
                json.dump(meta, _meta)

        # Write UUID
        with (dirpath / 'uuid').open('w') as _uuid:
            _uuid.write(perma_uuid)

        # Write no_index marker (optional)
        if not listing:
            (dirpath / 'no_index').touch()

        # Write parent UUID (optional)
        if parent:
            with (dirpath / 'parent').open('w') as _parent:
                _parent.write(parent)

        if 'downloaded_filename' in entries and entries['downloaded_filename']:
            with(dirpath / '0.data.filename').open('w') as _downloaded_filename:
                _downloaded_filename.write(entries['downloaded_filename'])

        if 'downloaded_file' in entries and entries['downloaded_file']:
            with(dirpath / '0.data').open('wb') as _downloaded_file:
                _downloaded_file.write(entries['downloaded_file'])

        if 'error' in entries:
            with (dirpath / 'error.txt').open('w') as _error:
                json.dump(entries['error'], _error)

        if 'har' not in entries:
            return False, entries['error'] if entries['error'] else "Unknown error"

        with (dirpath / '0.har').open('w') as _har:
            json.dump(entries['har'], _har)

        if 'png' in entries and entries['png']:
            with (dirpath / '0.png').open('wb') as _img:
                _img.write(entries['png'])

        if 'html' in entries and entries['html']:
            with (dirpath / '0.html').open('w') as _html:
                _html.write(entries['html'])

        if 'last_redirected_url' in entries and entries['last_redirected_url']:
            with (dirpath / '0.last_redirect.txt').open('w') as _redir:
                _redir.write(entries['last_redirected_url'])

        if 'cookies' in entries and entries['cookies']:
            with (dirpath / '0.cookies.json').open('w') as _cookies:
                json.dump(entries['cookies'], _cookies)
        await self.redis.hset('lookup_dirs', perma_uuid, str(dirpath))
        return True, 'All good!'

    async def _to_run_forever_async(self):
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        while await self.redis.exists('to_capture'):
            await self.process_capture_queue()
            if self.shutdown_requested():
                break
        await self.redis.close()


def main():
    m = AsyncCapture()
    asyncio.run(m.run_async(sleep_in_sec=1))


if __name__ == '__main__':
    main()
