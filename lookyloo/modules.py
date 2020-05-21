#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List, Union
from datetime import date
import hashlib
import json
from pathlib import Path
import time


from .helpers import get_homedir
from .exceptions import ConfigError

import vt  # type: ignore
from pysanejs import SaneJS


class SaneJavaScript():

    skip_lookup: Dict[str, str] = {
        "717ea0ff7f3f624c268eccb244e24ec1305ab21557abb3d6f1a7e183ff68a2d28f13d1d2af926c9ef6d1fb16dd8cbe34cd98cacf79091dddc7874dcee21ecfdc": "1*1px gif",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": "Empty file"
    }

    def __init__(self, config: Dict[str, Any]):
        if not ('enabled' in config or config['enabled']):
            self.available = False
            return
        self.client = SaneJS()
        if not self.client.is_up:
            self.available = False
            return
        self.available = True
        self.storage_dir = get_homedir() / 'sanejs'
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def hashes_lookup(self, sha512: Union[List[str], str], force: bool=False) -> Dict[str, Any]:
        if isinstance(sha512, str):
            hashes = [sha512]
        else:
            hashes = sha512

        today_dir = self.storage_dir / date.today().isoformat()
        today_dir.mkdir(parents=True, exist_ok=True)
        sanejs_unknowns = today_dir / 'unknown'
        unknown_hashes = []
        if sanejs_unknowns.exists():
            with sanejs_unknowns.open() as f:
                unknown_hashes = [line.strip() for line in f.readlines()]

        to_return = {h: details for h, details in self.skip_lookup.items() if h in sha512}

        to_lookup = [h for h in hashes if h not in self.skip_lookup]
        if not force:
            to_lookup = [h for h in to_lookup if (h not in unknown_hashes
                                                  and not (today_dir / h).exists())]
        for h in to_lookup:
            response = self.client.sha512(h)
            if 'error' in response:
                # Server not ready
                break
            if 'response' in response and response['response']:
                cached_path = today_dir / h
                with cached_path.open('w') as f:
                    json.dump(response['response'], f)
                to_return[h] = response['response']
            else:
                unknown_hashes.append(h)

        for h in hashes:
            cached_path = today_dir / h
            if h in unknown_hashes or h in to_return:
                continue
            elif cached_path.exists():
                with cached_path.open() as f:
                    to_return[h] = json.load(f)

        return to_return


class VirusTotal():

    def __init__(self, config: Dict[str, Any]):
        if 'apikey' not in config:
            self.available = False
            return

        self.available = True
        self.autosubmit = False
        self.client = vt.Client(config['apikey'])
        if config.get('autosubmit'):
            self.autosubmit = True
        self.storage_dir_vt = get_homedir() / 'vt_url'
        self.storage_dir_vt.mkdir(parents=True, exist_ok=True)

    def __del__(self) -> None:
        if hasattr(self, 'client'):
            self.client.close()

    def __get_cache_directory(self, url: str) -> Path:
        url_id = vt.url_id(url)
        m = hashlib.md5()
        m.update(url_id.encode())
        return self.storage_dir_vt / m.hexdigest()

    def get_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        url_storage_dir = self.__get_cache_directory(url)
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def url_lookup(self, url: str, force: bool=False) -> None:
        '''Lookup an URL on VT
        Note: force means 2 things:
            * (re)scan of the URL
            * re fetch the object from VT even if we already did it today

        Note: the URL will only be sent for scan if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('VirusTotal not available, probably no API key')

        url_id = vt.url_id(url)
        url_storage_dir = self.__get_cache_directory(url)
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        vt_file = url_storage_dir / date.today().isoformat()

        scan_requested = False
        if self.autosubmit and force:
            self.client.scan_url(url)
            scan_requested = True

        if not force and vt_file.exists():
            return

        for i in range(3):
            try:
                url_information = self.client.get_object(f"/urls/{url_id}")
                with vt_file.open('w') as _f:
                    json.dump(url_information.to_dict(), _f)
                break
            except vt.APIError as e:
                if not self.autosubmit:
                    break
                if not scan_requested and e.code == 'NotFoundError':
                    self.client.scan_url(url)
                    scan_requested = True
            time.sleep(5)
