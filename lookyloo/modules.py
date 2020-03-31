#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any
from datetime import date
import hashlib
import json


from .helpers import get_homedir
from .exceptions import ConfigError

import vt  # type: ignore


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

    def __del__(self):
        if hasattr(self, 'client'):
            self.client.close()

    def url_lookup(self, url: str):
        if not self.available:
            raise ConfigError('VirusTotal not available, probably no API key')

        url_id = vt.url_id(url)
        m = hashlib.md5()
        m.update(url_id.encode())

        url_storage_dir = self.storage_dir_vt / m.hexdigest()
        url_storage_dir.mkdir(parents=True, exist_ok=True)

        vt_file = url_storage_dir / date.today().isoformat()
        if vt_file.exists():
            return

        try:
            url_information = self.client.get_object(f"/urls/{url_id}")
            with vt_file.open('w') as _f:
                json.dump(url_information.to_dict(), _f)
        except vt.APIError as e:
            if self.autosubmit and e.code == 'NotFoundError':
                self.client.scan_url(url)
