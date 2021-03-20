#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .exceptions import LookylooException


@dataclass
class CaptureCache():
    __default_cache_keys: Tuple[str, str, str, str, str, str] = \
        ('uuid', 'title', 'timestamp', 'url', 'redirects', 'capture_dir')

    def __init__(self, cache_entry: Dict[str, Any]):
        if all(key in cache_entry.keys() for key in self.__default_cache_keys):
            self.uuid: str = cache_entry['uuid']
            self.title: str = cache_entry['title']
            self.timestamp: datetime = datetime.strptime(cache_entry['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
            self.url: str = cache_entry['url']
            self.redirects: List[str] = json.loads(cache_entry['redirects'])
            self.capture_dir: Path = Path(cache_entry['capture_dir'])
        elif not cache_entry.get('error'):
            missing = set(self.__default_cache_keys) - set(cache_entry.keys())
            raise LookylooException(f'Missing keys ({missing}), no error message. It should not happen.')

        # Error without all the keys in __default_cache_keys was fatal.
        # if the keys in __default_cache_keys are present, it was an HTTP error
        self.error: Optional[str] = cache_entry.get('error')
        self.incomplete_redirects: bool = True if cache_entry.get('incomplete_redirects') in [1, '1'] else False
        self.no_index: bool = True if cache_entry.get('no_index') in [1, '1'] else False
        self.categories: List[str] = json.loads(cache_entry['categories']) if cache_entry.get('categories') else []
