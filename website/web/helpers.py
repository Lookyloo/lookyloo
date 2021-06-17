#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from functools import lru_cache
from typing import Dict

from lookyloo.helpers import get_homedir


@lru_cache(64)
def sri_load() -> Dict[str, Dict[str, str]]:
    with (get_homedir() / 'website' / 'web' / 'sri.txt').open() as f:
        return json.load(f)
