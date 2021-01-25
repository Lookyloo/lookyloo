#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lookyloo.lookyloo import Lookyloo

lookyloo = Lookyloo()

for capture_uuid in lookyloo.capture_uuids:
    try:
        ct = lookyloo.get_crawled_tree(capture_uuid)
    except Exception:
        continue
