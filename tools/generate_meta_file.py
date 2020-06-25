#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lookyloo.lookyloo import Lookyloo

lookyloo = Lookyloo()

for capture_dir in lookyloo.capture_dirs:
    try:
        ct = lookyloo.get_crawled_tree(capture_dir)
    except Exception:
        continue
    lookyloo._ensure_meta(capture_dir, ct)
