#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from pathlib import Path
import json

from lookyloo.helpers import ua_parser, get_homedir, safe_create_dir

to_parse = Path('Most Common User Agents - Tech Blog (wh).html')

today = datetime.now()
ua_path = get_homedir() / 'user_agents' / str(today.year) / f'{today.month:02}'
safe_create_dir(ua_path)
ua_file_name: Path = ua_path / f'{today.date().isoformat()}.json'

with to_parse.open() as f:
    to_store = ua_parser(f.read())

with open(ua_file_name, 'w') as f:
    json.dump(to_store, f, indent=2)
