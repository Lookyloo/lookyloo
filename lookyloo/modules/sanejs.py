#!/usr/bin/env python3

import json
from datetime import date
from typing import Dict, Iterable, List, Union

from pysanejs import SaneJS

from ..default import get_homedir

from .abstractmodule import AbstractModule


class SaneJavaScript(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('enabled'):
            self.logger.info('Not enabled.')
            return False

        self.client = SaneJS()

        if not self.client.is_up:
            self.logger.warning('Not up.')
            return False

        self.allow_auto_trigger = bool(self.config.get('allow_auto_trigger', False))
        self.storage_dir = get_homedir() / 'sanejs'
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        return True

    def hashes_lookup(self, sha512: Union[Iterable[str], str], force: bool=False) -> Dict[str, List[str]]:
        if isinstance(sha512, str):
            hashes: Iterable[str] = [sha512]
        else:
            hashes = sha512

        today_dir = self.storage_dir / date.today().isoformat()
        today_dir.mkdir(parents=True, exist_ok=True)
        sanejs_unknowns = today_dir / 'unknown'
        unknown_hashes = set()
        if sanejs_unknowns.exists():
            with sanejs_unknowns.open() as f:
                unknown_hashes = {line.strip() for line in f.readlines()}

        to_return: Dict[str, List[str]] = {}

        if force:
            to_lookup = hashes
        else:
            to_lookup = [h for h in hashes if (h not in unknown_hashes
                                               and not (today_dir / h).exists())]
        has_new_unknown = False
        for h in to_lookup:
            try:
                response = self.client.sha512(h)
            except Exception as e:
                self.logger.warning(f'Something went wrong. Query: {h} - {e}')
                continue

            if 'error' in response:
                # Server not ready
                break
            if 'response' in response and response['response']:
                cached_path = today_dir / h
                with cached_path.open('w') as f:
                    json.dump(response['response'], f)
                to_return[h] = response['response']
            else:
                has_new_unknown = True
                unknown_hashes.add(h)

        for h in hashes:
            cached_path = today_dir / h
            if h in unknown_hashes or h in to_return:
                continue
            elif cached_path.exists():
                with cached_path.open() as f:
                    to_return[h] = json.load(f)

        if has_new_unknown:
            with sanejs_unknowns.open('w') as f:
                f.writelines(f'{h}\n' for h in unknown_hashes)

        return to_return
