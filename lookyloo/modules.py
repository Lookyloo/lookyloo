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
        "717ea0ff7f3f624c268eccb244e24ec1305ab21557abb3d6f1a7e183ff68a2d28f13d1d2af926c9ef6d1fb16dd8cbe34cd98cacf79091dddc7874dcee21ecfdc": "This is a 1*1 pixel GIF",
        "e508d5d17e94d14b126164082342a9ca4774f404e87a3dd56c26812493ee18d9c3d6daacca979134a94a003066aca24116de874596d00d1e52130c1283d54209": "This is a 1*1 pixel GIF",
        "2d073e10ae40fde434eb31cbedd581a35cd763e51fb7048b88caa5f949b1e6105e37a228c235bc8976e8db58ed22149cfccf83b40ce93a28390566a28975744a": "This is a 1*1 pixel GIF",
        "84e24a70b78e9de9c9d0dfeb49f3f4247dbc1c715d8844471ee40669270682e199d48f5fbec62bd984c9c0270534b407c4d2561dd6c05adec3c83c1534f32d5c": "This is a 1*1 pixel GIF",
        "d5da26b5d496edb0221df1a4057a8b0285d15592a8f8dc7016a294df37ed335f3fde6a2252962e0df38b62847f8b771463a0124ef3f84299f262ed9d9d3cee4c": "This is a 1*1 pixel GIF",
        "f7a5f748f4c0d3096a3ca972886fe9a9dff5dce7792779ec6ffc42fa880b3815e2e4c3bdea452352f3844b81864c9bfb7861f66ac961cfa66cb9cb4febe568e8": "This is a 1*1 pixel GIF",
        "b2ca25a3311dc42942e046eb1a27038b71d689925b7d6b3ebb4d7cd2c7b9a0c7de3d10175790ac060dc3f8acf3c1708c336626be06879097f4d0ecaa7f567041": "This is a 1*1 pixel GIF",
        "b8d82d64ec656c63570b82215564929adad167e61643fd72283b94f3e448ef8ab0ad42202f3537a0da89960bbdc69498608fc6ec89502c6c338b6226c8bf5e14": "This is a 1*1 pixel GIF",
        "2991c3aa1ba61a62c1cccd990c0679a1fb8dccd547d153ec0920b91a75ba20820de1d1c206f66d083bf2585d35050f0a39cd7a3e11c03882dafec907d27a0180": "This is a 1*1 pixel GIF",
        "b1a6cfa7b21dbb0b281d241af609f3ba7f3a63e5668095bba912bf7cfd7f0320baf7c3b0bfabd0f8609448f39902baeb145ba7a2d8177fe22a6fcea03dd29be1": "This is a 1*1 pixel GIF",
        "ebfe0c0df4bcc167d5cb6ebdd379f9083df62bef63a23818e1c6adf0f64b65467ea58b7cd4d03cf0a1b1a2b07fb7b969bf35f25f1f8538cc65cf3eebdf8a0910": "This is a 1*1 pixel GIF",
        "1d68b92e8d822fe82dc7563edd7b37f3418a02a89f1a9f0454cca664c2fc2565235e0d85540ff9be0b20175be3f5b7b4eae1175067465d5cca13486aab4c582c": "This is a 1*1 pixel GIF",
        "ac44da7f455bfae52b883639964276026fb259320902aa813d0333e021c356a7b3e3537b297f9a2158e588c302987ce0854866c039d1bb0ffb27f67560739db2": "This is a 1*1 pixel GIF",
        "921944dc10fbfb6224d69f0b3ac050f4790310fd1bcac3b87c96512ad5ed9a268824f3f5180563d372642071b4704c979d209baf40bc0b1c9a714769aba7dfc7": "This is a 1*1 pixel GIF",
        "89dfc38ec77cf258362e4db7c8203cae8a02c0fe4f99265b0539ec4f810c84f8451e22c9bef1ebc59b4089af7e93e378e053c542a5967ec4912d4c1fc5de22f0": "This is a 1*1 pixel GIF",
        "280ea4383ee6b37051d91c5af30a5ce72aa4439340fc6d31a4fbe7ba8a8156eb7893891d5b2371b9fc4934a78f08de3d57e5b63fa9d279a317dcbefb8a07a6b0": "This is a 1*1 pixel GIF",
        "3844065e1dd778a05e8cc39901fbf3191ded380d594359df137901ec56ca52e03d57eb60acc2421a0ee74f0733bbb5d781b7744685c26fb013a236f49b02fed3": "This is a 1*1 pixel GIF",
        "bd9ab35dde3a5242b04c159187732e13b0a6da50ddcff7015dfb78cdd68743e191eaf5cddedd49bef7d2d5a642c217272a40e5ba603fe24ca676a53f8c417c5d": "This is a 1*1 pixel GIF",
        "d052ecec2839340876eb57247cfc2e777dd7f2e868dc37cd3f3f740c8deb94917a0c9f2a4fc8229987a0b91b04726de2d1e9f6bcbe3f9bef0e4b7e0d7f65ea12": "This is a 1*1 pixel GIF",
        "8717074ddf1198d27b9918132a550cb4ba343794cc3d304a793f9d78c9ff6c4929927b414141d40b6f6ad296725520f4c63edeb660ed530267766c2ab74ee4a9": "This is a 1*1 pixel GIF",
        "f1c33e72643ce366fd578e3b5d393799e8c9ea27b180987826af43b4fc00b65a4eaae5e6426a23448956fee99e3108c6a86f32fb4896c156e24af0571a11c498": "This is a 1*1 pixel PNG",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": "This is an empty file"
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
