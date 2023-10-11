#!/usr/bin/env python3

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlsplit

from har2tree import CrawledTree, HostNode, URLNode
from redis import Redis

from .default import get_config, get_homedir, get_socket_path
from .helpers import get_resources_hashes, load_known_content, serialize_to_json
from .modules import SaneJavaScript


class Context():

    def __init__(self):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('indexing'), db=1, decode_responses=True)
        self._cache_known_content()
        self.sanejs = SaneJavaScript(config_name='SaneJS')

    def clear_context(self):
        self.redis.flushdb()

    def _cache_known_content(self) -> None:
        for dirname in ['known_content', 'known_content_user']:
            for filename, file_content in load_known_content(dirname).items():
                p = self.redis.pipeline()
                if filename == 'generic':
                    # 1px images, files with spaces, empty => non-relevant stuff
                    for _, type_content in file_content.items():
                        p.hset('known_content', mapping={h: type_content['description'] for h in type_content['entries']})
                elif filename == 'malicious':
                    # User defined as malicious
                    for h, details in file_content.items():
                        p.sadd('bh|malicious', h)
                        if 'target' in details and details['target']:
                            p.sadd(f'{h}|target', *details['target'])
                        if 'tag' in details and details['tag']:
                            p.sadd(f'{h}|tag', *details['tag'])
                elif filename == 'legitimate':
                    # User defined as legitimate
                    for h, details in file_content.items():
                        if 'domain' in details and details['domain']:
                            p.sadd(f'bh|{h}|legitimate', *details['domain'])
                        elif 'description' in details:
                            p.hset('known_content', h, details['description'])
                else:
                    # Full captures marked as legitimate
                    for h, details in file_content.items():
                        p.sadd(f'bh|{h}|legitimate', *details['hostnames'])
                p.execute()

    def find_known_content(self, har2tree_container: Union[CrawledTree, HostNode, URLNode, str]) -> Dict[str, Any]:
        """Return a dictionary of content resources found in the local known_content database, or in SaneJS (if enabled)"""
        if isinstance(har2tree_container, str):
            to_lookup: Set[str] = {har2tree_container, }
        else:
            to_lookup = get_resources_hashes(har2tree_container)
        known_content_table: Dict[str, Any] = {}
        if not to_lookup:
            return known_content_table
        # get generic known content
        known_in_generic = zip(to_lookup, self.redis.hmget('known_content', to_lookup))
        for h, details in known_in_generic:
            if not details:
                continue
            known_content_table[h] = {'type': 'generic', 'details': details}

        to_lookup = to_lookup - set(known_content_table.keys())
        if not to_lookup:
            return known_content_table

        # get known malicious
        for h in to_lookup:
            if self.redis.sismember('bh|malicious', h):
                known_content_table[h] = {'type': 'malicious', 'details': {}}
                targets = self.redis.smembers(f'{h}|target')
                tags = self.redis.smembers(f'{h}|tag')
                if targets:
                    known_content_table[h]['details']['target'] = targets
                if tags:
                    known_content_table[h]['details']['tag'] = tags

        to_lookup = to_lookup - set(known_content_table.keys())
        if not to_lookup:
            return known_content_table

        # get known legitimate with domain
        for h in to_lookup:
            domains = self.redis.smembers(f'bh|{h}|legitimate')
            if not domains:
                continue
            known_content_table[h] = {'type': 'legitimate_on_domain', 'details': domains}

        to_lookup = to_lookup - set(known_content_table.keys())
        if not to_lookup:
            return known_content_table

        if to_lookup and self.sanejs.available:
            # Query sanejs on the remaining ones
            try:
                for h, entry in self.sanejs.hashes_lookup(to_lookup).items():
                    libname, version, path = entry[0].split("|")
                    known_content_table[h] = {'type': 'sanejs',
                                              'details': (libname, version, path, len(entry))}
            except json.decoder.JSONDecodeError as e:
                self.logger.warning(f'Something went wrong with sanejs: {e}')

        return known_content_table

    def store_known_legitimate_tree(self, tree: CrawledTree):
        known_content = self.find_known_content(tree)
        capture_file: Path = get_homedir() / 'known_content_user' / f'{urlsplit(tree.root_url).hostname}.json'
        if capture_file.exists():
            with open(capture_file) as f:
                to_store = json.load(f)
        else:
            to_store = {}
        for urlnode in tree.root_hartree.url_tree.traverse():
            for h in urlnode.resources_hashes:
                if h in known_content and known_content[h]['type'] != 'malicious':
                    # when we mark a tree as legitimate, we may get a hash that was marked
                    # as malicious beforehand but turn out legitimate on that specific domain.
                    continue
                mimetype = ''
                if h != urlnode.body_hash:
                    # this is the hash of an embeded content so it won't have a filename but has a different mimetype
                    # FIXME: this is ugly.
                    for ressource_mimetype, blobs in urlnode.embedded_ressources.items():
                        for ressource_h, _ in blobs:
                            if ressource_h == h:
                                mimetype = ressource_mimetype.split(';')[0]
                                break
                        if mimetype:
                            break
                else:
                    if urlnode.mimetype:
                        mimetype = urlnode.mimetype.split(';')[0]
                if h not in to_store:
                    to_store[h] = {'filenames': set(), 'description': '', 'hostnames': set(), 'mimetype': mimetype}
                else:
                    to_store[h]['filenames'] = set(to_store[h]['filenames'])
                    to_store[h]['hostnames'] = set(to_store[h]['hostnames'])

                to_store[h]['hostnames'].add(urlnode.hostname)
                if urlnode.url_split.path:
                    filename = Path(urlnode.url_split.path).name
                    if filename:
                        to_store[h]['filenames'].add(filename)

        with open(capture_file, 'w') as f:
            json.dump(to_store, f, indent=2, default=serialize_to_json)

    def mark_as_legitimate(self, tree: CrawledTree, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> None:
        if hostnode_uuid:
            urlnodes = tree.root_hartree.get_host_node_by_uuid(hostnode_uuid).urls
        elif urlnode_uuid:
            urlnodes = [tree.root_hartree.get_url_node_by_uuid(urlnode_uuid)]
        else:
            urlnodes = tree.root_hartree.url_tree.traverse()
            self.store_known_legitimate_tree(tree)
        known_content = self.find_known_content(tree)
        pipeline = self.redis.pipeline()
        for urlnode in urlnodes:
            # Note: we can have multiple hahes on the same urlnode (see embedded resources).
            # They are expected to be on the same domain as urlnode. This code work as expected.
            for h in urlnode.resources_hashes:
                if h in known_content and known_content[h]['type'] != 'malicious':
                    # when we mark a tree as legitimate, we may get a hash that was marked
                    # as malicious beforehand but turn out legitimate on that specific domain.
                    continue
                pipeline.sadd(f'bh|{h}|legitimate', urlnode.hostname)
        pipeline.execute()

    def contextualize_tree(self, tree: CrawledTree) -> CrawledTree:
        """Iterate through all the URL nodes in the tree, add context to Host nodes accordingly
        * malicious: At least one URLnode in the Hostnode is marked as malicious
        * legitimate: All the URLnodes in the Hostnode are marked as legitimate
        * empty: All the the URLnodes in the Hostnode have an empty body in their response
        """
        hostnodes_with_malicious_content = set()
        known_content = self.find_known_content(tree)
        for urlnode in tree.root_hartree.url_tree.traverse():
            if urlnode.empty_response:
                continue

            malicious = self.is_malicious(urlnode, known_content)
            if malicious is True:
                urlnode.add_feature('malicious', True)
                hostnodes_with_malicious_content.add(urlnode.hostnode_uuid)
            elif malicious is False:
                # Marked as legitimate
                urlnode.add_feature('legitimate', True)
            else:
                # malicious is None => we cannot say.
                pass

        for hostnode in tree.root_hartree.hostname_tree.traverse():
            if hostnode.uuid in hostnodes_with_malicious_content:
                hostnode.add_feature('malicious', True)
            elif all(urlnode.empty_response for urlnode in hostnode.urls):
                hostnode.add_feature('all_empty', True)
            else:
                legit = [True for urlnode in hostnode.urls if 'legitimate' in urlnode.features]
                if len(legit) == len(hostnode.urls):
                    hostnode.add_feature('legitimate', True)
        return tree

    def legitimate_body(self, body_hash: str, legitimate_hostname: str) -> None:
        self.redis.sadd(f'bh|{body_hash}|legitimate', legitimate_hostname)

    def store_known_malicious_ressource(self, ressource_hash: str, details: Dict[str, str]):
        known_malicious_ressource_file = get_homedir() / 'known_content_user' / 'malicious.json'
        if known_malicious_ressource_file.exists():
            with open(known_malicious_ressource_file) as f:
                to_store = json.load(f)
        else:
            to_store = {}

        if ressource_hash not in to_store:
            to_store[ressource_hash] = {'target': set(), 'tag': set()}
        else:
            to_store[ressource_hash]['target'] = set(to_store[ressource_hash]['target'])
            to_store[ressource_hash]['tag'] = set(to_store[ressource_hash]['tag'])

        if 'target' in details:
            to_store[ressource_hash]['target'].add(details['target'])
        if 'type' in details:
            to_store[ressource_hash]['tag'].add(details['type'])

        with open(known_malicious_ressource_file, 'w') as f:
            json.dump(to_store, f, indent=2, default=serialize_to_json)

    def add_malicious(self, ressource_hash: str, details: Dict[str, str]):
        self.store_known_malicious_ressource(ressource_hash, details)
        p = self.redis.pipeline()
        p.sadd('bh|malicious', ressource_hash)
        if 'target' in details:
            p.sadd(f'{ressource_hash}|target', details['target'])
        if 'type' in details:
            p.sadd(f'{ressource_hash}|tag', details['type'])
        p.execute()

    def store_known_legitimate_ressource(self, ressource_hash: str, details: Dict[str, str]):
        known_legitimate_ressource_file = get_homedir() / 'known_content_user' / 'legitimate.json'
        if known_legitimate_ressource_file.exists():
            with open(known_legitimate_ressource_file) as f:
                to_store = json.load(f)
        else:
            to_store = {}

        if ressource_hash not in to_store:
            to_store[ressource_hash] = {'domain': set(), 'description': ''}
        else:
            to_store[ressource_hash]['domain'] = set(to_store[ressource_hash]['domain'])

        if 'domain' in details:
            to_store[ressource_hash]['domain'].add(details['domain'])
        if 'description' in details:
            to_store[ressource_hash]['description'] = details['description']

        with open(known_legitimate_ressource_file, 'w') as f:
            json.dump(to_store, f, indent=2, default=serialize_to_json)

    def add_legitimate(self, ressource_hash: str, details: Dict[str, str]):
        self.store_known_legitimate_ressource(ressource_hash, details)
        if 'domain' in details:
            self.redis.sadd(f'bh|{ressource_hash}|legitimate', details['domain'])
        elif 'description' in details:
            # Library
            self.redis.hset('known_content', ressource_hash, details['description'])

    # Query DB

    def is_legitimate(self, urlnode: URLNode, known_hashes: Dict[str, Any]) -> Optional[bool]:
        """
        If legitimate if generic, marked as legitimate or known on sanejs, loaded from the right domain
        3 cases:
            * True if *all* the contents are known legitimate
            * False if *any* content is malicious
            * None in all other cases
        """
        status: List[Optional[bool]] = []
        for h in urlnode.resources_hashes:
            # Note: we can have multiple hashes on the same urlnode (see embedded resources).
            if h not in known_hashes:
                # We do not return here, because we want to return False if
                # *any* of the contents is malicious
                status.append(None)  # Unknown
            elif known_hashes[h]['type'] == 'malicious':
                return False
            elif known_hashes[h]['type'] in ['generic', 'sanejs']:
                status.append(True)
            elif known_hashes[h]['type'] == 'legitimate_on_domain':
                if urlnode.hostname in known_hashes[h]['details']:
                    status.append(True)
                else:
                    return False
        if status and all(status):
            return True  # All the contents are known legitimate
        return None

    def is_malicious(self, urlnode: URLNode, known_hashes: Dict[str, Any]) -> Optional[bool]:
        """3 cases:
            * True if *any* content is malicious
            * False if *all* the contents are known legitimate
            * None in all other cases
        """
        legitimate = self.is_legitimate(urlnode, known_hashes)
        if legitimate:
            return False
        elif legitimate is False:
            return True
        return None
