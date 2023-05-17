#!/usr/bin/env python3

import fnmatch
import logging

from typing import Dict, Any, Union, List, Optional, TypedDict, Tuple

from har2tree import URLNode

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .context import Context
from .capturecache import CapturesIndex
from .default import get_config, get_socket_path
from .exceptions import MissingUUID


class CompareSettings(TypedDict):
    '''The settings that can be passed to the compare method to filter out some differences'''

    ressources_ignore_domains: Tuple[str, ...]
    ressources_ignore_regexes: Tuple[str, ...]


class Comparator():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('cache'), decode_responses=True)

        self.context = Context()
        self._captures_index = CapturesIndex(self.redis, self.context)
        self.public_domain = get_config('generic', 'public_domain')

    @property
    def redis(self) -> Redis:
        return Redis(connection_pool=self.redis_pool)

    def get_comparables_node(self, node: URLNode) -> Dict[str, str]:
        to_return = {'url': node.name, 'hostname': node.hostname}
        if hasattr(node, 'ip_address'):
            to_return['ip_address'] = str(node.ip_address)
        return to_return

    def _compare_nodes(self, left: Dict[str, str], right: Dict[str, str], /, different: bool) -> Tuple[bool, Dict[str, Any]]:
        to_return = {}
        # URL
        if left['url'] != right['url']:
            different = True
            to_return['url'] = {'message': 'The nodes have different URLs.',
                                'details': [left['url'], right['url']]}
            # Hostname
            if left['hostname'] != right['hostname']:
                to_return['hostname'] = {'message': 'The nodes have different hostnames.',
                                         'details': [left['hostname'], right['hostname']]}
            else:
                to_return['hostname'] = {'message': 'The nodes have the same hostname.',
                                         'details': left['hostname']}
        else:
            to_return['url'] = {'message': 'The nodes have the same URL.',
                                'details': left['url']}
        # IP in HAR
        if left.get('ip_address') and right.get('ip_address'):
            if left['ip_address'] != right['ip_address']:
                different = True
                to_return['ip'] = {'message': 'The nodes load content from different IPs.',
                                   'details': [left['ip_address'], right['ip_address']]}
            else:
                to_return['ip'] = {'message': 'The nodes load content from the same IP.',
                                   'details': left['ip_address']}

        # IPs in hostnode + ASNs
        return different, to_return

    def get_comparables_capture(self, capture_uuid: str) -> Dict[str, Any]:
        if capture_uuid not in self._captures_index:
            raise MissingUUID(f'{capture_uuid} does not exists.')

        capture = self._captures_index[capture_uuid]
        to_return = {'root_url': capture.tree.root_url,
                     'final_url': capture.tree.root_hartree.har.final_redirect,
                     'final_hostname': capture.tree.root_hartree.rendered_node.hostname,
                     'final_status_code': capture.tree.root_hartree.rendered_node.response['status'],
                     'redirects': {'length': len(capture.tree.redirects)}}

        to_return['redirects']['nodes'] = [self.get_comparables_node(a) for a in list(reversed(capture.tree.root_hartree.rendered_node.get_ancestors())) + [capture.tree.root_hartree.rendered_node]]
        to_return['ressources'] = {(a.name, a.hostname) for a in capture.tree.root_hartree.rendered_node.traverse()}
        return to_return

    def compare_captures(self, capture_left: str, capture_right: str, /, *, settings: Optional[CompareSettings]=None) -> Tuple[bool, Dict[str, Any]]:
        if capture_left not in self._captures_index:
            raise MissingUUID(f'{capture_left} does not exists.')
        if capture_right not in self._captures_index:
            raise MissingUUID(f'{capture_right} does not exists.')

        different: bool = False
        to_return: Dict[str, Dict[str, Union[str,
                                             List[Union[str, Dict[str, Any]]],
                                             Dict[str, Union[int, str,
                                                             List[Union[int, str, Dict[str, Any]]]]]]]] = {}
        to_return['lookyloo_urls'] = {'left': f'https://{self.public_domain}/tree/{capture_left}',
                                      'right': f'https://{self.public_domain}/tree/{capture_right}'}
        left = self.get_comparables_capture(capture_left)
        right = self.get_comparables_capture(capture_right)
        # Compare initial URL (first entry in HAR)
        if left['root_url'] != right['root_url']:
            different = True
            to_return['root_url'] = {'message': 'The captures are for different URLs.',
                                     'details': [left['root_url'], right['root_url']]}
        else:
            to_return['root_url'] = {'message': 'The captures are the same URL.',
                                     'details': left['root_url']}

        # Compare landing page (URL in browser)
        if left['final_url'] != right['final_url']:
            different = True
            to_return['final_url'] = {'message': 'The landing page is different.',
                                      'details': [left['final_url'], right['final_url']]}
            #   => if different, check if the hostname is the same
            if left['final_hostname'] != right['final_hostname']:
                to_return['final_hostname'] = {'message': 'The hostname of the rendered page is different.',
                                               'details': [left['final_hostname'], right['final_hostname']]}
            else:
                to_return['final_hostname'] = {'message': 'The hostname of the rendered page is the same.',
                                               'details': left['final_hostname']}
        else:
            to_return['final_url'] = {'message': 'The landing page is the same.',
                                      'details': left['final_url']}

        if left['final_status_code'] != right['final_status_code']:
            different = True
            to_return['final_status_code'] = {'message': 'The status code of the rendered page is different.',
                                              'details': [left['final_status_code'], right['final_status_code']]}
        else:
            to_return['final_status_code'] = {'message': 'The status code of the rendered page is the same.',
                                              'details': left['final_status_code']}

        to_return['redirects'] = {'length': {}, 'nodes': []}
        if left['redirects']['length'] != right['redirects']['length']:
            different = True
            to_return['redirects']['length'] = {'message': 'The captures have a different amount of redirects',
                                                'details': [left['redirects']['length'], right['redirects']['length']]}
        else:
            to_return['redirects']['length'] = {'message': 'The captures have the same number of redirects',
                                                'details': left['redirects']['length']}

        # Compare chain of redirects
        for redirect_left, redirect_right in zip(right['redirects']['nodes'], left['redirects']['nodes']):
            if isinstance(to_return['redirects']['nodes'], list):
                different, node_compare = self._compare_nodes(redirect_left, redirect_right, different)
                to_return['redirects']['nodes'].append(node_compare)

        # Compare all ressources URLs
        to_return['ressources'] = {}
        _settings: Optional[CompareSettings]
        if settings:
            # cleanup the settings
            _ignore_domains = set(settings['ressources_ignore_domains'] if settings.get('ressources_ignore_domains') else [])
            _ignore_regexes = set(settings['ressources_ignore_regexes'] if settings.get('ressources_ignore_regexes') else [])
            _settings = {
                'ressources_ignore_domains': tuple(_ignore_domains),
                'ressources_ignore_regexes': tuple(_ignore_regexes)
            }
        else:
            _settings = None
        ressources_left = {url for url, hostname in left['ressources']
                           if not _settings
                           or (not hostname.endswith(_settings['ressources_ignore_domains'])
                               and not any(fnmatch.fnmatch(url, regex) for regex in _settings['ressources_ignore_regexes']))}
        ressources_right = {url for url, hostname in right['ressources']
                            if not _settings
                            or (not hostname.endswith(_settings['ressources_ignore_domains'])
                                and not any(fnmatch.fnmatch(url, regex) for regex in _settings['ressources_ignore_regexes']))}
        if present_in_both := ressources_left & ressources_right:
            to_return['ressources']['both'] = sorted(present_in_both)
        if present_left := ressources_left - ressources_right:
            different = True
            to_return['ressources']['left'] = sorted(present_left)
        if present_right := ressources_right - ressources_left:
            different = True
            to_return['ressources']['right'] = sorted(present_right)

        # IP/ASN checks - Note: there is the IP in the HAR, and the ones resolved manually - if the IP is different, but part of the list, it's cool
        # For each node up to the landing page
        #   Compare IPs
        #   Compare ASNs
        return different, to_return
