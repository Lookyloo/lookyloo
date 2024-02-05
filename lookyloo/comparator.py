#!/usr/bin/env python3

from __future__ import annotations

import fnmatch
import logging

from typing import Any, TypedDict

from har2tree import URLNode

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .context import Context
from .capturecache import CapturesIndex
from .default import get_config, get_socket_path, LookylooException
from .exceptions import MissingUUID, TreeNeedsRebuild


class CompareSettings(TypedDict):
    '''The settings that can be passed to the compare method to filter out some differences'''

    ressources_ignore_domains: tuple[str, ...]
    ressources_ignore_regexes: tuple[str, ...]

    ignore_ips: bool


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
    def redis(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.redis_pool)

    def get_comparables_node(self, node: URLNode) -> dict[str, str]:
        to_return = {'url': node.name, 'hostname': node.hostname}
        if hasattr(node, 'ip_address'):
            to_return['ip_address'] = str(node.ip_address)
        return to_return

    def _compare_nodes(self, left: dict[str, str], right: dict[str, str], /, different: bool, ignore_ips: bool) -> tuple[bool, dict[str, Any]]:
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
        if not ignore_ips and left.get('ip_address') and right.get('ip_address'):
            if left['ip_address'] != right['ip_address']:
                different = True
                to_return['ip'] = {'message': 'The nodes load content from different IPs.',
                                   'details': [left['ip_address'], right['ip_address']]}
            else:
                to_return['ip'] = {'message': 'The nodes load content from the same IP.',
                                   'details': left['ip_address']}

        # IPs in hostnode + ASNs
        return different, to_return

    def get_comparables_capture(self, capture_uuid: str) -> dict[str, Any]:
        if capture_uuid not in self._captures_index:
            raise MissingUUID(f'{capture_uuid} does not exists.')

        capture = self._captures_index[capture_uuid]
        to_return: dict[str, Any]
        try:
            if capture.error:
                # The error on lookyloo is too verbose and contains the UUID of the capture, skip that.
                if "has an error: " in capture.error:
                    _, message = capture.error.split('has an error: ', 1)
                else:
                    message = capture.error
                to_return = {'error': message}
            else:
                to_return = {'root_url': capture.tree.root_url,
                             'final_url': capture.tree.root_hartree.har.final_redirect,
                             'final_hostname': capture.tree.root_hartree.rendered_node.hostname,
                             'final_status_code': capture.tree.root_hartree.rendered_node.response['status'],
                             'redirects': {'length': len(capture.tree.redirects)}}

                to_return['redirects']['nodes'] = [self.get_comparables_node(a) for a in list(reversed(capture.tree.root_hartree.rendered_node.get_ancestors())) + [capture.tree.root_hartree.rendered_node]]
                to_return['ressources'] = {(a.name, a.hostname) for a in capture.tree.root_hartree.rendered_node.traverse()}
        except TreeNeedsRebuild as e:
            self.logger.warning(f"The tree for {capture_uuid} couldn't be built.")
            to_return = {'error': str(e)}
        except LookylooException as e:
            to_return = {'error': str(e)}
        return to_return

    def compare_captures(self, capture_left: str, capture_right: str, /, *, settings: CompareSettings | None=None) -> tuple[bool, dict[str, Any]]:
        if capture_left not in self._captures_index:
            raise MissingUUID(f'{capture_left} does not exists.')
        if capture_right not in self._captures_index:
            raise MissingUUID(f'{capture_right} does not exists.')

        different: bool = False
        to_return: dict[str, dict[str,
                                  (str | list[str | dict[str, Any]]
                                   | dict[str, (int | str | list[int | str | dict[str, Any]])])]] = {}
        to_return['lookyloo_urls'] = {'left': f'https://{self.public_domain}/tree/{capture_left}',
                                      'right': f'https://{self.public_domain}/tree/{capture_right}'}
        left = self.get_comparables_capture(capture_left)
        right = self.get_comparables_capture(capture_right)
        if 'error' in left and 'error' in right:
            # both captures failed
            if left['error'] == right['error']:
                to_return['error'] = {'message': 'Both captures failed with the same error message.',
                                      'details': right['error']}
            else:
                different = True
                to_return['error'] = {'message': 'Both captures failed with different error messages',
                                      'details': [left['error'], right['error']]}

        elif 'error' in right:
            different = True
            to_return['error'] = {'message': 'Error in the most recent capture.',
                                  'details': ['The precedent capture worked fine', right['error']]}

        elif 'error' in left:
            different = True
            to_return['error'] = {'message': 'Error in the precedent capture.',
                                  'details': [left['error'], 'The most recent capture worked fine']}

        # Just to avoid to put everything below in a else
        if 'error' in to_return:
            return different, to_return

        # ------------------------- Compare working captures

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

        # Prepare settings
        _settings: CompareSettings | None
        if settings:
            # cleanup the settings
            _ignore_domains = set(settings['ressources_ignore_domains'] if settings.get('ressources_ignore_domains') else [])
            _ignore_regexes = set(settings['ressources_ignore_regexes'] if settings.get('ressources_ignore_regexes') else [])
            _settings = {
                'ressources_ignore_domains': tuple(_ignore_domains),
                'ressources_ignore_regexes': tuple(_ignore_regexes),
                'ignore_ips': bool(settings.get('ignore_ips'))
            }
        else:
            _settings = None

        # Compare chain of redirects
        for redirect_left, redirect_right in zip(right['redirects']['nodes'], left['redirects']['nodes']):
            if isinstance(to_return['redirects']['nodes'], list):  # NOTE always true, but makes mypy happy.
                different, node_compare = self._compare_nodes(redirect_left, redirect_right, different, _settings['ignore_ips'] if _settings is not None else False)
                to_return['redirects']['nodes'].append(node_compare)

        # Compare all ressources URLs
        ressources_left = {url for url, hostname in left['ressources']
                           if not _settings
                           or (not hostname.endswith(_settings['ressources_ignore_domains'])
                               and not any(fnmatch.fnmatch(url, regex) for regex in _settings['ressources_ignore_regexes']))}
        ressources_right = {url for url, hostname in right['ressources']
                            if not _settings
                            or (not hostname.endswith(_settings['ressources_ignore_domains'])
                                and not any(fnmatch.fnmatch(url, regex) for regex in _settings['ressources_ignore_regexes']))}

        to_return['ressources'] = {}
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
