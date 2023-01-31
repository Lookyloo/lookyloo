#!/usr/bin/env python3

import logging

from typing import Dict, Any, Union, List

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .context import Context
from .capturecache import CapturesIndex
from .default import get_config, get_socket_path
from .exceptions import MissingUUID


class Comparator():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('cache'), decode_responses=True)

        self.context = Context()
        self._captures_index = CapturesIndex(self.redis, self.context)

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool)

    def compare_nodes(self, left, right, /) -> Dict[str, Any]:
        to_return = {}
        # URL
        if left.name != right.name:
            to_return['url'] = {'message': 'The nodes have different URLs.',
                                'details': [left.name, right.name]}
            # Hostname
            if left.hostname != right.hostname:
                to_return['hostname'] = {'message': 'The nodes have different hostnames.',
                                         'details': [left.hostname, right.hostname]}
            else:
                to_return['hostname'] = {'message': 'The nodes have the same hostname.',
                                         'details': left.hostname}
        else:
            to_return['url'] = {'message': 'The nodes have the same URL.',
                                'details': left.name}
        # IP in HAR
        if left.ip_address != right.ip_address:
            to_return['ip'] = {'message': 'The nodes load content from different IPs.',
                               'details': [str(left.ip_address), str(right.ip_address)]}
        else:
            to_return['ip'] = {'message': 'The nodes load content from the same IP.',
                               'details': str(left.ip_address)}

        # IPs in hostnode + ASNs
        return to_return

    def compare_captures(self, capture_left, capture_right, /) -> Dict[str, Any]:
        if capture_left not in self._captures_index:
            raise MissingUUID(f'{capture_left} does not exists.')
        if capture_right not in self._captures_index:
            raise MissingUUID(f'{capture_right} does not exists.')

        to_return: Dict[str, Dict[str, Union[str,
                                             List[Union[str, Dict[str, Any]]],
                                             Dict[str, Union[int, str,
                                                             List[Union[int, str, Dict[str, Any]]]]]]]] = {}
        left = self._captures_index[capture_left]
        right = self._captures_index[capture_right]
        # Compare initial URL (first entry in HAR)
        if left.tree.root_url != right.tree.root_url:
            to_return['root_url'] = {'message': 'The captures are for different URLs.',
                                     'details': [left.tree.root_url, right.tree.root_url]}
        else:
            to_return['root_url'] = {'message': 'The captures are the same URL.',
                                     'details': left.tree.root_url}

        # Compare landing page (URL in browser)
        if left.tree.root_hartree.har.final_redirect != right.tree.root_hartree.har.final_redirect:
            to_return['final_url'] = {'message': 'The landing page is different.',
                                      'details': [left.tree.root_hartree.har.final_redirect, right.tree.root_hartree.har.final_redirect]}
            #   => if different, check if the hostname is the same
            if left.tree.root_hartree.rendered_node.hostname != right.tree.root_hartree.rendered_node.hostname:
                to_return['final_hostname'] = {'message': 'The hostname of the rendered page is different.',
                                               'details': [left.tree.root_hartree.rendered_node.hostname, right.tree.root_hartree.rendered_node.hostname]}
            else:
                to_return['final_hostname'] = {'message': 'The hostname of the rendered page is the same.',
                                               'details': left.tree.root_hartree.rendered_node.hostname}
        else:
            to_return['final_url'] = {'message': 'The landing page is the same.',
                                      'details': left.tree.root_hartree.har.final_redirect}

        if left.tree.root_hartree.rendered_node.response['status'] != right.tree.root_hartree.rendered_node.response['status']:
            to_return['final_status_code'] = {'message': 'The status code of the rendered page is different.',
                                              'details': [left.tree.root_hartree.rendered_node.response['status'], right.tree.root_hartree.rendered_node.response['status']]}
        else:
            to_return['final_status_code'] = {'message': 'The status code of the rendered page is the same.',
                                              'details': left.tree.root_hartree.rendered_node.response['status']}

        to_return['redirects'] = {'length': {}, 'nodes': []}
        if len(left.tree.redirects) != len(right.tree.redirects):
            to_return['redirects']['length'] = {'message': 'The captures have a different amount of redirects',
                                                'details': [len(left.tree.redirects), len(right.tree.redirects)]}
        else:
            to_return['redirects']['length'] = {'message': 'The captures have the same number of redirects',
                                                'details': len(left.tree.redirects)}

        # Compare chain of redirects
        redirect_nodes_left = [a for a in reversed(left.tree.root_hartree.rendered_node.get_ancestors())] + [left.tree.root_hartree.rendered_node]
        redirect_nodes_right = [a for a in reversed(right.tree.root_hartree.rendered_node.get_ancestors())] + [right.tree.root_hartree.rendered_node]
        for redirect_left, redirect_right in zip(redirect_nodes_left, redirect_nodes_right):
            if isinstance(to_return['redirects']['nodes'], list):
                to_return['redirects']['nodes'].append(self.compare_nodes(redirect_left, redirect_right))

        # Compare all ressources URLs
        to_return['ressources'] = {}
        ressources_left = {a.name for a in left.tree.root_hartree.rendered_node.traverse()}
        ressources_right = {a.name for a in right.tree.root_hartree.rendered_node.traverse()}
        if present_in_both := ressources_left & ressources_right:
            to_return['ressources']['both'] = sorted(present_in_both)
        if present_left := ressources_left - ressources_right:
            to_return['ressources']['left'] = sorted(present_left)
        if present_right := ressources_right - ressources_left:
            to_return['ressources']['right'] = sorted(present_right)

        # IP/ASN checks - Note: there is the IP in the HAR, and the ones resolved manually - if the IP is different, but part of the list, it's cool
        # For each node up to the landing page
        #   Compare IPs
        #   Compare ASNs
        return to_return
