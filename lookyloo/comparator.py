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

    def compare_nodes(self, one, two, /) -> Dict[str, Any]:
        to_return = {}
        # URL
        if one.name != two.name:
            to_return['url'] = {'message': 'The nodes have different URLs.',
                                'details': [one.name, two.name]}
            # Hostname
            if one.hostname != two.hostname:
                to_return['hostname'] = {'message': 'The nodes have different hostnames.',
                                         'details': [one.hostname, two.hostname]}
            else:
                to_return['hostname'] = {'message': 'The nodes have the same hostname.',
                                         'details': one.hostname}
        else:
            to_return['url'] = {'message': 'The nodes have the same URL.',
                                'details': one.name}
        # IP in HAR
        if one.ip_address != two.ip_address:
            to_return['ip'] = {'message': 'The nodes load content from different IPs.',
                               'details': [str(one.ip_address), str(two.ip_address)]}
        else:
            to_return['ip'] = {'message': 'The nodes load content from the same IP.',
                               'details': str(one.ip_address)}

        # IPs in hostnode + ASNs
        return to_return

    def compare_captures(self, capture_one, capture_two, /) -> Dict[str, Any]:
        if capture_one not in self._captures_index:
            raise MissingUUID(f'{capture_one} does not exists.')
        if capture_two not in self._captures_index:
            raise MissingUUID(f'{capture_two} does not exists.')

        to_return: Dict[str, Dict[str, Union[str,
                                             List[Union[str, Dict[str, Any]]],
                                             Dict[str, Union[int, str,
                                                             List[Union[int, str, Dict[str, Any]]]]]]]] = {}
        one = self._captures_index[capture_one]
        two = self._captures_index[capture_two]
        # Compare initial URL (first entry in HAR)
        if one.tree.root_url != two.tree.root_url:
            to_return['root_url'] = {'message': 'The captures are for different URLs.',
                                     'details': [one.tree.root_url, two.tree.root_url]}
        else:
            to_return['root_url'] = {'message': 'The captures are the same URL.',
                                     'details': one.tree.root_url}

        # Compare landing page (URL in browser)
        if one.tree.root_hartree.har.final_redirect != two.tree.root_hartree.har.final_redirect:
            to_return['final_url'] = {'message': 'The landing page is different.',
                                      'details': [one.tree.root_hartree.har.final_redirect, two.tree.root_hartree.har.final_redirect]}
            #   => if different, check if the hostname is the same
            if one.tree.root_hartree.rendered_node.hostname != two.tree.root_hartree.rendered_node.hostname:
                to_return['final_hostname'] = {'message': 'The hostname of the rendered page is different.',
                                               'details': [one.tree.root_hartree.rendered_node.hostname, two.tree.root_hartree.rendered_node.hostname]}
            else:
                to_return['final_hostname'] = {'message': 'The hostname of the rendered page is the same.',
                                               'details': one.tree.root_hartree.rendered_node.hostname}
        else:
            to_return['final_url'] = {'message': 'The landing page is the same.',
                                      'details': one.tree.root_hartree.har.final_redirect}

        if one.tree.root_hartree.rendered_node.response['status'] != two.tree.root_hartree.rendered_node.response['status']:
            to_return['final_status_code'] = {'message': 'The status code of the rendered page is different.',
                                              'details': [one.tree.root_hartree.rendered_node.response['status'], two.tree.root_hartree.rendered_node.response['status']]}
        else:
            to_return['final_status_code'] = {'message': 'The status code of the rendered page is the same.',
                                              'details': one.tree.root_hartree.rendered_node.response['status']}

        to_return['redirects'] = {'length': {}, 'nodes': []}
        if len(one.tree.redirects) != len(two.tree.redirects):
            to_return['redirects']['length'] = {'message': 'The captures have a different amount of redirects',
                                                'details': [len(one.tree.redirects), len(two.tree.redirects)]}
        else:
            to_return['redirects']['length'] = {'message': 'The captures have the same number of redirects',
                                                'details': len(one.tree.redirects)}

        # Compare chain of redirects
        redirect_nodes_one = [a for a in reversed(one.tree.root_hartree.rendered_node.get_ancestors())] + [one.tree.root_hartree.rendered_node]
        redirect_nodes_two = [a for a in reversed(two.tree.root_hartree.rendered_node.get_ancestors())] + [two.tree.root_hartree.rendered_node]
        for redirect_one, redirect_two in zip(redirect_nodes_one, redirect_nodes_two):
            if isinstance(to_return['redirects']['nodes'], list):
                to_return['redirects']['nodes'].append(self.compare_nodes(redirect_one, redirect_two))

        # IP/ASN checks - Note: there is the IP in the HAR, and the ones resolved manually - if the IP is different, but part of the list, it's cool
        # For each node up to the landing page
        #   Compare IPs
        #   Compare ASNs
        return to_return
