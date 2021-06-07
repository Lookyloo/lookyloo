#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
from typing import Dict, Any

from flask import request, Response
import flask_login  # type: ignore
from flask_restx import Namespace, Resource, fields, abort  # type: ignore
from werkzeug.security import check_password_hash

from lookyloo.lookyloo import Lookyloo

from .helpers import src_request_ip, load_user_from_request, build_users_table

api = Namespace('GenericAPI', description='Generic Lookyloo API', path='/')


lookyloo: Lookyloo = Lookyloo()


def api_auth_check(method):
    if flask_login.current_user.is_authenticated or load_user_from_request(request):
        return method
    abort(403, 'Authentication required.')


token_request_fields = api.model('AuthTokenFields', {
    'username': fields.String(description="Your username", required=True),
    'password': fields.String(description="Your password", required=True),
})


@api.route('/json/get_token')
@api.doc(description='Get the API token required for authenticated calls')
class AuthToken(Resource):

    users_table = build_users_table()

    @api.param('username', 'Your username')
    @api.param('password', 'Your password')
    def get(self):
        username = request.args['username'] if request.args.get('username') else False
        password = request.args['password'] if request.args.get('password') else False
        if username in self.users_table and check_password_hash(self.users_table[username]['password'], password):
            return {'authkey': self.users_table[username]['authkey']}
        return {'error': 'User/Password invalid.'}

    @api.doc(body=token_request_fields)
    def post(self):
        auth: Dict = request.get_json(force=True)
        if 'username' in auth and 'password' in auth:  # Expected keys in json
            if (auth['username'] in self.users_table
                    and check_password_hash(self.users_table[auth['username']]['password'], auth['password'])):
                return {'authkey': self.users_table[auth['username']]['authkey']}
        return {'error': 'User/Password invalid.'}


@api.route('/json/<string:tree_uuid>/status')
@api.doc(description='Get the status of a capture',
         params={'tree_uuid': 'The UUID of the capture'})
class CaptureStatusQuery(Resource):
    def get(self, tree_uuid: str):
        return {'status_code': lookyloo.get_capture_status(tree_uuid)}


@api.route('/json/<string:tree_uuid>/redirects')
@api.doc(description='Get all the redirects of a capture',
         params={'tree_uuid': 'The UUID of the capture'})
class CaptureRedirects(Resource):
    def get(self, tree_uuid: str):
        cache = lookyloo.capture_cache(tree_uuid)
        if not cache:
            return {'error': 'UUID missing in cache, try again later.'}

        to_return: Dict[str, Any] = {'response': {'url': cache.url, 'redirects': []}}
        if not cache.redirects:
            to_return['response']['info'] = 'No redirects'
            return to_return
        if cache.incomplete_redirects:
            # Trigger tree build, get all redirects
            lookyloo.get_crawled_tree(tree_uuid)
            cache = lookyloo.capture_cache(tree_uuid)
            if cache:
                to_return['response']['redirects'] = cache.redirects
        else:
            to_return['response']['redirects'] = cache.redirects

        return to_return


@api.route('/json/<string:tree_uuid>/misp_export')
@api.doc(description='Get an export of the capture in MISP format',
         params={'tree_uuid': 'The UUID of the capture'})
class MISPExport(Resource):
    def get(self, tree_uuid: str):
        with_parents = request.args.get('with_parents')
        event = lookyloo.misp_export(tree_uuid, True if with_parents else False)
        if isinstance(event, dict):
            return event

        to_return = []
        for e in event:
            to_return.append(e.to_json(indent=2))
        return to_return


misp_push_fields = api.model('MISPPushFields', {
    'allow_duplicates': fields.Integer(description="Push the event even if it is already present on the MISP instance",
                                       example=0, min=0, max=1),
    'with_parents': fields.Integer(description="Also push the parents of the capture (if any)",
                                   example=0, min=0, max=1),
})


@api.route('/json/<string:tree_uuid>/misp_push')
@api.doc(description='Push an event to a pre-configured MISP instance',
         params={'tree_uuid': 'The UUID of the capture'},
         security='apikey')
class MISPPush(Resource):
    method_decorators = [api_auth_check]

    @api.param('with_parents', 'Also push the parents of the capture (if any)')
    @api.param('allow_duplicates', 'Push the event even if it is already present on the MISP instance')
    def get(self, tree_uuid: str):
        with_parents = True if request.args.get('with_parents') else False
        allow_duplicates = True if request.args.get('allow_duplicates') else False
        to_return: Dict = {}
        if not lookyloo.misp.available:
            to_return['error'] = 'MISP module not available.'
        elif not lookyloo.misp.enable_push:
            to_return['error'] = 'Push not enabled in MISP module.'
        else:
            event = lookyloo.misp_export(tree_uuid, with_parents)
            if isinstance(event, dict):
                to_return['error'] = event
            else:
                new_events = lookyloo.misp.push(event, allow_duplicates)
                if isinstance(new_events, dict):
                    to_return['error'] = new_events
                else:
                    events_to_return = []
                    for e in new_events:
                        events_to_return.append(e.to_json(indent=2))
                    return events_to_return

        return to_return

    @api.doc(body=misp_push_fields)
    def post(self, tree_uuid: str):
        parameters: Dict = request.get_json(force=True)
        with_parents = True if parameters.get('with_parents') else False
        allow_duplicates = True if parameters.get('allow_duplicates') else False

        to_return: Dict = {}
        if not lookyloo.misp.available:
            to_return['error'] = 'MISP module not available.'
        elif not lookyloo.misp.enable_push:
            to_return['error'] = 'Push not enabled in MISP module.'
        else:
            event = lookyloo.misp_export(tree_uuid, with_parents)
            if isinstance(event, dict):
                to_return['error'] = event
            else:
                new_events = lookyloo.misp.push(event, allow_duplicates)
                if isinstance(new_events, dict):
                    to_return['error'] = new_events
                else:
                    events_to_return = []
                    for e in new_events:
                        events_to_return.append(e.to_json(indent=2))
                    return events_to_return

        return to_return


@api.route('/json/hash_info/<h>')
@api.doc(description='Search for a ressource with a specific hash (sha512)',
         params={'h': 'The hash (sha512)'})
class HashInfo(Resource):
    def get(self, h: str):
        details, body = lookyloo.get_body_hash_full(h)
        if not details:
            return {'error': 'Unknown Hash.'}
        to_return: Dict[str, Any] = {'response': {'hash': h, 'details': details,
                                                  'body': base64.b64encode(body.getvalue()).decode()}}
        return to_return


url_info_fields = api.model('URLInfoFields', {
    'url': fields.String(description="The URL to search", required=True),
    'limit': fields.Integer(description="The maximal amount of captures to return", example=20),
})


@api.route('/json/url_info')
@api.doc(description='Search for a URL')
class URLInfo(Resource):

    @api.doc(body=url_info_fields)
    def post(self):
        to_query: Dict = request.get_json(force=True)
        occurrences = lookyloo.get_url_occurrences(to_query.pop('url'), **to_query)
        return occurrences


hostname_info_fields = api.model('HostnameInfoFields', {
    'hostname': fields.String(description="The hostname to search", required=True),
    'limit': fields.Integer(description="The maximal amount of captures to return", example=20),
})


@api.route('/json/hostname_info')
@api.doc(description='Search for a hostname')
class HostnameInfo(Resource):

    @api.doc(body=hostname_info_fields)
    def post(self):
        to_query: Dict = request.get_json(force=True)
        occurrences = lookyloo.get_hostname_occurrences(to_query.pop('hostname'), **to_query)
        return occurrences


@api.route('/json/stats')
@api.doc(description='Get the statistics of the lookyloo instance.')
class InstanceStats(Resource):
    def get(self):
        return lookyloo.get_stats()


submit_fields = api.model('SubmitFields', {
    'url': fields.String(description="The URL to capture", required=True),
    'listing': fields.Integer(description="Display the capture on the index", min=0, max=1, example=1),
    'user_agent': fields.String(description="User agent to use for the capture", example=''),
    'referer': fields.String(description="Referer to pass to the capture", example=''),
    'cookies': fields.String(description="JSON export of a list of cookies as exported from an other capture", example='')
})


@api.route('/submit')
class SubmitCapture(Resource):

    @api.doc(body=submit_fields)
    def post(self):
        if flask_login.current_user.is_authenticated:
            user = flask_login.current_user.get_id()
        else:
            user = src_request_ip(request)
        to_query: Dict = request.get_json(force=True)
        perma_uuid = lookyloo.enqueue_capture(to_query, source='api', user=user, authenticated=flask_login.current_user.is_authenticated)
        return Response(perma_uuid, mimetype='text/text')


@api.route('/json/<string:tree_uuid>/stats')
@api.doc(description='Get the statistics of the capture.')
class CaptureStats(Resource):
    def get(self, tree_uuid: str):
        return lookyloo.get_statistics(tree_uuid)
