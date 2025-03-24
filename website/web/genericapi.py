#!/usr/bin/env python3

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import logging.config

from datetime import datetime
from io import BytesIO
from typing import Any
from uuid import uuid4
from zipfile import ZipFile

import flask_login  # type: ignore[import-untyped]
from flask import request, send_file, Response, make_response
from flask_restx import Namespace, Resource, fields, abort  # type: ignore[import-untyped]
from werkzeug.security import check_password_hash

from lacuscore import CaptureStatus as CaptureStatusCore, CaptureSettingsError
from pylacus import CaptureStatus as CaptureStatusPy
from lookyloo import CaptureSettings, Lookyloo
from lookyloo.default import get_config
from lookyloo.comparator import Comparator
from lookyloo.exceptions import MissingUUID, NoValidHarFile, ModuleError
from lookyloo.helpers import load_user_config

from .helpers import (build_users_table, load_user_from_request, src_request_ip,
                      get_lookyloo_instance, get_indexing)

api = Namespace('GenericAPI', description='Generic Lookyloo API', path='/')

lookyloo: Lookyloo = get_lookyloo_instance()
comparator: Comparator = Comparator()
logging.config.dictConfig(get_config('logging'))


def api_auth_check(method):  # type: ignore[no-untyped-def]
    if flask_login.current_user.is_authenticated or load_user_from_request(request):
        return method
    abort(403, 'Authentication required.')


token_request_fields = api.model('AuthTokenFields', {
    'username': fields.String(description="Your username", required=True),
    'password': fields.String(description="Your password", required=True),
})


@api.errorhandler(NoValidHarFile)  # type: ignore[misc]
def handle_no_HAR_file_exception(error: Any) -> Response:
    '''The capture has no HAR file, it failed for some reason.'''
    return make_response({'message': str(error)}, 400)


@api.errorhandler(CaptureSettingsError)  # type: ignore[misc]
def handle_pydandic_validation_exception(error: CaptureSettingsError) -> Response:
    '''Return the validation error message and 400 status code'''
    if error.pydantic_validation_errors:
        return make_response({'message': 'Unable to validate capture settings.',
                              'details': error.pydantic_validation_errors.errors()}, 400)
    return make_response({'message': str(error)}, 400)


@api.route('/json/get_user_config')
@api.doc(description='Get the configuration of the user (if any)', security='apikey')
class UserConfig(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def get(self) -> dict[str, Any] | None | Response:
        if not flask_login.current_user.is_authenticated:
            return make_response({'error': 'User not authenticated.'}, 401)
        return load_user_config(flask_login.current_user.get_id())


@api.route('/json/get_token')
@api.doc(description='Get the API token required for authenticated calls')
class AuthToken(Resource):  # type: ignore[misc]

    users_table = build_users_table()

    @api.param('username', 'Your username')  # type: ignore[misc]
    @api.param('password', 'Your password')  # type: ignore[misc]
    def get(self) -> Response:
        username: str | None = request.args['username'] if request.args.get('username') else None
        password: str | None = request.args['password'] if request.args.get('password') else None
        if username and password and username in self.users_table and check_password_hash(self.users_table[username]['password'], password):
            return make_response({'authkey': self.users_table[username]['authkey']})
        return make_response({'error': 'User/Password invalid.'}, 401)

    @api.doc(body=token_request_fields)  # type: ignore[misc]
    def post(self) -> Response:
        auth: dict[str, Any] = request.get_json(force=True)
        if 'username' in auth and 'password' in auth:  # Expected keys in json
            if (auth['username'] in self.users_table
                    and check_password_hash(self.users_table[auth['username']]['password'], auth['password'])):
                return make_response({'authkey': self.users_table[auth['username']]['authkey']})
        return make_response({'error': 'User/Password invalid.'}, 401)


@api.route('/json/<string:capture_uuid>/status')
@api.doc(description='Get the status of a capture',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureStatusQuery(Resource):  # type: ignore[misc]

    @api.param('with_error', 'Add the error message of the capture (if there is one)')  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        with_error: bool = True if request.args.get('with_error') else False
        status_code = lookyloo.get_capture_status(capture_uuid)
        to_return: dict[str, Any] = {'status_code': status_code}
        if status_code in [CaptureStatusCore.DONE, CaptureStatusPy.DONE] and with_error:
            cache = lookyloo.capture_cache(capture_uuid)
            if cache and cache.error:
                to_return['error'] = cache.error
        return make_response(to_return)


@api.route('/json/<string:capture_uuid>/hostnames')
@api.doc(description='Get all the hostnames of all the resources of a capture',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureHostnames(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        cache = lookyloo.capture_cache(capture_uuid)
        if not cache:
            return make_response({'error': 'UUID missing in cache, try again later and check the status first.'}, 400)
        return make_response({'response': {'hostnames': list(lookyloo.get_hostnames(capture_uuid))}})


@api.route('/json/<string:capture_uuid>/urls')
@api.doc(description='Get all the URLs of all the resources of a capture',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureURLs(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        cache = lookyloo.capture_cache(capture_uuid)
        if not cache:
            return make_response({'error': 'UUID missing in cache, try again later and check the status first.'}, 400)
        return make_response({'response': {'urls': list(lookyloo.get_urls(capture_uuid))}})


@api.route('/json/<string:capture_uuid>/hashes')
@api.doc(description='Get all the hashes of all the resources of a capture',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureHashes(Resource):  # type: ignore[misc]
    # Note: shake algos require a length for the digest, discarding them.
    supported_hash_algos = [algo for algo in hashlib.algorithms_available if not algo.startswith('shake')]

    # NOTE: the SHA512 hashes are pre-computed in the tree, anything else must be computed on the spot
    #       so we return the SHA512 hashes by default

    @api.param('algorithm', default='sha512', description=f'Algorithm of the hashes (default: sha512). Supported options: {", ".join(supported_hash_algos)}')  # type: ignore[misc]
    @api.param('hashes_only', default=1, description='If 1 (default), only returns a list hashes instead of a dictionary of hashes with their respective URLs..')  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        cache = lookyloo.capture_cache(capture_uuid)
        if not cache:
            return make_response({'error': 'UUID missing in cache, try again later and check the status first.'}, 400)

        algorithm = request.args['algorithm'].lower() if request.args.get('algorithm') else 'sha512'
        hashes_only = False if 'hashes_only' in request.args and request.args['hashes_only'] in [0, '0'] else True
        if algorithm == 'sha512' and hashes_only:
            to_return: dict[str, Any] = {'response': {'hashes': list(lookyloo.get_hashes(capture_uuid))}}
        else:
            hashes = lookyloo.get_hashes_with_context(capture_uuid, algorithm=algorithm, urls_only=True)
            to_return = {'response': {'hashes': list(hashes.keys())}}
            if not hashes_only:
                to_return['response']['hashes_with_urls'] = {h: list(urls) for h, urls in hashes.items()}
        return make_response(to_return)


@api.route('/json/<string:capture_uuid>/redirects')
@api.doc(description='Get all the redirects of a capture',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureRedirects(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        cache = lookyloo.capture_cache(capture_uuid)
        if not cache:
            return make_response({'error': 'UUID missing in cache, try again later and check the status first.'}, 400)

        to_return: dict[str, Any] = {}
        try:
            to_return = {'response': {'url': cache.url,
                                      'redirects': cache.redirects if cache.redirects else []}}
            if not cache.redirects:
                to_return['response']['info'] = 'No redirects'
        except Exception as e:
            if cache and hasattr(cache, 'error'):
                to_return['error'] = cache.error
            else:
                to_return['error'] = str(e)
        return make_response(to_return)


@api.route('/json/<string:capture_uuid>/misp_export')
@api.doc(description='Get an export of the capture in MISP format',
         params={'capture_uuid': 'The UUID of the capture'})
class MISPExport(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        with_parents = request.args.get('with_parents')
        try:
            event = lookyloo.misp_export(capture_uuid, True if with_parents else False)
        except ModuleError as e:
            return make_response({'error': str(e)}, 500)
        if isinstance(event, dict):
            return make_response(event)

        to_return = []
        for ev in event:
            to_return.append(json.loads(ev.to_json()))
        return make_response(to_return)


misp_push_fields = api.model('MISPPushFields', {
    'allow_duplicates': fields.Integer(description="Push the event even if it is already present on the MISP instance",
                                       example=0, min=0, max=1),
    'with_parents': fields.Integer(description="Also push the parents of the capture (if any)",
                                   example=0, min=0, max=1),
})


@api.route('/json/<string:capture_uuid>/misp_push')
@api.route('/json/<string:capture_uuid>/misp_push/<string:instance_name>')
@api.doc(description='Push an event to a pre-configured MISP instance',
         params={'capture_uuid': 'The UUID of the capture'},
         security='apikey')
class MISPPush(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @api.param('with_parents', 'Also push the parents of the capture (if any)')  # type: ignore[misc]
    @api.param('allow_duplicates', 'Push the event even if it is already present on the MISP instance')  # type: ignore[misc]
    def get(self, capture_uuid: str, instance_name: str | None=None) -> Response:
        with_parents = True if request.args.get('with_parents') else False
        allow_duplicates = True if request.args.get('allow_duplicates') else False

        if instance_name is None:
            misp = lookyloo.misps.default_misp
        elif lookyloo.misps.get(instance_name) is not None:
            misp = lookyloo.misps[instance_name]
        else:
            return make_response({'error': f'MISP instance "{instance_name}" does not exists.'}, 400)

        to_return: dict[str, Any] = {}
        if not misp.available:
            to_return['error'] = 'MISP module not available.'
        elif not misp.enable_push:
            to_return['error'] = 'Push not enabled in MISP module.'
        else:
            event = lookyloo.misp_export(capture_uuid, with_parents)
            if isinstance(event, dict):
                to_return['error'] = event
            else:
                new_events = misp.push(event, allow_duplicates)
                if isinstance(new_events, dict):
                    to_return['error'] = new_events
                else:
                    events_to_return = []
                    for e in new_events:
                        events_to_return.append(json.loads(e.to_json()))
                    return make_response(events_to_return)

        return make_response(to_return)

    @api.doc(body=misp_push_fields)  # type: ignore[misc]
    def post(self, capture_uuid: str, instance_name: str | None=None) -> Response:
        parameters: dict[str, Any] = request.get_json(force=True)
        with_parents = True if parameters.get('with_parents') else False
        allow_duplicates = True if parameters.get('allow_duplicates') else False
        if instance_name is None:
            misp = lookyloo.misps.default_misp
        elif lookyloo.misps.get(instance_name) is not None:
            misp = lookyloo.misps[instance_name]
        else:
            return make_response({'error': f'MISP instance "{instance_name}" does not exists.'}, 400)

        to_return: dict[str, Any] = {}
        if not misp.available:
            to_return['error'] = 'MISP module not available.'
        elif not misp.enable_push:
            to_return['error'] = 'Push not enabled in MISP module.'
        else:
            event = lookyloo.misp_export(capture_uuid, with_parents)
            if isinstance(event, dict):
                to_return['error'] = event
            else:
                new_events = misp.push(event, allow_duplicates)
                if isinstance(new_events, dict):
                    to_return['error'] = new_events
                else:
                    events_to_return = []
                    for e in new_events:
                        events_to_return.append(json.loads(e.to_json()))
                    return make_response(events_to_return)

        return make_response(to_return)


trigger_modules_fields = api.model('TriggerModulesFields', {
    'force': fields.Boolean(description="Force trigger the modules, even if the results are already cached.",
                            default=False, required=False),
})


@api.route('/json/<string:capture_uuid>/trigger_modules')
@api.doc(description='Trigger all the available 3rd party modules on the given capture',
         params={'capture_uuid': 'The UUID of the capture'})
class TriggerModules(Resource):  # type: ignore[misc]
    @api.doc(body=trigger_modules_fields)  # type: ignore[misc]
    def post(self, capture_uuid: str) -> Response:
        parameters: dict[str, Any] = request.get_json(force=True)
        force = True if parameters.get('force') else False
        return make_response(lookyloo.trigger_modules(capture_uuid,
                                                      force=force, auto_trigger=False,
                                                      as_admin=flask_login.current_user.is_authenticated))


@api.route('/json/<string:capture_uuid>/modules')
@api.doc(description='Get responses from the 3rd party modules',
         params={'capture_uuid': 'The UUID of the capture'})
class ModulesResponse(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        return make_response(lookyloo.get_modules_responses(capture_uuid))


@api.route('/json/hash_info/<h>')
@api.doc(description='Search for a ressource with a specific hash (sha512)',
         params={'h': 'The hash (sha512)'})
class HashInfo(Resource):  # type: ignore[misc]
    def get(self, h: str) -> Response:
        if uuids := get_indexing(flask_login.current_user).get_hash_uuids(h):
            # got UUIDs for this hash
            capture_uuid, urlnode_uuid = uuids
            if ressource := lookyloo.get_ressource(capture_uuid, urlnode_uuid, h):
                filename, body, mimetype = ressource
                details = get_indexing(flask_login.current_user).get_body_hash_urlnodes(h)
                return make_response({'response': {'hash': h, 'details': details,
                                      'body': base64.b64encode(body.getvalue()).decode()}})
            return make_response({'error': 'Unable to get ressource'}, 400)
        return make_response({'error': 'Unknown Hash.'}, 404)


def get_url_occurrences(url: str, /, limit: int=20, cached_captures_only: bool=True) -> list[dict[str, Any]]:
    '''Get the most recent captures and URL nodes where the URL has been seen.'''
    captures = lookyloo.sorted_capture_cache(
        get_indexing(flask_login.current_user).get_captures_url(url, offset=0, limit=limit),
        cached_captures_only=cached_captures_only)

    to_return: list[dict[str, Any]] = []
    for capture in captures:
        ct = lookyloo.get_crawled_tree(capture.uuid)
        to_append: dict[str, str | dict[str, Any]] = {'capture_uuid': capture.uuid,
                                                      'start_timestamp': capture.timestamp.isoformat(),
                                                      'title': capture.title}
        urlnodes: dict[str, dict[str, str]] = {}
        for urlnode in ct.root_hartree.url_tree.search_nodes(name=url):
            urlnodes[urlnode.uuid] = {'start_time': urlnode.start_time.isoformat(),
                                      'hostnode_uuid': urlnode.hostnode_uuid}
            if hasattr(urlnode, 'body_hash'):
                urlnodes[urlnode.uuid]['hash'] = urlnode.body_hash
        to_append['urlnodes'] = urlnodes
        to_return.append(to_append)
    return to_return


url_info_fields = api.model('URLInfoFields', {
    'url': fields.String(description="The URL to search", required=True),
    'limit': fields.Integer(description="The maximal amount of captures to return", example=20),
    'cached_captures_only': fields.Boolean(description="If false, re-cache the missing captures (can take a while)", default=True),
})


@api.route('/json/url_info')
@api.doc(description='Search for a URL')
class URLInfo(Resource):  # type: ignore[misc]

    @api.doc(body=url_info_fields)  # type: ignore[misc]
    def post(self) -> Response:
        to_query: dict[str, Any] = request.get_json(force=True)
        return make_response(get_url_occurrences(to_query.pop('url'), **to_query))


def get_hostname_occurrences(hostname: str, /, with_urls_occurrences: bool=False, limit: int=20, cached_captures_only: bool=True) -> list[dict[str, Any]]:
    '''Get the most recent captures and URL nodes where the hostname has been seen.'''
    _, entries = get_indexing(flask_login.current_user).get_captures_hostname(hostname, offset=0, limit=limit)
    captures = lookyloo.sorted_capture_cache(entries, cached_captures_only=cached_captures_only)

    to_return: list[dict[str, Any]] = []
    for capture in captures:
        ct = lookyloo.get_crawled_tree(capture.uuid)
        to_append: dict[str, str | list[Any] | dict[str, Any]] = {
            'capture_uuid': capture.uuid,
            'start_timestamp': capture.timestamp.isoformat(),
            'title': capture.title}
        hostnodes: list[str] = []
        if with_urls_occurrences:
            urlnodes: dict[str, dict[str, str]] = {}
        for hostnode in ct.root_hartree.hostname_tree.search_nodes(name=hostname):
            hostnodes.append(hostnode.uuid)
            if with_urls_occurrences:
                for urlnode in hostnode.urls:
                    urlnodes[urlnode.uuid] = {'start_time': urlnode.start_time.isoformat(),
                                              'url': urlnode.name,
                                              'hostnode_uuid': urlnode.hostnode_uuid}
                    if hasattr(urlnode, 'body_hash'):
                        urlnodes[urlnode.uuid]['hash'] = urlnode.body_hash
            to_append['hostnodes'] = hostnodes
            if with_urls_occurrences:
                to_append['urlnodes'] = urlnodes
            to_return.append(to_append)
    return to_return


hostname_info_fields = api.model('HostnameInfoFields', {
    'hostname': fields.String(description="The hostname to search", required=True),
    'limit': fields.Integer(description="The maximal amount of captures to return", example=20),
    'cached_captures_only': fields.Boolean(description="If false, re-cache the missing captures (can take a while)", default=True),
})


@api.route('/json/hostname_info')
@api.doc(description='Search for a hostname')
class HostnameInfo(Resource):  # type: ignore[misc]

    @api.doc(body=hostname_info_fields)  # type: ignore[misc]
    def post(self) -> Response:
        to_query: dict[str, Any] = request.get_json(force=True)
        return make_response(get_hostname_occurrences(to_query.pop('hostname'), **to_query))


@api.route('/json/stats')
@api.doc(description='Get the statistics of the lookyloo instance.')
class InstanceStats(Resource):  # type: ignore[misc]
    def get(self) -> Response:
        return make_response(lookyloo.get_stats())


@api.route('/json/devices')
@api.doc(description='Get the list of devices pre-configured on the platform')
class Devices(Resource):  # type: ignore[misc]

    def get(self) -> Response:
        return make_response(lookyloo.get_playwright_devices())


@api.route('/json/<string:capture_uuid>/stats')
@api.doc(description='Get the statistics of the capture.',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureStats(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        return make_response(lookyloo.get_statistics(capture_uuid))


@api.route('/json/<string:capture_uuid>/info')
@api.doc(description='Get basic information about the capture.',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureInfo(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        success, info = lookyloo.get_info(capture_uuid)
        if success:
            return make_response(info)
        return make_response(info, 404)


@api.route('/json/<string:capture_uuid>/cookies')
@api.doc(description='Get the complete cookie jar created during the capture.',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureCookies(Resource):  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        success, cookies = lookyloo.get_cookies(capture_uuid)
        if success and cookies.getvalue():
            return make_response(json.loads(cookies.getvalue()))
        return make_response({'error': 'No cookies'}, 404)


@api.route('/json/<string:capture_uuid>/report')
@api.doc(description='Reports the url by sending an email to the investigation team',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureReport(Resource):  # type: ignore[misc]
    @api.param('email', 'Email of the reporter, used by the analyst to get in touch.')  # type: ignore[misc]
    @api.param('comment', 'Description of the URL, will be given to the analyst.')  # type: ignore[misc]
    def post(self, capture_uuid: str) -> Response:
        parameters: dict[str, Any] = request.get_json(force=True)
        return make_response(lookyloo.send_mail(capture_uuid, parameters.get('email', ''), parameters.get('comment')))


@api.route('/json/upload')
@api.doc(description='Submits a capture from another instance')
class UploadCapture(Resource):  # type: ignore[misc]
    def post(self) -> Response:
        parameters: dict[str, Any] = request.get_json(force=True)
        listing = True if parameters.get('listing') else False
        har: dict[str, Any] | None = None
        html: str | None = None
        last_redirected_url: str | None = None
        screenshot: bytes | None = None

        if 'har_file' in parameters and parameters.get('har_file'):
            uuid = str(uuid4())
            try:
                har_decoded = base64.b64decode(parameters['har_file'])
                try:
                    # new format
                    har_uncompressed = gzip.decompress(har_decoded)
                except gzip.BadGzipFile:
                    # old format
                    har_uncompressed = har_decoded

                har = json.loads(har_uncompressed)
                last_redirected_url = parameters.get('landing_page')
                if 'screenshot_file' in parameters:
                    screenshot = base64.b64decode(parameters['screenshot_file'])
                if 'html_file' in parameters:
                    html = base64.b64decode(parameters['html_file']).decode()
                lookyloo.store_capture(uuid, is_public=listing, har=har,
                                       last_redirected_url=last_redirected_url,
                                       png=screenshot, html=html)
            except Exception as e:
                return make_response({'error': f'Unable to process the upload: {e}'}, 400)
            return make_response({'uuid': uuid})

        elif 'full_capture' in parameters and parameters.get('full_capture'):
            try:
                zipped_capture = base64.b64decode(parameters['full_capture'].encode())
            except Exception:
                return make_response({'error': 'Invalid base64-encoding'}, 400)
            full_capture_file = BytesIO(zipped_capture)
            uuid, messages = lookyloo.unpack_full_capture_archive(full_capture_file, listing=listing)
            if 'errors' in messages and messages['errors']:
                return make_response({'error': ', '.join(messages['errors'])}, 400)
            return make_response({'uuid': uuid, 'messages': messages})
        else:
            # Treat it as a direct export from Lacus, requires at a bare minimum a HAR
            if 'har' not in parameters or not parameters.get('har'):
                return make_response({'error': 'Missing HAR file'}, 400)
            try:
                uuid = str(uuid4())
                # The following parameters are base64 encoded and need to be decoded first
                if 'png' in parameters and parameters['png']:
                    parameters['png'] = base64.b64decode(parameters['png'])
                if 'downloaded_file' in parameters and parameters['downloaded_file']:
                    parameters['downloaded_file'] = base64.b64decode(parameters['downloaded_file'])
                if 'potential_favicons' in parameters and parameters['potential_favicons']:
                    parameters['potential_favicons'] = {base64.b64decode(f) for f in parameters['potential_favicons']}

                lookyloo.store_capture(
                    uuid, is_public=listing,
                    downloaded_filename=parameters.get('downloaded_filename'),
                    downloaded_file=parameters.get('downloaded_file'),
                    error=parameters.get('error'), har=parameters.get('har'),
                    png=parameters.get('png'), html=parameters.get('html'),
                    last_redirected_url=parameters.get('last_redirected_url'),
                    cookies=parameters.get('cookies'),
                    potential_favicons=parameters.get('potential_favicons'),
                )
                return make_response({'uuid': uuid})
            except Exception as e:
                return make_response({'error': f'Unable to load capture results in lacus format: {e}'}, 400)


auto_report_model = api.model('AutoReportModel', {
    'email': fields.String(description="Email of the reporter, used by the analyst to get in touch.", example=''),
    'comment': fields.String(description="Description of the URL, will be given to the analyst.", example='')
})

submit_fields_post = api.model('SubmitFieldsPost', {
    'url': fields.Url(description="The URL to capture", example=''),
    'document': fields.String(description="A base64 encoded document, it can be anything a browser can display.", example=''),
    'document_name': fields.String(description="The name of the document.", example=''),
    'listing': fields.Integer(description="Display the capture on the index", min=0, max=1, example=1),
    'allow_tracking': fields.Integer(description="Attempt to let the website violate your privacy", min=0, max=1, example=0),
    'java_script_enabled': fields.Integer(description="Enable/Disable running JavaScript when rendering the page", min=0, max=1, example=1),
    'user_agent': fields.String(description="User agent to use for the capture", example=''),
    'browser_name': fields.String(description="Use this browser. Must be chromium, firefox or webkit.", example=''),
    'device_name': fields.String(description="Use the pre-configured settings for this device. Get a list from /json/devices.", example=''),
    'referer': fields.String(description="Referer to pass to the capture", example=''),
    'headers': fields.String(description="Headers to pass to the capture", example='Accept-Language: en-US;q=0.5, fr-FR;q=0.4'),
    'proxy': fields.Url(description="Proxy to use for the capture. Format: [scheme]://[username]:[password]@[hostname]:[port]", example=''),
    'cookies': fields.String(description="JSON export of a list of cookies as exported from an other capture", example=''),
    'auto_report': fields.Nested(auto_report_model, description="The settings for the automatic reporting.")
})


@api.route('/submit')
class SubmitCapture(Resource):  # type: ignore[misc]

    @api.param('url', 'The URL to capture', required=True)  # type: ignore[misc]
    @api.param('listing', 'Display the capture on the index', default=1)  # type: ignore[misc]
    @api.param('allow_tracking', 'Attempt to let the website violate your privacy', default=1)  # type: ignore[misc]
    @api.param('java_script_enabled', 'Enable/Disable running JavaScript when rendering the page', default=1)  # type: ignore[misc]
    @api.param('user_agent', 'User agent to use for the capture')  # type: ignore[misc]
    @api.param('browser_name', 'Use this browser. Must be chromium, firefox or webkit.')  # type: ignore[misc]
    @api.param('device_name', 'Use the pre-configured settings for this device')  # type: ignore[misc]
    @api.param('referer', 'Referer to pass to the capture')  # type: ignore[misc]
    @api.param('proxy', 'Proxy to use for the the capture')  # type: ignore[misc]
    @api.produces(['text/text'])  # type: ignore[misc]
    def get(self) -> Response:
        if flask_login.current_user.is_authenticated:
            user = flask_login.current_user.get_id()
        else:
            user = src_request_ip(request)

        if 'url' not in request.args or not request.args.get('url'):
            return make_response({'error': 'No "url" in the URL params, nothing to capture.'}, 400)

        to_query: dict[str, Any] = {
            'url': request.args['url'],
            'listing': False if 'listing' in request.args and request.args['listing'] in [0, '0'] else True,
            'allow_tracking': False if 'allow_tracking' in request.args and request.args['allow_tracking'] in [0, '0'] else True,
            'java_script_enabled': False if 'java_script_enabled' in request.args and request.args['java_script_enabled'] in [0, '0'] else True
        }
        if request.args.get('user_agent'):
            to_query['user_agent'] = request.args['user_agent']
        if request.args.get('browser_name'):
            to_query['browser_name'] = request.args['browser_name']
        if request.args.get('device_name'):
            to_query['device_name'] = request.args['device_name']
        if request.args.get('referer'):
            to_query['referer'] = request.args['referer']
        if request.args.get('headers'):
            to_query['headers'] = request.args['headers']
        if request.args.get('proxy'):
            to_query['proxy'] = request.args['proxy']

        perma_uuid = lookyloo.enqueue_capture(CaptureSettings(**to_query), source='api', user=user, authenticated=flask_login.current_user.is_authenticated)
        return make_response(perma_uuid)

    @api.doc(body=submit_fields_post)  # type: ignore[misc]
    @api.produces(['text/text'])  # type: ignore[misc]
    def post(self) -> Response:
        if flask_login.current_user.is_authenticated:
            user = flask_login.current_user.get_id()
        else:
            user = src_request_ip(request)
        to_query: dict[str, Any] = request.get_json(force=True)
        perma_uuid = lookyloo.enqueue_capture(CaptureSettings(**to_query), source='api', user=user, authenticated=flask_login.current_user.is_authenticated)
        return make_response(perma_uuid)


# Binary stuff

@api.route('/bin/<string:capture_uuid>/screenshot')
@api.doc(description='Get the screenshot associated to the capture.',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureScreenshot(Resource):  # type: ignore[misc]

    @api.produces(['image/png'])  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        success, screenshot = lookyloo.get_screenshot(capture_uuid)
        if success:
            return send_file(screenshot, mimetype='image/png')
        return make_response({'error': 'No screenshot available'}, 404)


@api.route('/bin/<string:capture_uuid>/export')
@api.doc(description='Get all the files generated by the capture, except the pickle.',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureExport(Resource):  # type: ignore[misc]

    @api.produces(['application/zip'])  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        success, capture = lookyloo.get_capture(capture_uuid)
        if success:
            return send_file(capture, mimetype='application/zip')
        return make_response({'error': 'No capture available'}, 404)


@api.route('/bin/<string:capture_uuid>/data')
@api.doc(description='Get the file downloaded by the capture.',
         params={'capture_uuid': 'The UUID of the capture'})
class CaptureData(Resource):  # type: ignore[misc]

    @api.produces(['application/zip'])  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        success, filename, data = lookyloo.get_data(capture_uuid)
        if success:
            to_return = BytesIO()
            with ZipFile(to_return, 'w') as z:
                z.writestr(filename, data.getvalue())
            to_return.seek(0)
            return send_file(to_return, mimetype='application/zip')
        return make_response({'error': "This capture didn't trigger a download"}, 404)


# Compare captures (WiP)

compare_settings_mapping = api.model('CompareSettings', {
    'ressources_ignore_domains': fields.List(fields.String(description="A domain to ignore")),
    'ressources_ignore_regexes': fields.List(fields.String(description="A regex to match anything in a URL"))
})

compare_captures_fields = api.model('CompareCapturesFields', {
    'capture_left': fields.String(description="Left capture to compare.", required=True),
    'capture_right': fields.String(description="Right capture to compare.", required=True),
    'compare_settings': fields.Nested(compare_settings_mapping, description="The settings to compare captures.")
})


@api.route('/json/compare_captures')
@api.doc(description='Compare two captures')
class CompareCaptures(Resource):  # type: ignore[misc]
    @api.doc(body=compare_captures_fields)  # type: ignore[misc]
    def post(self) -> Response:
        parameters: dict[str, Any] = request.get_json(force=True)
        left_uuid = parameters.get('capture_left')
        right_uuid = parameters.get('capture_right')
        if not left_uuid or not right_uuid:
            return make_response({'error': 'UUIDs of captures to compare missing',
                                  'details': f'Left: {left_uuid} / Right: {right_uuid}'}, 400)
        try:
            different, result = comparator.compare_captures(left_uuid, right_uuid, settings=parameters.get('compare_settings'))
        except MissingUUID as e:
            # UUID non-existent, or capture still ongoing.
            if left_uuid and right_uuid:
                status_left = lookyloo.get_capture_status(left_uuid)
                status_right = lookyloo.get_capture_status(right_uuid)
                return make_response({'error': str(e),
                                      'details': {left_uuid: status_left, right_uuid: status_right}}, 404)
            else:
                return make_response({'error': str(e),
                                      'details': 'Invalid request (left/right UUIDs missing.)'}, 400)
        result['different'] = different
        return make_response(result)


comparables_nodes_model = api.model('ComparablesNodeModel', {
    'url': fields.String,
    'hostname': fields.String,
    'ip_address': fields.String,
})

redirects_model = api.model('RedirectsModel', {
    'length': fields.Integer,
    'nodes': fields.List(fields.Nested(comparables_nodes_model)),
})


comparables_model = api.model('ComparablesModel', {
    'root_url': fields.String,
    'final_url': fields.String,
    'final_hostname': fields.String,
    'final_status_code': fields.Integer,
    'redirects': fields.Nested(redirects_model),
    'ressources': fields.List(fields.List(fields.String)),
})


@api.route('/json/<string:capture_uuid>/comparables')
@api.doc(description='Get the data we can compare across captures')
class Comparables(Resource):  # type: ignore[misc]

    @api.marshal_with(comparables_model)  # type: ignore[misc]
    def get(self, capture_uuid: str) -> Response:
        return make_response(comparator.get_comparables_capture(capture_uuid))


# Get information for takedown

takedown_fields = api.model('TakedownFields', {
    'capture_uuid': fields.String(description="The UUID of the capture.", required=True),
    'filter': fields.Boolean(description="If true, the response is a list of emails.", default=False),
})


@api.route('/json/takedown')
@api.doc(description='Get information for triggering a takedown request')
class Takedown(Resource):  # type: ignore[misc]
    @api.doc(body=takedown_fields)  # type: ignore[misc]
    def post(self) -> Response:
        if not lookyloo.uwhois.available:
            return make_response({'error': 'UWhois not available, cannot get contacts.'}, 400)
        parameters: dict[str, Any] = request.get_json(force=True)
        capture_uuid = parameters.get('capture_uuid')
        if not capture_uuid:
            return make_response({'error': f'Invalid request: {parameters}'}, 400)
        if parameters.get('filter'):
            return make_response(list(lookyloo.contacts_filtered(capture_uuid)))
        else:
            return make_response(lookyloo.contacts(capture_uuid))


# Admin stuff

@api.route('/admin/rebuild_all')
@api.doc(description='Rebuild all the trees. WARNING: IT IS GOING TO TAKE A VERY LONG TIME.',
         security='apikey')
class RebuildAll(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self) -> Response:
        try:
            lookyloo.rebuild_all()
        except Exception as e:
            return make_response({'error': f'Unable to rebuild all captures: {e}'}, 400)
        return make_response({'info': 'Captures successfully rebuilt.'})


@api.route('/admin/rebuild_all_cache')
@api.doc(description='Rebuild all the caches. It will take a while, but less that rebuild all.',
         security='apikey')
class RebuildAllCache(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self) -> Response:
        try:
            lookyloo.rebuild_cache()
        except Exception as e:
            return make_response({'error': f'Unable to rebuild all the caches: {e}'}, 400)
        return make_response({'info': 'All caches successfully rebuilt.'})


@api.route('/admin/<string:capture_uuid>/rebuild')
@api.doc(description='Rebuild the tree.',
         params={'capture_uuid': 'The UUID of the capture'},
         security='apikey')
class CaptureRebuildTree(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self, capture_uuid: str) -> Response:
        try:
            lookyloo.remove_pickle(capture_uuid)
            lookyloo.get_crawled_tree(capture_uuid)
        except Exception as e:
            return make_response({'error': f'Unable to rebuild tree: {e}'}, 400)
        return make_response({'info': f'Tree {capture_uuid} successfully rebuilt.'})


@api.route('/admin/<string:capture_uuid>/hide')
@api.doc(description='Hide the capture from the index.',
         params={'capture_uuid': 'The UUID of the capture'},
         security='apikey')
class CaptureHide(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self, capture_uuid: str) -> Response:
        try:
            lookyloo.hide_capture(capture_uuid)
        except Exception as e:
            return make_response({'error': f'Unable to hide the tree: {e}'}, 400)
        return make_response({'info': f'Capture {capture_uuid} successfully hidden.'})


@api.route('/admin/<string:capture_uuid>/remove')
@api.doc(description='Remove the capture from the index.',
         params={'capture_uuid': 'The UUID of the capture'},
         security='apikey')
class CaptureRemove(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self, capture_uuid: str) -> Response:
        try:
            lookyloo.remove_capture(capture_uuid)
        except Exception as e:
            return make_response({'error': f'Unable to remove the tree: {e}'}, 400)
        return make_response({'info': f'Capture {capture_uuid} successfully removed.'})


@api.route('/json/recent_captures')
@api.route('/json/recent_captures/<string:timestamp>')
@api.doc(description='Get uuids of the most recent captures.',
         params={'timestamp': 'The timestamp up to which we want to have the current captures'},
         required=False)
class RecentCaptures(Resource):  # type: ignore[misc]
    def get(self, timestamp: str | float | None=None) -> Response:
        return make_response(lookyloo.get_recent_captures(since=timestamp))


@api.route('/json/categories')
@api.route('/json/categories/<string:category>')
@api.doc(description='Get uuids for a specific category.',
         params={'category': 'The category according to which the uuids are to be returned.'},
         required=False)
class CategoriesCaptures(Resource):  # type: ignore[misc]
    def get(self, category: str | None=None) -> Response:
        if category:
            _, entries = get_indexing(flask_login.current_user).get_captures_category(category)
            return make_response([uuid for uuid, _ in entries])
        to_return: dict[str, list[str]] = {}
        for c in get_indexing(flask_login.current_user).categories:
            _, entries = get_indexing(flask_login.current_user).get_captures_category(c)
            to_return[c] = [uuid for uuid, _ in entries]
        return make_response(to_return)


# NOTE: there are a few extra paramaters we may want to add in the future: most recent/oldest capture
@api.route('/json/tlds')
@api.doc(description='Get captures with hits on a specific TLD, to TLD returns the a list of most frequent TLDs.')
class TLDCaptures(Resource):  # type: ignore[misc]

    @api.param('tld', 'Get captures with a specific TLD and their capture timestamp.')  # type: ignore[misc]
    @api.param('urls_only', 'Returns recent URLs with that TLD, regardless the capture.')  # type: ignore[misc]
    @api.param('most_recent_capture', 'Timestamp of the most recent capture to check for a TLD (fallback to now)')  # type: ignore[misc]
    @api.param('oldest_capture', 'Timestamp of the oldest capture to check for a TLD (fallback to 1 day ago)')  # type: ignore[misc]
    def get(self) -> Response:
        tld: str | None = request.args['tld'] if request.args.get('tld') else None
        if not tld:
            return make_response(list(get_indexing(flask_login.current_user).tlds))

        urls_only: bool | None = True if request.args.get('urls_only') else None
        most_recent_capture: datetime | None
        oldest_capture: datetime | None = None
        if _most_recent := request.args.get('most_recent_capture'):
            try:
                most_recent_capture = datetime.fromtimestamp(float(_most_recent))
            except Exception:
                most_recent_capture = None
        else:
            most_recent_capture = None
        if _oldest := request.args.get('oldest_capture'):
            try:
                oldest_capture = datetime.fromtimestamp(float(_oldest))
            except Exception:
                oldest_capture = None

        _, recent_captures_with_tld = get_indexing(flask_login.current_user).get_captures_tld(tld, most_recent_capture, oldest_capture)
        if not recent_captures_with_tld:
            return make_response([])
        if not urls_only:
            return make_response(recent_captures_with_tld)
        # get the capture, get the node uuids, get the names, make it a list
        to_return: set[str] = set()
        # Make sure to only get the captures with a pickle ready
        cache = lookyloo.sorted_capture_cache([uuid for uuid, _ in recent_captures_with_tld], cached_captures_only=True)
        for c in cache:
            uuid = c.uuid
            nodes_with_tld = get_indexing(flask_login.current_user).get_capture_tld_nodes(uuid, tld)
            try:
                to_return.update(node.name for node in lookyloo.get_urlnodes_from_tree(uuid, nodes_with_tld))
            except IndexError:
                # The capture needs to be re-indexed
                # NOTE: If this warning it printed on a loop for a capture, we have a problem with the index.
                logging.warning(f'Capture {uuid} needs to be re-indexed.')
                get_indexing(flask_login.current_user).force_reindex(uuid)
        return make_response(list(to_return))
