#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO, StringIO
import os
from pathlib import Path
from datetime import datetime, timedelta
import json
import http
import calendar

from flask import Flask, render_template, request, send_file, redirect, url_for, Response, flash, jsonify
from flask_bootstrap import Bootstrap  # type: ignore
from flask_httpauth import HTTPDigestAuth  # type: ignore

from lookyloo.helpers import get_homedir, update_user_agents, get_user_agents, get_config, get_taxonomies
from lookyloo.lookyloo import Lookyloo, Indexing
from lookyloo.exceptions import NoValidHarFile, MissingUUID
from .proxied import ReverseProxied

from typing import Optional, Dict, Any, Union

import logging

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

secret_file_path: Path = get_homedir() / 'secret_key'

if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
    with secret_file_path.open('wb') as f:
        f.write(os.urandom(64))

with secret_file_path.open('rb') as f:
    app.config['SECRET_KEY'] = f.read()

Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo'
app.debug = False
auth = HTTPDigestAuth()

lookyloo: Lookyloo = Lookyloo()

user = get_config('generic', 'cache_clean_user')
time_delta_on_index = get_config('generic', 'time_delta_on_index')
blur_screenshot = get_config('generic', 'enable_default_blur_screenshot')
max_depth = get_config('generic', 'max_depth')

enable_mail_notification = get_config('generic', 'enable_mail_notification')
enable_context_by_users = get_config('generic', 'enable_context_by_users')
enable_categorization = get_config('generic', 'enable_categorization')
enable_bookmark = get_config('generic', 'enable_bookmark')
auto_trigger_modules = get_config('generic', 'auto_trigger_modules')

logging.basicConfig(level=get_config('generic', 'loglevel'))


# ##### Global methods passed to jinja

# Method to make sizes in bytes human readable
# Source: https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return ("%.1f%s%s" % (num, 'Yi', suffix)).strip()


app.jinja_env.globals.update(sizeof_fmt=sizeof_fmt)


def http_status_description(code: int):
    if code in http.client.responses:
        return http.client.responses[code]
    return f'Invalid code: {code}'


app.jinja_env.globals.update(http_status_description=http_status_description)


def month_name(month: int):
    return calendar.month_name[month]


app.jinja_env.globals.update(month_name=month_name)


# ##### Generic/configuration methods #####

@app.after_request
def after_request(response):
    ua = request.headers.get('User-Agent')
    real_ip = request.headers.get('X-Real-IP')
    if ua:
        if real_ip:
            lookyloo.cache_user_agents(ua, real_ip)
        else:
            lookyloo.cache_user_agents(ua, request.remote_addr)
    return response


@auth.get_password
def get_pw(username: str) -> Optional[str]:
    if username in user:
        return user.get(username)
    return None


# ##### Hostnode level methods #####

@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>/hashes', methods=['GET'])
def hashes_hostnode(tree_uuid: str, node_uuid: str):
    hashes = lookyloo.get_hashes(tree_uuid, hostnode_uuid=node_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, attachment_filename=f'hashes.{node_uuid}.txt')


@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>/text', methods=['GET'])
def urls_hostnode(tree_uuid: str, node_uuid: str):
    hostnode = lookyloo.get_hostnode_from_tree(tree_uuid, node_uuid)
    return send_file(BytesIO('\n'.join(url.name for url in hostnode.urls).encode()),
                     mimetype='test/plain', as_attachment=True, attachment_filename=f'urls.{node_uuid}.txt')


@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>', methods=['GET'])
def hostnode_popup(tree_uuid: str, node_uuid: str):
    keys_response = {
        'js': {'icon': "javascript.png", 'tooltip': 'The content of the response is a javascript'},
        'exe': {'icon': "exe.png", 'tooltip': 'The content of the response is an executable'},
        'css': {'icon': "css.png", 'tooltip': 'The content of the response is a CSS'},
        'font': {'icon': "font.png", 'tooltip': 'The content of the response is a font'},
        'html': {'icon': "html.png", 'tooltip': 'The content of the response is a HTML document'},
        'json': {'icon': "json.png", 'tooltip': 'The content of the response is a Json'},
        'text': {'icon': "json.png", 'tooltip': 'The content of the response is a text'},  # FIXME: Need new icon
        'iframe': {'icon': "ifr.png", 'tooltip': 'This content is loaded from an Iframe'},
        'image': {'icon': "img.png", 'tooltip': 'The content of the response is an image'},
        'unset_mimetype': {'icon': "wtf.png", 'tooltip': 'The type of content of the response is not set'},
        'octet-stream': {'icon': "wtf.png", 'tooltip': 'The type of content of the response is a binary blob'},
        'unknown_mimetype': {'icon': "wtf.png", 'tooltip': 'The type of content of the response is of an unknown type'},
        'video': {'icon': "video.png", 'tooltip': 'The content of the response is a video'},
        'livestream': {'icon': "video.png", 'tooltip': 'The content of the response is a livestream'},
        'response_cookie': {'icon': "cookie_received.png", 'tooltip': 'There are cookies in the response'},
        # redirect has to be last
        'redirect': {'icon': "redirect.png", 'tooltip': 'The request is redirected'},
        'redirect_to_nothing': {'icon': "cookie_in_url.png", 'tooltip': 'The request is redirected to an URL we do not have in the capture'}
    }
    keys_request = {
        'request_cookie': {'icon': "cookie_read.png", 'tooltip': 'There are cookies in the request'}
    }

    hostnode, urls = lookyloo.get_hostnode_investigator(tree_uuid, node_uuid)

    return render_template('hostname_popup.html',
                           tree_uuid=tree_uuid,
                           hostnode_uuid=node_uuid,
                           hostnode=hostnode,
                           urls=urls,
                           keys_response=keys_response,
                           keys_request=keys_request,
                           enable_context_by_users=enable_context_by_users)


# ##### Tree level Methods #####

@app.route('/tree/<string:tree_uuid>/rebuild')
@auth.login_required
def rebuild_tree(tree_uuid: str):
    try:
        lookyloo.remove_pickle(tree_uuid)
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    except Exception:
        return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/trigger_modules/', defaults={'force': False})
@app.route('/tree/<string:tree_uuid>/trigger_modules/<int:force>', methods=['GET'])
def trigger_modules(tree_uuid: str, force: int):
    lookyloo.trigger_modules(tree_uuid, True if force else False)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/categories_capture/', defaults={'query': ''})
@app.route('/tree/<string:tree_uuid>/categories_capture/<string:query>', methods=['GET'])
def categories_capture(tree_uuid: str, query: str):
    if not enable_categorization:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    current_categories = lookyloo.categories_capture(tree_uuid)
    matching_categories = None
    if query:
        matching_categories = {}
        t = get_taxonomies()
        entries = t.search(query)
        if entries:
            matching_categories = {e: t.revert_machinetag(e) for e in entries}
    return render_template('categories_capture.html', tree_uuid=tree_uuid,
                           current_categories=current_categories,
                           matching_categories=matching_categories)


@app.route('/tree/<string:tree_uuid>/uncategorize/', defaults={'category': ''})
@app.route('/tree/<string:tree_uuid>/uncategorize/<string:category>', methods=['GET'])
def uncategorize_capture(tree_uuid: str, category: str):
    if not enable_categorization:
        return jsonify({'response': 'Categorization not enabled.'})
    lookyloo.uncategorize_capture(tree_uuid, category)
    return jsonify({'response': f'{category} successfully added to {tree_uuid}'})


@app.route('/tree/<string:tree_uuid>/categorize/', defaults={'category': ''})
@app.route('/tree/<string:tree_uuid>/categorize/<string:category>', methods=['GET'])
def categorize_capture(tree_uuid: str, category: str):
    if not enable_categorization:
        return jsonify({'response': 'Categorization not enabled.'})
    lookyloo.categorize_capture(tree_uuid, category)
    return jsonify({'response': f'{category} successfully removed from {tree_uuid}'})


@app.route('/tree/<string:tree_uuid>/stats', methods=['GET'])
def stats(tree_uuid: str):
    stats = lookyloo.get_statistics(tree_uuid)
    return render_template('statistics.html', uuid=tree_uuid, stats=stats)


@app.route('/tree/<string:tree_uuid>/modules', methods=['GET'])
def modules(tree_uuid: str):
    modules_responses = lookyloo.get_modules_responses(tree_uuid)
    if not modules_responses:
        return redirect(url_for('tree', tree_uuid=tree_uuid))

    vt_short_result: Dict[str, Dict[str, Any]] = {}
    if 'vt' in modules_responses:
        # VirusTotal cleanup
        vt = modules_responses.pop('vt')
        # Get malicious entries
        for url, full_report in vt.items():
            if not full_report:
                continue
            vt_short_result[url] = {
                'permaurl': f'https://www.virustotal.com/gui/url/{full_report["id"]}/detection',
                'malicious': []
            }
            for vendor, result in full_report['attributes']['last_analysis_results'].items():
                if result['category'] == 'malicious':
                    vt_short_result[url]['malicious'].append((vendor, result['result']))

    pi_short_result: Dict[str, str] = {}
    if 'pi' in modules_responses:
        pi = modules_responses.pop('pi')
        for url, full_report in pi.items():
            if not full_report:
                continue
            pi_short_result[url] = full_report['results'][0]['tag_label']

    return render_template('modules.html', uuid=tree_uuid, vt=vt_short_result, pi=pi_short_result)


@app.route('/tree/<string:tree_uuid>/redirects', methods=['GET'])
def redirects(tree_uuid: str):
    cache = lookyloo.capture_cache(tree_uuid)
    if not cache:
        return Response('Not available.', mimetype='text/text')
    if not cache['redirects']:
        return Response('No redirects.', mimetype='text/text')
    if cache['url'] == cache['redirects'][0]:  # type: ignore
        to_return = BytesIO('\n'.join(cache['redirects']).encode())  # type: ignore
    else:
        to_return = BytesIO('\n'.join([cache['url']] + cache['redirects']).encode())  # type: ignore
    return send_file(to_return, mimetype='text/text',
                     as_attachment=True, attachment_filename='redirects.txt')


@app.route('/tree/<string:tree_uuid>/image', methods=['GET'])
def image(tree_uuid: str):
    to_return = lookyloo.get_screenshot(tree_uuid)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, attachment_filename='image.png')


@app.route('/tree/<string:tree_uuid>/html', methods=['GET'])
def html(tree_uuid: str):
    to_return = lookyloo.get_html(tree_uuid)
    return send_file(to_return, mimetype='text/html',
                     as_attachment=True, attachment_filename='page.html')


@app.route('/tree/<string:tree_uuid>/cookies', methods=['GET'])
def cookies(tree_uuid: str):
    to_return = lookyloo.get_cookies(tree_uuid)
    return send_file(to_return, mimetype='application/json',
                     as_attachment=True, attachment_filename='cookies.json')


@app.route('/tree/<string:tree_uuid>/hashes', methods=['GET'])
def hashes_tree(tree_uuid: str):
    hashes = lookyloo.get_hashes(tree_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, attachment_filename='hashes.txt')


@app.route('/tree/<string:tree_uuid>/export', methods=['GET'])
def export(tree_uuid: str):
    to_return = lookyloo.get_capture(tree_uuid)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, attachment_filename='capture.zip')


@app.route('/tree/<string:tree_uuid>/hide', methods=['GET'])
@auth.login_required
def hide_capture(tree_uuid: str):
    lookyloo.hide_capture(tree_uuid)
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/cache', methods=['GET'])
def cache_tree(tree_uuid: str):
    lookyloo.cache_tree(tree_uuid)
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/send_mail', methods=['POST', 'GET'])
def send_mail(tree_uuid: str):
    if not enable_mail_notification:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    email: str = request.form.get('email') if request.form.get('email') else ''  # type: ignore
    if '@' not in email:
        # skip clearly incorrect emails
        email = ''
    comment: str = request.form.get('comment') if request.form.get('comment') else ''  # type: ignore
    lookyloo.send_mail(tree_uuid, email, comment)
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>', methods=['GET'])
@app.route('/tree/<string:tree_uuid>/<string:urlnode_uuid>', methods=['GET'])
def tree(tree_uuid: str, urlnode_uuid: Optional[str]=None):
    if tree_uuid == 'False':
        flash("Unable to process your request. The domain may not exist, or splash isn't started", 'error')
        return redirect(url_for('index'))
    try:
        cache = lookyloo.capture_cache(tree_uuid)
    except MissingUUID:
        flash(f'Unable to find this UUID ({tree_uuid}). The capture may still be ongoing, try again later.', 'error')
        return redirect(url_for('index'))

    if not cache:
        flash('Invalid cache.', 'error')
        return redirect(url_for('index'))

    if 'error' in cache:
        flash(cache['error'], 'error')

    try:
        tree_json, start_time, user_agent, root_url, meta = lookyloo.load_tree(tree_uuid)
        b64_thumbnail = lookyloo.get_screenshot_thumbnail(tree_uuid, for_datauri=True)
        return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                               user_agent=user_agent, root_url=root_url, tree_uuid=tree_uuid,
                               screenshot_thumbnail=b64_thumbnail, page_title=cache['title'],
                               meta=meta, enable_mail_notification=enable_mail_notification,
                               enable_context_by_users=enable_context_by_users,
                               enable_categorization=enable_categorization,
                               enable_bookmark=enable_bookmark,
                               blur_screenshot=blur_screenshot, urlnode_uuid=urlnode_uuid,
                               auto_trigger_modules=auto_trigger_modules,
                               has_redirects=True if cache['redirects'] else False)

    except NoValidHarFile as e:
        return render_template('error.html', error_message=e)


@app.route('/tree/<string:tree_uuid>/mark_as_legitimate', methods=['POST'])
@auth.login_required
def mark_as_legitimate(tree_uuid: str):
    if request.data:
        legitimate_entries = request.get_json(force=True)
        lookyloo.add_to_legitimate(tree_uuid, **legitimate_entries)
    else:
        lookyloo.add_to_legitimate(tree_uuid)
    return jsonify({'message': 'Legitimate entry added.'})


# ##### helpers #####

def index_generic(show_hidden: bool=False, category: Optional[str]=None):
    titles = []
    if time_delta_on_index:
        # We want to filter the captures on the index
        cut_time = datetime.now() - timedelta(**time_delta_on_index)
    else:
        cut_time = None  # type: ignore

    for cached in lookyloo.sorted_cache:
        if not cached:
            continue
        if category:
            if 'categories' not in cached or category not in cached['categories']:
                continue
        if show_hidden:
            if 'no_index' not in cached:
                # Only display the hidden ones
                continue
        elif 'no_index' in cached:
            continue
        if cut_time and datetime.fromisoformat(cached['timestamp'][:-1]) < cut_time:
            continue

        titles.append((cached['uuid'], cached['title'], cached['timestamp'], cached['url'],
                       cached['redirects'], True if cached['incomplete_redirects'] == '1' else False))
    titles = sorted(titles, key=lambda x: (x[2], x[3]), reverse=True)
    return render_template('index.html', titles=titles)


# ##### Index level methods #####

@app.route('/', methods=['GET'])
def index():
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    update_user_agents()
    return index_generic()


@app.route('/hidden', methods=['GET'])
@auth.login_required
def index_hidden():
    return index_generic(show_hidden=True)


@app.route('/category/<string:category>', methods=['GET'])
def index_category(category: str):
    return index_generic(category=category)


@app.route('/cookies', methods=['GET'])
def cookies_lookup():
    i = Indexing()
    cookies_names = [(name, freq, i.cookies_names_number_domains(name)) for name, freq in i.cookies_names]
    return render_template('cookies.html', cookies_names=cookies_names)


@app.route('/ressources', methods=['GET'])
def ressources():
    i = Indexing()
    ressources = []
    for h, freq in i.ressources:
        domain_freq = i.ressources_number_domains(h)
        context = lookyloo.context.find_known_content(h)
        capture_uuid, url_uuid, hostnode_uuid = i.get_hash_uuids(h)
        ressources.append((h, freq, domain_freq, context.get(h), capture_uuid, url_uuid, hostnode_uuid))
    return render_template('ressources.html', ressources=ressources)


@app.route('/categories', methods=['GET'])
def categories():
    i = Indexing()
    print(i.categories)
    return render_template('categories.html', categories=i.categories)


@app.route('/rebuild_all')
@auth.login_required
def rebuild_all():
    lookyloo.rebuild_all()
    return redirect(url_for('index'))


@app.route('/rebuild_cache')
@auth.login_required
def rebuild_cache():
    lookyloo.rebuild_cache()
    return redirect(url_for('index'))


@app.route('/submit', methods=['POST', 'GET'])
def submit():
    to_query = request.get_json(force=True)
    perma_uuid = lookyloo.enqueue_capture(to_query)
    return Response(perma_uuid, mimetype='text/text')


@app.route('/capture', methods=['GET', 'POST'])
def capture_web():
    if request.form.get('url'):
        # check if the post request has the file part
        if 'cookies' in request.files and request.files['cookies'].filename:
            cookie_file = request.files['cookies'].stream
        else:
            cookie_file = None
        url = request.form.get('url')
        if request.form.get('personal_ua') and request.headers.get('User-Agent'):
            user_agent = request.headers.get('User-Agent')
            os = None
            browser = None
        else:
            user_agent = request.form.get('user_agent')
            os = request.form.get('os')
            browser = request.form.get('browser')
        if url:
            depth: int = request.form.get('depth') if request.form.get('depth') else 1  # type: ignore
            listing: bool = request.form.get('listing') if request.form.get('listing') else False  # type: ignore
            perma_uuid = lookyloo.capture(url=url, cookies_pseudofile=cookie_file,
                                          depth=depth, listing=listing,
                                          user_agent=user_agent,
                                          referer=request.form.get('referer'),  # type: ignore
                                          os=os, browser=browser)
            return redirect(url_for('tree', tree_uuid=perma_uuid))
    user_agents: Dict[str, Any] = {}
    if get_config('generic', 'use_user_agents_users'):
        lookyloo.build_ua_file()
        # NOTE: For now, just generate the file, so we have an idea of the size
        # user_agents = get_user_agents('own_user_agents')
    if not user_agents:
        user_agents = get_user_agents()
    user_agents.pop('by_frequency')
    return render_template('capture.html', user_agents=user_agents,
                           max_depth=max_depth, personal_ua=request.headers.get('User-Agent'))


@app.route('/cookies/<string:cookie_name>', methods=['GET'])
def cookies_name_detail(cookie_name: str):
    captures, domains = lookyloo.get_cookie_name_investigator(cookie_name)
    return render_template('cookie_name.html', cookie_name=cookie_name, domains=domains, captures=captures)


@app.route('/body_hashes/<string:body_hash>', methods=['GET'])
def body_hash_details(body_hash: str):
    captures, domains = lookyloo.get_body_hash_investigator(body_hash)
    return render_template('body_hash.html', body_hash=body_hash, domains=domains, captures=captures)


@app.route('/stats', methods=['GET'])
def statsfull():
    stats = lookyloo.get_stats()
    return render_template('stats.html', stats=stats)


# ##### Methods related to a specific URLNode #####

@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/request_cookies', methods=['GET'])
def urlnode_request_cookies(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.request_cookie:
        return

    return send_file(BytesIO(json.dumps(urlnode.request_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, attachment_filename='request_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/response_cookies', methods=['GET'])
def urlnode_response_cookies(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.response_cookie:
        return

    return send_file(BytesIO(json.dumps(urlnode.response_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, attachment_filename='response_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/urls_in_rendered_content', methods=['GET'])
def urlnode_urls_in_rendered_content(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.rendered_html:
        return
    to_return = StringIO()
    to_return.writelines([f'{u}\n' for u in urlnode.urls_in_rendered_page])
    return send_file(BytesIO(to_return.getvalue().encode()), mimetype='text/plain',
                     as_attachment=True, attachment_filename='urls_in_rendered_content.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/rendered_content', methods=['GET'])
def urlnode_rendered_content(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.rendered_html:
        return
    return send_file(BytesIO(urlnode.rendered_html.getvalue()), mimetype='text/plain',
                     as_attachment=True, attachment_filename='rendered_content.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/posted_data', methods=['GET'])
def urlnode_post_request(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.posted_data:
        return
    posted: Union[str, bytes]
    if isinstance(urlnode.posted_data, (dict, list)):
        # JSON blob, pretty print.
        posted = json.dumps(urlnode.posted_data, indent=2)
    else:
        posted = urlnode.posted_data

    if isinstance(posted, str):
        to_return = BytesIO(posted.encode())
        is_blob = False
    else:
        to_return = BytesIO(posted)
        is_blob = True
    to_return.seek(0)

    if is_blob:
        return send_file(to_return, mimetype='application/octet-stream',
                         as_attachment=True, attachment_filename='posted_data.bin')
    else:
        return send_file(to_return, mimetype='text/plain',
                         as_attachment=True, attachment_filename='posted_data.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/ressource', methods=['POST', 'GET'])
def get_ressource(tree_uuid: str, node_uuid: str):
    if request.method == 'POST':
        h_request = request.form.get('ressource_hash')
    else:
        h_request = None
    ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_request)
    to_return = BytesIO()
    with ZipFile(to_return, 'w', ZIP_DEFLATED) as zfile:
        if ressource:
            filename, r, mimetype = ressource
            zfile.writestr(filename, r.getvalue())
        else:
            zfile.writestr('file.txt', b'Unknown Hash')
    to_return.seek(0)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, attachment_filename='file.zip')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/ressource_preview', methods=['POST', 'GET'])
def get_ressource_preview(tree_uuid: str, node_uuid: str):
    if request.method == 'POST':
        h_request = request.form.get('ressource_hash')
    else:
        h_request = None
    ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_request)
    if not ressource:
        return None
    filename, r, mimetype = ressource
    if mimetype.startswith('image'):
        return send_file(r, mimetype=mimetype,
                         as_attachment=True, attachment_filename=filename)
    return None


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/hashes', methods=['GET'])
def hashes_urlnode(tree_uuid: str, node_uuid: str):
    hashes = lookyloo.get_hashes(tree_uuid, urlnode_uuid=node_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, attachment_filename='hashes.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/add_context', methods=['POST'])
@auth.login_required
def add_context(tree_uuid: str, node_uuid: str):
    if not enable_context_by_users:
        return redirect(url_for('ressources'))

    context_data = request.form
    ressource_hash: str = context_data.get('hash_to_contextualize')  # type: ignore
    hostnode_uuid: str = context_data.get('hostnode_uuid')  # type: ignore
    callback_str: str = context_data.get('callback_str')  # type: ignore
    legitimate: bool = True if context_data.get('legitimate') else False
    malicious: bool = True if context_data.get('malicious') else False
    details: Dict[str, Dict] = {'malicious': {}, 'legitimate': {}}
    if malicious:
        malicious_details = {}
        if context_data.get('malicious_type'):
            malicious_details['type'] = context_data['malicious_type']
        if context_data.get('malicious_target'):
            malicious_details['target'] = context_data['malicious_target']
        details['malicious'] = malicious_details
    if legitimate:
        legitimate_details = {}
        if context_data.get('legitimate_domain'):
            legitimate_details['domain'] = context_data['legitimate_domain']
        if context_data.get('legitimate_description'):
            legitimate_details['description'] = context_data['legitimate_description']
        details['legitimate'] = legitimate_details
    lookyloo.add_context(tree_uuid, node_uuid, ressource_hash, legitimate, malicious, details)
    if callback_str == 'hostnode_popup':
        return redirect(url_for('hostnode_popup', tree_uuid=tree_uuid, node_uuid=hostnode_uuid))
    elif callback_str == 'ressources':
        return redirect(url_for('ressources'))


# Query API

@app.route('/json/<string:tree_uuid>/redirects', methods=['GET'])
def json_redirects(tree_uuid: str):
    cache = lookyloo.capture_cache(tree_uuid)
    if not cache:
        return {'error': 'UUID missing in cache, try again later.'}

    to_return: Dict[str, Any] = {'response': {'url': cache['url'], 'redirects': []}}
    if not cache['redirects']:
        to_return['response']['info'] = 'No redirects'
        return to_return
    if cache['incomplete_redirects']:
        # Trigger tree build, get all redirects
        lookyloo.cache_tree(tree_uuid)
        cache = lookyloo.capture_cache(tree_uuid)
        if cache:
            to_return['response']['redirects'] = cache['redirects']
    else:
        to_return['response']['redirects'] = cache['redirects']

    return jsonify(to_return)


@app.route('/json/<string:tree_uuid>/misp_export', methods=['GET'])
def misp_export(tree_uuid: str):
    event = lookyloo.misp_export(tree_uuid)
    if isinstance(event, dict):
        return jsonify(event)
    return Response(event.to_json(indent=2), mimetype='application/json')


@app.route('/json/hash_info/<h>', methods=['GET'])
def json_hash_info(h: str):
    details, body = lookyloo.get_body_hash_full(h)
    if not details:
        return {'error': 'Unknown Hash.'}
    to_return: Dict[str, Any] = {'response': {'hash': h, 'details': details,
                                              'body': base64.b64encode(body.getvalue()).decode()}}
    return jsonify(to_return)


@app.route('/json/url_info', methods=['POST'])
def json_url_info():
    to_query = request.get_json(force=True)
    occurrences = lookyloo.get_url_occurrences(**to_query)
    return jsonify(occurrences)


@app.route('/json/hostname_info', methods=['POST'])
def json_hostname_info():
    to_query = request.get_json(force=True)
    occurrences = lookyloo.get_hostname_occurrences(**to_query)
    return jsonify(occurrences)


@app.route('/json/stats', methods=['GET'])
def json_stats():
    to_return = lookyloo.get_stats()
    return Response(json.dumps(to_return), mimetype='application/json')
