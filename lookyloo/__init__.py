#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from har2tree import CrawledTree
from scrapysplashwrapper import crawl

from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap

from glob import glob
import os
from datetime import datetime

app = Flask(__name__)

Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.debug = True

HAR_DIR = 'scraped'
SPLASH = 'http://127.0.0.1:8050'


def load_tree(report_dir):
    har_files = sorted(glob(os.path.join(HAR_DIR, report_dir, '*.har')))
    ct = CrawledTree(har_files)
    ct.find_parents()
    ct.join_trees()
    return ct.jsonify(), ct.start_time.isoformat(), ct.user_agent, ct.root_url


@app.route('/scrape', methods=['GET', 'POST'])
def scrape():
    if request.form.get('url'):
        url = request.form.get('url')
        depth = request.form.get('depth')
        if depth is None:
            depth = 1
        items = crawl(SPLASH, url, depth)
        if not items:
            # broken
            pass
        width = len(str(len(items)))
        i = 1
        dirpath = os.path.join(HAR_DIR, datetime.now().isoformat())
        os.makedirs(dirpath)
        for item in items:
            harfile = item['har']
            with open(os.path.join(dirpath, '{0:0{width}}.har'.format(i, width=width)), 'w') as f:
                json.dump(harfile, f)
            i += 1
        return tree(0)
    return render_template('scrape.html')


def get_report_dirs():
    # Cleanup HAR_DIR of failed runs.
    for report_dir in os.listdir(HAR_DIR):
        if not os.listdir(os.path.join(HAR_DIR, report_dir)):
            os.rmdir(os.path.join(HAR_DIR, report_dir))
    return sorted(os.listdir(HAR_DIR), reverse=True)


@app.route('/tree/<int:tree_id>', methods=['GET'])
def tree(tree_id):
    report_dir = get_report_dirs()[tree_id]
    tree_json, start_time, user_agent, root_url = load_tree(report_dir)
    return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                           user_agent=user_agent, root_url=root_url)


@app.route('/', methods=['GET'])
def index():
    i = 0
    titles = []
    if not os.path.exists(HAR_DIR):
        os.makedirs(HAR_DIR)
    for report_dir in get_report_dirs():
        har_files = sorted(glob(os.path.join(HAR_DIR, report_dir, '*.har')))
        if not har_files:
            continue
        with open(har_files[0], 'r') as f:
            j = json.load(f)
            titles.append((i, j['log']['pages'][0]['title']))
        i += 1

    return render_template('index.html', titles=titles)


if __name__ == '__main__':
    app.run(port=5001, threaded=True)
