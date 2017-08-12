#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from har2tree import CrawledTree, hostname_treestyle
from scrapysplashwrapper import crawl
from ete3_webserver import NodeActions, WebTreeHandler

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
    ct.root_hartree.make_hostname_tree()
    actions = NodeActions()
    style = hostname_treestyle()
    return WebTreeHandler(ct.root_hartree.hostname_tree, actions, style)


@app.route('/scrap', methods=['GET', 'POST'])
def scrap():
    if request.form.get('url'):
        url = request.form.get('url')
        depth = request.form.get('depth')
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
        return tree(-1)
    return render_template('scrap.html')


@app.route('/tree/<int:tree_id>', methods=['GET'])
def tree(tree_id):
    report_dir = sorted(os.listdir(HAR_DIR))[tree_id]
    tree = load_tree(report_dir)
    nodes, faces, base64 = tree.redraw()
    return render_template('tree.html', nodes=nodes, faces=faces, base64_img=base64)


@app.route('/', methods=['GET'])
def index():
    i = 0
    titles = []
    if not os.path.exists(HAR_DIR):
        os.makedirs(HAR_DIR)
    for report_dir in sorted(os.listdir(HAR_DIR)):
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
