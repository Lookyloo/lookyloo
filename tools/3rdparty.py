#!/usr/bin/env python3

import requests

from lookyloo.default import get_homedir

d3js_version = '7.8.3'
jquery_version = "3.6.4"
datatables_version = "1.13.4"

if __name__ == '__main__':
    dest_dir = get_homedir() / 'website' / 'web' / 'static'

    d3 = requests.get(f'https://cdn.jsdelivr.net/npm/d3@{d3js_version}/dist/d3.min.js')
    with (dest_dir / 'd3.min.js').open('wb') as f:
        f.write(d3.content)
        print(f'Downloaded d3js v{d3js_version}.')

    jquery = requests.get(f'https://code.jquery.com/jquery-{jquery_version}.min.js')
    with (dest_dir / 'jquery.min.js').open('wb') as f:
        f.write(jquery.content)
        print(f'Downloaded jquery v{jquery_version}.')

    datatables_js = requests.get(f'https://cdn.datatables.net/v/bs4/dt-{datatables_version}/datatables.min.js')
    with (dest_dir / 'datatables.min.js').open('wb') as f:
        f.write(datatables_js.content)
        print(f'Downloaded datatables js v{datatables_version}.')

    datatables_css = requests.get(f'https://cdn.datatables.net/v/bs4/dt-{datatables_version}/datatables.min.css')
    with (dest_dir / 'datatables.min.css').open('wb') as f:
        f.write(datatables_css.content)
        print(f'Downloaded datatables_css v{datatables_version}.')

    print('All 3rd party modules for the website were downloaded.')
