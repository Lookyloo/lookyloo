#!/usr/bin/env python3

import requests

from lookyloo.default import get_homedir

d3js_version = '7.9.0'
jquery_version = "3.7.1"
datatables_version = "2.3.4"
datatables_rowgroup_version = "1.6.0"
datatables_buttons_version = "3.2.5"
datatables_select_version = "3.1.3"
jquery_json_viewer_version = "1.5.0"


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

    datatables_js = requests.get(f'https://cdn.datatables.net/v/bs5/dt-{datatables_version}/b-{datatables_buttons_version}/rg-{datatables_rowgroup_version}/sl-{datatables_select_version}/datatables.min.js')
    with (dest_dir / 'datatables.min.js').open('wb') as f:
        f.write(datatables_js.content)
        print(f'Downloaded datatables js v{datatables_version}.')

    datatables_css = requests.get(f'https://cdn.datatables.net/v/bs5/dt-{datatables_version}/b-{datatables_buttons_version}/rg-{datatables_rowgroup_version}/sl-{datatables_select_version}/datatables.min.css')
    with (dest_dir / 'datatables.min.css').open('wb') as f:
        f.write(datatables_css.content)
        print(f'Downloaded datatables_css v{datatables_version}.')

    jquery_json_js = requests.get(f'https://cdn.jsdelivr.net/npm/jquery.json-viewer@{jquery_json_viewer_version}/json-viewer/jquery.json-viewer.js')
    with (dest_dir / 'jquery.json-viewer.js').open('wb') as f:
        f.write(jquery_json_js.content)
        print(f'Downloaded jquery_json js v{jquery_json_viewer_version}.')

    jquery_json_css = requests.get(f'https://cdn.jsdelivr.net/npm/jquery.json-viewer@{jquery_json_viewer_version}/json-viewer/jquery.json-viewer.css')
    with (dest_dir / 'jquery.json-viewer.css').open('wb') as f:
        f.write(jquery_json_css.content)
        print(f'Downloaded jsontree css v{jquery_json_viewer_version}.')

    print('All 3rd party modules for the website were downloaded.')
