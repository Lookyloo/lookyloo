import argparse
import json

from .api import Lookyloo


def main():
    parser = argparse.ArgumentParser(description='Enqueue a URL on Lookyloo.', epilog='The response is the permanent URL where you can see the result of the capture.')
    parser.add_argument('--url', type=str, help='URL of the instance (defaults to https://lookyloo.circl.lu/, the public instance).')
    parser.add_argument('--query', help='URL to enqueue.')
    parser.add_argument('--listing', default=False, action='store_true', help='Should the report be publicly listed.')
    parser.add_argument('--redirects', help='Get redirects for a given capture.')
    args = parser.parse_args()

    if args.url:
        lookyloo = Lookyloo(args.url)
    else:
        lookyloo = Lookyloo()

    if lookyloo.is_up:
        if args.query:
            url = lookyloo.enqueue(args.query, listing=args.listing)
            print(url)
        else:
            response = lookyloo.get_redirects(args.redirects)
            print(json.dumps(response))
    else:
        print(f'Unable to reach {lookyloo.root_url}. Is the server up?')
