from .api import Lookyloo

import argparse


def main():
    parser = argparse.ArgumentParser(description='Enqueue a URL on Lookyloo.', epilog='The response is the permanent URL where you can see the result of the capture.')
    parser.add_argument('--url', type=str, help='URL of the instance (defaults to https://lookyloo.circl.lu/, the public instance).')
    parser.add_argument('--query', required=True, help='URL to enqueue.')
    args = parser.parse_args()

    if args.url:
        lookyloo = Lookyloo(args.url)
    else:
        lookyloo = Lookyloo()

    if lookyloo.is_up():
        url = lookyloo.enqueue(args.query)
        print(url)
    else:
        print(f'Unable to reach {lookyloo.root_url}. Is the server up?')
