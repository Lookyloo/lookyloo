#!/usr/bin/env python3

from copy import copy

from lookyloo.modules.cloudflare import Cloudflare


def update_cloudflare_lists() -> None:
    """
    Update the Cloudflare lists.
    """
    cloudflare = Cloudflare(test=True)

    ipv4_list_old = copy(cloudflare.ipv4_list)
    ipv6_list_old = copy(cloudflare.ipv6_list)

    cloudflare.fetch_lists(test=True)
    cloudflare.init_lists()

    if cloudflare.ipv4_list == ipv4_list_old and cloudflare.ipv6_list == ipv6_list_old:
        print('No changes in Cloudflare lists.')
    else:
        # Raise exception so the tests fail and we don't forget about it.
        if cloudflare.ipv4_list != ipv4_list_old:
            raise Exception('IPv4 list has changed, please update the default one in the repo.')
        if cloudflare.ipv6_list != ipv6_list_old:
            raise Exception('IPv6 list has changed, please update the default one in the repo.')


if __name__ == "__main__":
    update_cloudflare_lists()
