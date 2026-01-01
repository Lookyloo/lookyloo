#!/usr/bin/env python3

from lookyloo.helpers import get_devices  # type: ignore[attr-defined]


def playwright_known_devices() -> None:
    known_devices = get_devices()
    print('Desktop devices:')
    for name in known_devices['desktop']['default'].keys():
        print('\t*', f'"{name}"')
    print('Mobile devices:')
    for name in known_devices['mobile']['default'].keys():
        print('\t*', f'"{name}"')
    # Implement that later
    # print('Mobile devices (landscape mode):')
    # for name in known_devices['mobile']['landscape'].keys():
    #    print('\t*', f'"{name}"')

    # Not useful for in our case, afaict.
    # print('Desktop devices (HiDPI):')
    # for name in known_devices['desktop']['HiDPI'].keys():
    #     print('\t*', f'"{name}"')


if __name__ == "__main__":
    print('Pick anything in the lists below. Just what is between the double quotes (").')
    playwright_known_devices()
