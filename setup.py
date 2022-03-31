#!/usr/bin/env python3
from setuptools import setup


setup(
    name='lookyloo',
    version='1.11-dev',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/Lookyloo/lookyloo',
    description='Web interface to track the trackers.',
    packages=['lookyloo'],
    scripts=['bin/start_website.py', 'bin/start.py', 'bin/run_backend.py', 'bin/async_scrape.py',
             'bin/shutdown.py', 'bin/stop.py', 'bin/rebuild_caches.py', 'bin/update.py'],
    include_package_data=True,
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ],
)
