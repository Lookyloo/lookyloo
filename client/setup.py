# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='pylookyloo',
    version='0.7',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/Lookyloo/lookyloo/client',
    description='Python client for Lookyloo',
    packages=['pylookyloo'],
    entry_points={"console_scripts": ["lookyloo = pylookyloo:main"]},
    install_requires=['requests'],
    classifiers=[
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ]
)
