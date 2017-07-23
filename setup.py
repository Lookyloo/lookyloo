#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='lookyloo',
    version='0.1',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/lookyloo',
    description='Web interface to track the trackers.',
    packages=['lookyloo'],
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
