#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# This file is part of peframe
# ----------------------------------------------------------------------

from setuptools import setup
from codecs import open
from os import path

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='peframe-ds',
    version='6.2.0',
    description='peframe is an open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.',
    url='https://github.com/digitalsleuth/peframe',
    maintainer='Corey Forman',
    author='Gianni \'guelfoweb\' Amato',
    author_email='guelfoweb@gmail.com',
    license='GNU General Public License',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        ],

    keywords='peframe',
    packages=["peframe", "peframe.modules"],
    package_data={
        'peframe': [
            'config/config-peframe.json',
            'signatures/stringsmatch.json',
            'signatures/yara_plugins/doc/*.yar',
            'signatures/yara_plugins/pdf/*.yar',
            'signatures/yara_plugins/pe/*.yar',
            'signatures/yara_plugins/pe/*.yara',
            ],
    },
    install_requires=required,
    entry_points={
        'console_scripts': [
            'peframe=peframe.peframecli:main',
            ],
    },

)
