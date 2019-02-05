"""setuptools installation script"""
import io
from os import path

from setuptools import setup, find_packages

from aws_lp import __author__, __version__

with io.open(path.join(path.abspath(path.dirname(__file__)), 'README.md'),
             encoding='utf-8') as readme:
    LONG_DESCRIPTION = readme.read()

setup(
    name='aws-lp',
    version=__version__,
    description='Tool for using AWS CLI with LastPass SAML',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author=__author__,
    author_email='bleblan2@unb.ca',
    url='https://github.com/omnibrian/aws-lp',
    license='GPLv3',
    keywords='lastpass aws awscli boto3',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=[
        'awscli',
        'boto3',
        'click',
        'future',
        'requests',
        'six',
    ],
    entry_points={
        'console_scripts': [
            'aws-lp=aws_lp.main:main'
        ]
    },
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ]
)
