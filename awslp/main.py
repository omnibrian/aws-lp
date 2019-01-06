"""aws-lp main"""
from __future__ import print_function

import logging
from getpass import getpass

import click
import requests
from six import binary_type

from awslp import __version__
from awslp.exceptions import MfaRequiredException
from awslp.helpers import (get_saml_token, lastpass_login, prompt_for_role,
                           get_saml_aws_roles, aws_assume_role)

LOGGER = logging.getLogger(__name__)


@click.command(help='Assume AWS IAM Role with LastPass SAML')
@click.argument('username')
@click.argument('saml_config_id', type=int)
@click.option('--lastpass-server', default='https://lastpass.com',
              help='Proxy or debug server endpoint')
@click.version_option(version=__version__)
def main(username, saml_config_id, lastpass_server):
    """aws-lp cli"""
    password = binary_type(getpass(), 'utf-8')

    session = requests.Session()

    try:
        lastpass_login(session, lastpass_server, username, password)
    except MfaRequiredException:
        mfa_token = input('MFA: ')
        lastpass_login(session, lastpass_server, username, password, mfa_token)

    assertion = get_saml_token(session, lastpass_server, saml_config_id)
    roles = get_saml_aws_roles(assertion)

    role = prompt_for_role(roles)

    response = aws_assume_role(assertion, role[0], role[1])
    print(response)
