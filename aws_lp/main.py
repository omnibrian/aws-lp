"""aws-lp main"""
from __future__ import print_function

import base64
import logging
from getpass import getpass

import click

from aws_lp import __version__
from aws_lp.lastpass import LastPass
from aws_lp.utils import (aws_assume_role, binary_type, get_saml_aws_roles,
                          prompt_for_role)

LOGGER = logging.getLogger(__name__)


@click.command(help='Assume AWS IAM Role with LastPass SAML')
@click.argument('username')
@click.argument('saml_config_id', type=int)
@click.option('--lastpass-url', default='https://lastpass.com',
              help='Proxy or debug server endpoint')
@click.version_option(version=__version__)
def main(username, saml_config_id, lastpass_url):
    """aws-lp cli"""
    lastpass_session = LastPass(lastpass_url)
    lastpass_session.login(username, binary_type(getpass()))
    assertion = lastpass_session.get_saml_token(saml_config_id)

    roles = get_saml_aws_roles(base64.b64decode(assertion))
    role = prompt_for_role(roles)

    aws_credentials_response = aws_assume_role(assertion, role[0], role[1])
    print(aws_credentials_response)
