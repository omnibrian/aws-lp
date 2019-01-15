"""aws-lp main"""
from __future__ import print_function

import base64
import logging
import sys
from getpass import getpass

import click

from aws_lp import __version__
from aws_lp.lastpass import LastPass
from aws_lp.utils import (aws_assume_role, binary_type, get_saml_aws_roles,
                          prompt_for_role)
from aws_lp.shell import Shell

logging.basicConfig(
    format='[%(asctime)s][%(name)s][%(levelname)s]: %(message)s',
    stream=sys.stdout)
LOGGER = logging.getLogger(__name__)


@click.command(help='Assume AWS IAM Role with LastPass SAML')
@click.argument('username')
@click.argument('saml_config_id', type=int)
@click.option('--lastpass-url', default='https://lastpass.com',
              help='Proxy or debug server endpoint')
@click.option('-v', '--verbose', is_flag=True, help='Enable debug logging')
@click.version_option(version=__version__)
def main(username, saml_config_id, lastpass_url, verbose):
    """aws-lp cli"""
    if verbose:
        logging.getLogger('aws_lp').setLevel(logging.DEBUG)

    lastpass_session = LastPass(lastpass_url)
    lastpass_session.login(username, binary_type(getpass()))
    assertion = lastpass_session.get_saml_token(saml_config_id)

    roles = get_saml_aws_roles(base64.b64decode(assertion))
    role = prompt_for_role(roles)

    aws_credentials_response = aws_assume_role(assertion, role[0], role[1])
    LOGGER.debug('Received credentials: %s',
                 aws_credentials_response['Credentials'])

    shell = Shell()

    credentials = aws_credentials_response['Credentials']
    shell.update_env(AWS_ACCESS_KEY_ID=credentials['AccessKeyId'],
                     AWS_SECRET_ACCESS_KEY=credentials['SecretAccessKey'],
                     AWS_SESSION_TOKEN=credentials['SessionToken'])

    LOGGER.debug('Handing off to shell subprocess')
    result = shell.handoff()
    LOGGER.debug('Shell process finished with code %d', result)

    sys.exit(result)
