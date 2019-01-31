"""aws-lp main"""
from __future__ import print_function

import base64
import logging
import sys
from getpass import getpass

import click

from aws_lp import __version__
from aws_lp.config import Config
from aws_lp.exceptions import (LastPassIncorrectOtpError,
                               LastPassCredentialsError)
from aws_lp.lastpass import LastPass
from aws_lp.shell import Shell
from aws_lp.utils import (aws_assume_role, binary_type, get_saml_aws_roles,
                          prompt_for_role)

logging.basicConfig(
    format='[%(asctime)s][%(name)s][%(levelname)s]: %(message)s',
    stream=sys.stdout)
LOGGER = logging.getLogger(__name__)


@click.command(help='Assume AWS IAM Role with LastPass SAML')
@click.option('-p', '--profile', default='default',
              help='Set a specific profile from your configuration file')
@click.option('--configure', is_flag=True,
              help='Set configuration file for profile specified')
@click.option('--lastpass-url', default='https://lastpass.com',
              help='Proxy or debug server endpoint')
@click.option('-v', '--verbose', is_flag=True, help='Enable debug logging')
@click.version_option(version=__version__)
def main(profile, configure, lastpass_url, verbose):
    """Log into LastPass, get SAML auth, assume role, and create subshell"""
    if verbose:
        logging.getLogger('aws_lp').setLevel(logging.DEBUG)

    if configure:
        click.echo('Configuring profile: ' + profile)
        # configure(profile)
        sys.exit(0)
    else:
        config = Config(config_section=profile).get_config()

        username = config.get('username')
        saml_config_id = config.get('saml_config_id')

    username = binary_type(username)
    password = binary_type(getpass())
    lastpass_session = LastPass(lastpass_url)

    try:
        lastpass_session.login(username, password)
    except LastPassIncorrectOtpError:
        mfa = input('MFA: ')

        try:
            lastpass_session.login(username, password, otp=mfa)
        except LastPassIncorrectOtpError:
            sys.exit('Invalid MFA code')
    except LastPassCredentialsError:
        sys.exit('Invalid username or password')

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

    try:
        result = shell.handoff(prompt_message='LP:' + role[0].split('/')[-1])
    except AttributeError:
        result = shell.handoff(prompt_message='LP')

    LOGGER.debug('Shell process finished with code %d', result)

    sys.exit(result)
