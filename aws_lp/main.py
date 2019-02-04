"""aws-lp main"""
from __future__ import print_function

import base64
import logging
import sys
from getpass import getpass

import click

from aws_lp import __version__
from aws_lp.config import Config
from aws_lp.exceptions import (LastPassCredentialsError, LastPassError,
                               LastPassIncorrectOtpError)
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

    config = Config(config_section=profile)

    if configure:
        username = input('LastPass Username: ')
        click.echo('To find your SAML configuration ID for AWS you need to look'
                   ' at the launch URL for logging in through the LastPass web '
                   "UI. It will look similar to 'https://lastpass.com/saml/laun"
                   "ch/cfg/25', in this example, the SAML configuration ID is "
                   '25.')
        saml_config_id = input('LastPass SAML configuration ID: ')

        config.set_config(username=username, saml_config_id=saml_config_id)

        click.echo('Profile {profile} configured'.format(profile=profile))
        sys.exit(0)
    else:
        config_values = config.get_config()

        username = config_values.get('username')
        saml_config_id = config_values.get('saml_config_id')

        if not (username and saml_config_id):
            if profile == 'default':
                sys.exit("Please run 'aws-lp --configure' to set configuration "
                         'before running.')
            else:
                sys.exit("Profile '{profile}' not configured properly, please "
                         'execute with --configure flag to set up profile.'
                         .format(profile=profile))

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
    except LastPassError as error:
        # don't display stack trace but still exit and print error message
        sys.exit(str(error))

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
