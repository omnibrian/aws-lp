"""LastPass Session class."""
from __future__ import print_function, unicode_literals

import binascii
import hashlib
import json
import logging
import re
import sys
from xml.etree import ElementTree

import requests
import six

from aws_lp.exceptions import (LastPassCredentialsError, LastPassUnknownError,
                               LastPassIncorrectYubikeyPasswordError,
                               LastPassIncorrectGoogleAuthenticatorCodeError)

LOGGER = logging.getLogger(__name__)


class LastPass(object):
    """LastPass Session management class."""

    def __init__(self, connection_url='https://lastpass.com'):
        self.lastpass_url = 'https://lastpass.com'
        self.connection_url = connection_url

        self.__iterations = 5000
        self.__iterations_username = None
        self.__session = requests.Session()

    def __should_verify(self):
        """Disable SSL validation on connections not addressed to lastpass.com.

        This is to allow connecting use of a proxy server when connecting to
        LastPass
        """
        return self.lastpass_url in self.connection_url

    def __session_get(self, url):
        """Send GET request through internal requests session."""
        LOGGER.debug('[session_get] Sending GET request to %s', url)
        return self.__session.get(url, verify=self.__should_verify())

    def __session_post(self, url, data=None):
        """Send POST request through internal requests session."""
        LOGGER.debug('[session_post] Sending POST request to %s', url)
        return self.__session.post(
            url, data=data, verify=self.__should_verify())

    @staticmethod
    def __extract_form(html):
        """Attempt to extract the first form elements from an html page."""
        fields = {}
        matches = re.findall(r'name="([^"]*)" (id="([^"]*)" )?value="([^"]*)"',
                             html)

        for match in matches:
            if len(match) > 2:
                fields[match[0]] = match[3]

        match = re.search(r'action="([^"]*)"', html)
        action = match.group(1) if match else ''

        return {
            'action': action,
            'fields': fields
        }

    def __get_iterations(self, username):
        """Determine the number of PBKDF2 iterations needed for user."""
        if self.__iterations_username == username:
            LOGGER.debug('[get_iterations] Responding with stored iterations '
                         'for user %s', username)
            return self.__iterations

        LOGGER.debug('[get_iterations] Retrieving iterations for user %s',
                     username)
        iterations_url = '{url}/iterations.php'.format(url=self.connection_url)

        params = {
            'email': username
        }

        response = self.__session_post(iterations_url, data=params)

        if response.status_code == 200:
            self.__iterations = int(response.text)
            self.__iterations_username = username

        return self.__iterations

    @staticmethod
    def __login_hash(username, password, iterations):
        """Determine the login hash for the user."""
        LOGGER.debug('[login_hash] Computing login hash for %s with %d '
                     'iterations', username, iterations)

        if iterations == 1:
            key = binascii.hexlify(hashlib.sha256(username + password).digest())

            return bytearray(hashlib.sha256(key + password).hexdigest(),
                             'ascii')

        key = hashlib.pbkdf2_hmac('sha256', password, username, iterations, 32)

        return binascii.hexlify(hashlib.pbkdf2_hmac('sha256', key, password, 1,
                                                    32))

    @staticmethod
    def __parse_error(parsed_response):
        """Extract error from parsed LastPass response."""
        if parsed_response.tag != 'response':
            error = None
        else:
            error = parsed_response.find('error')

        if error is None or not error.attrib:
            raise LastPassUnknownError('Unknown schema in response from '
                                       'LastPass')

        exceptions = {
            'unknownemail': LastPassCredentialsError,
            'unknownpassword': LastPassCredentialsError,
            'googleauthrequired': LastPassIncorrectGoogleAuthenticatorCodeError,
            'googleauthfailed': LastPassIncorrectGoogleAuthenticatorCodeError,
            'yubikeyrestricted': LastPassIncorrectYubikeyPasswordError
        }

        cause = error.attrib.get('cause')
        message = error.attrib.get('message')

        if cause:
            return exceptions.get(cause, LastPassUnknownError)(message or cause)

        return LastPassUnknownError(message)

    def login(self, username, password, otp=None, client_id=None):
        """Log into LastPass with username, password, and optional OTP code.

        If the user requires an OTP to login a LastPassIncorrectOtpError will be
        raised.
        """
        LOGGER.debug('[login] Starting lastpass login as %s', username)
        iterations = self.__get_iterations(username)
        login_url = '{url}/login.php'.format(url=self.connection_url)

        params = {
            'method': 'mobile',
            'web': 1,
            'xml': 1,
            'username': username,
            'hash': self.__login_hash(username, password, iterations),
            'iterations': iterations
        }

        if otp:
            params['otp'] = otp

        if client_id:
            params['imei'] = client_id

        response = self.__session_post(login_url, data=params)

        if response.status_code != 200:
            LOGGER.debug('[login] Non 200 response from LastPass login: %d',
                         response.status_code)
            raise LastPassUnknownError('Bad response from LastPass')

        try:
            parsed_response = ElementTree.fromstring(response.text)
        except ElementTree.ParseError:
            LOGGER.debug('[login] Error from ElementTree parsing XML response '
                         'from LastPass')
            parsed_response = None

        if parsed_response is None:
            LOGGER.debug('[login] Failed to parse response from LastPass login:'
                         ' %s', response.text)
            raise LastPassUnknownError('Received invalid response from '
                                       'LastPass')

        session_id = None

        if parsed_response.tag == 'ok':
            session_id = parsed_response.attrib.get('sessionid')

            if isinstance(session_id, str):
                return session_id

        LOGGER.debug('[login] No session_id returned, parsing response for '
                     'error')
        raise self.__parse_error(parsed_response)

    def get_saml_token(self, saml_cfg_id):
        """Log into LastPass and retrieve SAML token for config."""
        LOGGER.debug('[get_saml_token] Starting SAML token retrieval')

        # once logged in, grab the SAML token from the IdP-initiated login
        idp_login_url = '{url}/saml/launch/cfg/{saml_cfg_id}'.format(
            url=self.connection_url, saml_cfg_id=saml_cfg_id)

        response = self.__session_get(idp_login_url)
        form = self.__extract_form(response.text)

        if not form['action']:
            # try to scrape the error message to give response to user
            error = ''

            for line in response.text.splitlines():
                match = re.search(r'<h2>(.*)</h2>', line)

                if match:
                    msg = six.moves.html_parser.HTMLParser()\
                        .unescape(match.group(1))
                    msg = msg.replace('<br/>', '\n')
                    msg = msg.replace('<b>', '')
                    msg = msg.replace('</b>', '')
                    error = '\n' + msg

            sys.exit('Unable to find SAML ACS ' + error)

        if not form['fields'].get('SAMLResponse'):
            LOGGER.debug('[get_saml_token] Form: %s', json.dumps(form))
            sys.exit('No SAML response from LastPass')

        return form['fields']['SAMLResponse']
