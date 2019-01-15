"""LastPass Session class."""
from __future__ import print_function, unicode_literals

import binascii
import hashlib
import hmac
import logging
import re
import struct
import sys
from xml.etree import ElementTree

import requests
import six

from aws_lp.utils import binary_type, xorbytes

LOGGER = logging.getLogger(__name__)


class MfaRequiredException(Exception):
    """Exception for required MFA when none submitted."""


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

    @staticmethod
    def __prf(hash_, data):
        """LastPass updated hash for pbkdf2/hmac-sha256."""
        hash_copy = hash_.copy()
        hash_copy.update(data)
        return hash_copy.digest()

    def __pbkdf2(self, password, salt, rounds, length):
        """PBKDF2-SHA256 password derivation for LastPass."""
        key = b''
        hash_ = hmac.new(password, None, hashlib.sha256)

        if isinstance(salt, six.text_type):
            salt = binary_type(salt)

        for block in range(0, int((length + 31) / 32)):
            index = hash_value = self.__prf(
                hash_,
                salt + struct.pack('>I', block + 1))

            for _ in range(1, rounds):
                hash_value = self.__prf(hash_, hash_value)
                index = xorbytes(index, hash_value)

            key = key + index

        return binascii.hexlify(key[0:length])

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

    def __login_hash(self, username, password):
        """Determine the login hash for the user."""
        iterations = self.__get_iterations(username)
        LOGGER.debug('[login_hash] Computing login hash for %s with %d '
                     'iterations', username, iterations)

        key = binascii.unhexlify(
            self.__pbkdf2(password, username, iterations, 32))

        return self.__pbkdf2(key, password, 1, 32)

    def __login(self, username, password, otp=None):
        """Log into LastPass with username and password."""
        LOGGER.debug('[login] Starting lastpass login as %s', username)
        login_hash = self.__login_hash(username, password)
        iterations = self.__get_iterations(username)

        login_url = '{url}/login.php'.format(url=self.connection_url)

        params = {
            'method': 'web',
            'xml': '1',
            'username': username,
            'hash': login_hash,
            'iterations': iterations
        }

        if otp:
            params['otp'] = otp

        response = self.__session_post(login_url, data=params)
        response.raise_for_status()

        document = ElementTree.fromstring(response.text)
        error = document.find('error')

        if error:
            LOGGER.debug('[login] Error logging in, extracting cause')
            cause = error.get('cause')

            if cause == 'googleauthrequired':
                raise MfaRequiredException('MFA is required for this login')
            else:
                reason = error.get('message')
                sys.exit('Could not login to lastpass: {reason}'.format(
                    reason=reason))

    def login(self, username, password):
        """Log into LastPass with username and password.

        The user will be prompted for MFA if a response from LastPass indicates
        that MFA is required for the user.
        """
        try:
            self.__login(username, password)
        except MfaRequiredException:
            mfa_token = six.moves.input('MFA: ')
            self.__login(username, password, mfa_token)

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
            print(form)
            sys.exit('No SAML response from LastPass')

        return form['fields']['SAMLResponse']
