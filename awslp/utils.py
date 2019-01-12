"""Static utility functions."""
import sys
from xml.etree import ElementTree

import boto3
import six


def binary_type(string):
    """Return binary_type of string."""
    if sys.version_info[0] == 2:
        return string

    return string.encode('utf-8')


def xorbytes(string_a, string_b):
    """XOR all bytes in a string"""
    if sys.version_info[0] == 2:
        return ''.join([chr(ord(x) ^ ord(y))
                        for (x, y) in zip(string_a, string_b)])

    return bytes([x ^ y for (x, y) in zip(string_a, string_b)])


def get_saml_aws_roles(assertion):
    """Get the AWS roles contained in a decoded SAML assertion.

    This returns a list of RoleARN, PrincipalARN (IdP) pairs.
    """
    document = ElementTree.fromstring(assertion)

    role_attribute = 'https://aws.amazon.com/SAML/Attributes/Role'
    xpath = ".//saml:Attribute[@Name='{role_attribute}']/saml:AttributeValue" \
        .format(role_attribute=role_attribute)

    namespace = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }

    attributes = document.findall(xpath, namespace)
    return [attribute.text.split(',', 2) for attribute in attributes]


def prompt_for_role(roles):
    """Ask user which role to assume."""
    if len(roles) == 1:
        return roles[0]

    print('Please select a role:')
    count = 1

    for role in roles:
        print('  {count}) {role}'.format(count=count, role=role[0]))
        count = count + 1

    choice = 0

    while choice < 1 or choice > len(roles) + 1:
        try:
            choice = int(input('Choice: '))
        except ValueError:
            choice = 0

    return roles[choice - 1]


def aws_assume_role(assertion, role_arn, principal_arn):
    """Assume role with a SAML assertion using boto3.

    returns {
        'Credentials': {
            'AccessKeyId': '',
            'SecretAccessKey': '',
            'SessionToken': ''
        }
    }
    """
    client = boto3.client('sts')

    return client.assume_role_with_saml(
        RoleArn=role_arn,
        PrincipalArn=principal_arn,
        SAMLAssertion=six.text_type(assertion))
