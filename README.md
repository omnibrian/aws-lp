# aws-lp: AWS LastPass CLI

[![PyPI version](https://badge.fury.io/py/aws-lp.svg)](https://badge.fury.io/py/aws-lp)

Tool for using AWS CLI with LastPass SAML.

## Installation

This tool is published on pypi.org:

```
pip install aws-lp
```

## Usage

You will need to look up your SAML configuration ID for the AWS role you wish to join. This is in the generated launch URL in the LastPass console, it will look something similar to `https://lastpass.com/saml/launch/cfg/25`. In this case, the configuration ID is `25`, enter this number when prompted during configuration of `aws-lp`.

```
aws-lp --configure
aws-lp
```

You will be prompted for your password and multi-factor code if that is set up on your account. If the command succeeds you will be returned to a prompt with the role name at the start of the prompt showing that you have managed to successfully get credentials and they are now added to your environment variables.
