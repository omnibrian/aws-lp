# aws-lp

Tool for using AWS CLI with LastPass SAML.

## Usage

You will need to look up your SAML configuration ID for the AWS role you wish to join. This is in the generated launch URL in the LastPass console, it will look something similar to `https://lastpass.com/saml/launch/cfg/25`. In this case, the configuration ID is `25`.

```
aws-lp user@example.com 25
```

You will be prompted for your password and multi-factor code if that is set up on your account. If the command succeeds you will be returned to a prompt with the role name at the start of the prompt showing that you have managed to successfully get credentials and they are now added to your environment variables.
