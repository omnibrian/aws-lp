"""Custom exception classes for project."""


# LastPass errors
class LastPassError(Exception):
    """General error for LastPass class."""


class LastPassCredentialsError(LastPassError):
    """Error for invalid credentials provided."""


class LastPassUnknownError(LastPassError):
    """Unknown error when handling LastPass connection."""


class LastPassIncorrectOtpError(LastPassError):
    """General error for incorrect OTP codes."""


class LastPassIncorrectGoogleAuthenticatorCodeError(LastPassIncorrectOtpError):
    """LastPass error for missing or incorrect Google Authenticator code."""


class LastPassIncorrectYubikeyPasswordError(LastPassIncorrectOtpError):
    """LastPass error for missing or incorrect Yubikey password."""
