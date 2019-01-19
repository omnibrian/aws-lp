"""Custom exception classes for project."""


# LastPass errors
class LastPassIncorrectOtpError(Exception):
    """General error for incorrect OTP codes."""


class LastPassIncorrectGoogleAuthenticatorCodeError(LastPassIncorrectOtpError):
    """LastPass error for missing or incorrect Google Authenticator code."""


class LastPassIncorrectYubikeyPasswordError(LastPassIncorrectOtpError):
    """LastPass error for missing or incorrect Yubikey password."""


class LastPassUnknownError(Exception):
    """Unknown error when handling LastPass connection."""
