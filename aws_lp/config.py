"""Configuration handler class."""


class Config(object):
    """Configuration handler class."""

    def __init__(self):
        self.config = {}

    def set_config(self, **kwargs):
        """Update config values."""
        self.config.update(kwargs)

    def get_config(self):
        """Return stored config."""
        return self.config
