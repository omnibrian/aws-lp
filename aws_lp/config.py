"""Configuration handler class."""


class Config(object):
    """Configuration handler class."""

    def __init__(self):
        # TODO bring in config parser
        self.config = {}
        # TODO add section names for different profiles

    def set_config(self, **kwargs):
        """Update config values."""
        self.config.update(kwargs)

    def get_config(self):
        """Return stored config."""
        return self.config
