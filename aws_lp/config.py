"""Configuration handler class."""
import os

from six.moves import configparser


class Config(object):
    """Configuration handler class."""

    def __init__(self):
        self.config_file_name = 'aws_lp'
        self.config_section = 'default'

        if os.path.isdir(os.path.expanduser('~/.config')):
            self.config_file = os.path.expanduser(
                '~/.config/' + self.config_file_name + '/config')
        else:
            self.config_file = os.path.expanduser('~/.' + self.config_file_name)

        self.configparser = configparser.ConfigParser()

    def set_config(self, **kwargs):
        """Update config values."""
        # TODO Update config file
        # self.config.update(kwargs)

    def get_config(self):
        """Return stored config."""
        if not os.path.isfile(self.config_file):
            return {}

        self.configparser.read(self.config_file)

        try:
            config = dict(self.configparser.items(self.config_section))
        except configparser.NoSectionError:
            return {}

        return config
