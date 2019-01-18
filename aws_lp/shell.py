"""Shell Integration class."""
import io
import os
import subprocess

from aws_lp.utils import tempdir


class Shell(object):
    """Shell Integration class."""

    def __init__(self):
        self.env = os.environ.copy()

    def update_env(self, **kwargs):
        """Update environment with new or updated variables."""
        self.env.update(kwargs)

    def handoff(self):
        """Handoff to shell process with defined environment."""
        if 'zsh' in self.env.get('SHELL', 'bash'):
            return self.handoff_zsh()

        return self.handoff_bash()

    def handoff_bash(self):
        """Handoff to bash with defined environment."""
        return subprocess.call('bash -i', env=self.env, executable='bash')

    def handoff_zsh(self):
        """Handoff to zsh with defined environment."""
        with tempdir() as dirpath:
            self.update_env(ZDOTDIR=dirpath)
            zshrc_location = os.path.expanduser('~/.zshrc')

            if os.path.exists(zshrc_location):
                with io.open(zshrc_location, mode='r') as zshrc, \
                        io.open(dirpath + '/.zshrc', mode='w') as zshrc_temp:
                    zshrc_temp.write(zshrc.read())

            return subprocess.call('zsh', env=self.env, executable='zsh')
