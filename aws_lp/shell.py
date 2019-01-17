"""Shell Integration class."""
import os
import subprocess

from aws_lp.utils import binary_type


class Shell(object):
    """Shell Integration class."""

    def __init__(self):
        self.env = os.environ.copy()

    def update_env(self, **kwargs):
        """Update environment with new or updated variables."""
        self.env.update(kwargs)

    def handoff(self):
        """Handoff to shell process with defined environment.

        Currently only supports bash subprocesses with environment.
        """
        return self.handoff_bash()

    def handoff_bash(self):
        """Handoff to bash with defined environment."""
        return subprocess.call('bash -i', env=self.env, executable='bash')

    def handoff_zsh(self):
        """Handoff to zsh with defined environment."""
        # TODO Figure out solution for having .zshrc loaded on start
        return subprocess.call('zsh -i', env=self.env, executable='zsh')
