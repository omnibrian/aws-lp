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
        return subprocess.call('bash -i', env=self.env, executable='bash')
