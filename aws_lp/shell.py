"""Shell Integration class."""
import os
import subprocess


class Shell(object):
    """Shell Integration class."""

    def __init__(self):
        self.env = os.environ.copy()

    def update_env(self, **kwargs):
        """Update environment with new or updated variables."""
        self.env.update(kwargs)

    def handoff(self, shell=os.environ['SHELL']):
        """Handoff to shell process with defined environment"""
        # TODO figure out how to load rc on subprocess start
        # return subprocess.call(shell, shell=True, env=self.env,
        #                        executable=shell)
        return subprocess.call(shell, shell=True, env=self.env)
